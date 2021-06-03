package com.csw.data.nvd.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FilenameUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.json.cpe.source.DefCpeMatch;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Service
@Qualifier("CpeLiveKeepServiceImpl")
public class CpeLiveKeepServiceImpl implements LiveKeepService<DefCpeMatch> {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeLiveKeepServiceImpl.class);
    
    @Value("${data.local.flag}")
    private boolean localFlag;
    
    @Value("${data.livekeep.cpe.base.path}")
    private String s3cpeBasePath;
    
    /** The s3 bucket name. */
    @Value("${data.livekeep.bucketName}")
    private String s3BucketName;
    
    /** The s3 client. */
    @Autowired
    private S3Client s3Client;
    
    @Override
    public JSONArray writeFileToLiveKeep(List<DefCpeMatch> defCpeMatchs, String cpeLocalDirectory, Map<String, Integer> recordStats) throws IOException {
        JSONArray kafkaMessage = new JSONArray();
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(Include.NON_NULL);
        
        for (DefCpeMatch defCpeMatch : defCpeMatchs) {
            String cleansedId = defCpeMatch.getCpe23Uri().replaceAll("[^a-zA-Z0-9\\._]+", "_");
            String targetFilePath = cpeLocalDirectory + cleansedId + ParserConstants.JSON_FILE_EXTENSION;
            File targetFile = new File(targetFilePath);
            
            //livekeep file is written
            if(validateFile(targetFilePath, cpeLocalDirectory + cleansedId, recordStats)) {
                mapper.writeValue(targetFile, defCpeMatch);
                kafkaMessage.put(writeJsonAndMessage(targetFilePath, defCpeMatch.getCpe23Uri(), cpeLocalDirectory, cleansedId));
            }
        }
        return kafkaMessage;
    }
    
    private boolean validateFile(String cpeFile, String cpeFileWithoutExtension, Map<String, Integer> recordStats) {
        Boolean canWrite = Boolean.FALSE;
        Path metaFilePath = Paths.get(cpeFileWithoutExtension + ParserConstants.META_JSON_FILE_EXTENSION);
        //new weakness file
        if (!Files.exists(metaFilePath)) {
            recordStats.merge("newRecords", 1, Integer::sum);
            return Boolean.TRUE;
        }
        //modified weakness file
        if(validateChecksum(metaFilePath, cpeFile)) {
            recordStats.merge("modifiedRecords", 1, Integer::sum);
            canWrite = Boolean.TRUE;
        }
        return canWrite;
    }
    
    private boolean validateChecksum(Path metaFilePath, String cpeFile) {
        Boolean isChanged = Boolean.FALSE;
        try {
            String metaFile = new String(Files.readAllBytes(metaFilePath));
            JSONObject metaJsonObject = new JSONObject(metaFile);
            String existingChecksum = metaJsonObject.getString("sha256");
            String newChecksum = HashingUtil.getShaChecksum(Files.readAllBytes(Paths.get(cpeFile)));
            if (!newChecksum.equals(existingChecksum)) {
                isChanged = Boolean.TRUE;
            }
        } catch (IOException e) {
            LOGGER.error("IOException while proccesing the meta JSON file : {}", e.getMessage(), e);
        } catch (JSONException e) {
            LOGGER.error("JSONException while proccesing the meta JSON file : {}", e.getMessage(), e);
        }
        return isChanged;
    }
    
    private JSONObject writeJsonAndMessage(String file, String id, String cpeLocalDirectory, String cleansedId) {
        String fileSystemType = localFlag ? "file" : "s3";
        LOGGER.debug("fileSystemType : {}", fileSystemType);
        //write file to s3
        if("s3".equalsIgnoreCase(fileSystemType)) {
            String objectKey = s3cpeBasePath + "cpe/" + cleansedId + ParserConstants.JSON_FILE_EXTENSION;
            PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
            s3Client.putObject(request, Paths.get(file));
        }
        
        //generate meta json file
        generateMetaFile(file, cpeLocalDirectory);
        
        //create and return the kafka message
        return createKafkaMessage(id, file, ParserConstants.CPE, fileSystemType);
    }
    
    private void generateMetaFile(String cpeFilePath, String cveLocalDirectory) {
        try {
            String shaChecksum = HashingUtil.getShaChecksum(Files.readAllBytes(Paths.get(cpeFilePath)));
            ObjectMapper mapper = new ObjectMapper();
            
            Map<String, Object> map = new HashMap<>();
            map.put("sha256", shaChecksum);
            
            String fileName = FilenameUtils.getBaseName(cpeFilePath);
            mapper.writeValue(Paths.get(cveLocalDirectory + fileName + ".meta.json").toFile(), map);
        } catch (IOException e) {
            LOGGER.error("IOException while proccesing the Json file");
        }
    }
    
    private JSONObject createKafkaMessage(String id, String objectKey, String fileType, String systemType) {
        JSONObject message = new JSONObject();
        try {
            message.put("id", id);
            message.put("uri", createFileUri(objectKey, systemType));
            message.put("fileType", fileType);
        } catch (JSONException e) {
            LOGGER.error("JSONException while creating kafka message for cpe file : {}", e.getMessage());
        }
        return message;
    }
    
    private Object createFileUri(String objectKey, String systemType) {
        if("s3".equalsIgnoreCase(systemType)) {
            return new StringBuilder().append("s3:/").append(objectKey).toString();
        }
        else {
            return new StringBuilder().append("file:///").append(objectKey).toString();
        }
    }
}
