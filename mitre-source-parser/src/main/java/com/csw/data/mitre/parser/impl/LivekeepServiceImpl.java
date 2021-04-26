package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FilenameUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.cwe.pojo.WeaknessRoot;
import com.csw.data.mitre.parser.LivekeepService;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * The Class LivekeepServiceImpl.
 */
@Service
@Qualifier("LivekeepService")
public class LivekeepServiceImpl implements LivekeepService {
	
	/** The Constant LOGGER. */
	private static final Logger LOGGER = LoggerFactory.getLogger(LivekeepServiceImpl.class);
	
	/** The local flag. */
	@Value("${data.local.flag}")
	private boolean localFlag;

	/** The live keep base path. */
	@Value("${livekeep.cwe.mitre.path}")
	private String liveKeepBasePath;

	/** The cwe path. */
	@Value("${cwe.path}")
	private String cwePath;
	
	/** The s3 bucket name. */
	@Value("${data.livekeep.bucketName}")
	private String s3BucketName;
	
	/** The s3 client. */
	@Autowired
	private S3Client s3Client;

	/**
	 * Write to live keep.
	 *
	 * @param weakness the weakness
	 * @param sourceFilePath the source file path
	 * @param recordStats the record stats
	 * @return the JSON object
	 * @throws Exception the exception
	 */
	@Override
	public JSONObject writeToLiveKeep(WeaknessRoot weakness, String sourceFilePath, Map<String, Integer> recordStats) throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(Include.NON_NULL);
		
		JSONObject kafkaMessage = null;
		String weaknessFilePath = liveKeepBasePath + weakness.getId() + ParserConstants.JSON_FILE_EXTENSION;
		File weaknessFile = new File(weaknessFilePath);
		// livekeep file is written
		if(validateFile(weaknessFilePath, liveKeepBasePath + weakness.getId(), recordStats)) {
			mapper.writeValue(weaknessFile, weakness);
			kafkaMessage = writeJsonAndMessage(weaknessFilePath, weakness.getId(), sourceFilePath);
		}
		
		return kafkaMessage;
	}
	
	/**
	 * Validate file.
	 *
	 * @param weaknessFile the weakness file
	 * @param weaknessFileWithoutExtension the weakness file without extension
	 * @param recordStats the record stats
	 * @return true, if successful
	 */
	private boolean validateFile(String weaknessFile, String weaknessFileWithoutExtension, Map<String, Integer> recordStats) {
		Boolean canWrite = Boolean.FALSE;
		Path metaFilePath = Paths.get(weaknessFileWithoutExtension + ParserConstants.META_JSON_FILE_EXTENSION);
		//new weakness file
		if (!Files.exists(metaFilePath)) {
			recordStats.merge("newRecords", 1, Integer::sum);
			return Boolean.TRUE;
		}
		//file is modified
		if(validateChecksum(metaFilePath, weaknessFile)) {
			recordStats.merge("modifiedRecords", 1, Integer::sum);
			canWrite = Boolean.TRUE;
		}
		return canWrite;
	}

	/**
	 * Validate checksum.
	 *
	 * @param metaFilePath the meta file path
	 * @param weaknessFile the weakness file
	 * @return true, if successful
	 */
	private boolean validateChecksum(Path metaFilePath, String weaknessFile) {
		Boolean isChanged = Boolean.FALSE;
		try {
			String metaFile = new String(Files.readAllBytes(metaFilePath));
			JSONObject metaJsonObject = new JSONObject(metaFile);
			String existingChecksum = metaJsonObject.getString("sha256");
			String newChecksum = HashingUtil.getShaChecksum(Files.readAllBytes(Paths.get(weaknessFile)));
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

	/**
	 * Write json and message.
	 *
	 * @param cweFile the cwe file
	 * @param weaknessId the weakness id
	 * @param sourceFilePath the source file path
	 * @return the JSON object
	 */
	private JSONObject writeJsonAndMessage(String cweFile, String weaknessId, String sourceFilePath) {
		String fileSystemType = localFlag ? "file" : "s3";
		//write file to s3
		if("s3".equalsIgnoreCase(fileSystemType)) {
			String objectKey = cwePath + "/mitre/" + weaknessId + ParserConstants.JSON_FILE_EXTENSION;
			PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
			s3Client.putObject(request, Paths.get(cweFile));
		}
		//generate meta json file
		generateMetaFile(cweFile, sourceFilePath, liveKeepBasePath);
		//create and return the kafka message
		return createKafkaMessage(weaknessId, cweFile, ParserConstants.CWE, fileSystemType);
	}
	
	/**
	 * Generate meta file.
	 *
	 * @param cweFilePath the file
	 * @param sourceFilePath the source file path
	 * @param cweLiveKeepDirectory the cwe live keep directory
	 */
	private void generateMetaFile(String cweFilePath, String sourceFilePath, String cweLiveKeepDirectory) {
		try {
			String shaChecksum = HashingUtil.getShaChecksum(Files.readAllBytes(Paths.get(cweFilePath)));
			ObjectMapper mapper = new ObjectMapper();
			
			Map<String, Object> map = new HashMap<>();
			map.put("sha256", shaChecksum);
			List<String> sourceFileLocation = new ArrayList<>();
			sourceFileLocation.add(sourceFilePath);
			map.put("sourceFiles", sourceFileLocation);
			
			String fileName = FilenameUtils.getBaseName(cweFilePath);
			mapper.writeValue(Paths.get(cweLiveKeepDirectory + fileName + ".meta.json").toFile(), map);
		} catch (IOException e) {
			LOGGER.error("IOException while proccesing the Json file");
		}
	}

	/**
	 * Creates the kafka message.
	 *
	 * @param weaknessId the weakness id
	 * @param objectKey the object key
	 * @param fileType the file type
	 * @param systemType the system type
	 * @return the JSON object
	 */
	private JSONObject createKafkaMessage(String weaknessId, String objectKey, String fileType, String systemType) {
		JSONObject message = new JSONObject();
		try {
			message.put("id", weaknessId);
			message.put("uri", createFileUri(objectKey, systemType));
			message.put("fileType", fileType);
		} catch (JSONException e) {
			LOGGER.error("JSON Exception while creating kafka message : {}", e.getMessage());
		}
		return message;
	}

	/**
	 * Creates the file uri.
	 *
	 * @param objectKey the object key
	 * @param systemType the system type
	 * @return the object
	 */
	private Object createFileUri(String objectKey, String systemType) {
		if("s3".equalsIgnoreCase(systemType)) {
			return new StringBuilder().append("s3:/").append(objectKey).toString();
		}
		else {
			return new StringBuilder().append("file:///").append(objectKey).toString();
		}
	}

}
