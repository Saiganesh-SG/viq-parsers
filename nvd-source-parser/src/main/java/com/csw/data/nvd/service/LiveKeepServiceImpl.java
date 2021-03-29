package com.csw.data.nvd.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
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

import com.csw.data.nvd.json.target.Vulnerability;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Service
@Qualifier("LiveKeepService")
public class LiveKeepServiceImpl implements LiveKeepService {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(LiveKeepServiceImpl.class);
	
	@Value("${data.local.flag}")
	private boolean localFlag;
	
	@Value("${data.livekeep.cve.base.path}")
	private String s3cveBasePath;
	
	/** The s3 bucket name. */
	@Value("${data.livekeep.bucketName}")
	private String s3BucketName;
	
	/** The s3 client. */
	@Autowired
	private S3Client s3Client;

	@Override
	public JSONArray writeFileToLiveKeep(List<Vulnerability> vulnerabilities, String cveLocalDirectory) throws IOException {
		JSONArray kafkaMessage = new JSONArray();
		ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(Include.NON_NULL);
		
		for (Vulnerability vulnerability : vulnerabilities) {
			String targetFilePath = cveLocalDirectory + vulnerability.getId() + ParserConstants.JSON_FILE_EXTENSION;
			File targetFile = new File(targetFilePath);
			
			//livekeep file is written
			mapper.writeValue(targetFile, vulnerability);
			kafkaMessage.put(writeJsonAndMessage(targetFilePath, vulnerability.getId(), vulnerability, cveLocalDirectory));
		}
		return kafkaMessage;
	}
	
	private JSONObject writeJsonAndMessage(String file, String id, Vulnerability vulnerability, String cveLocalDirectory) {
		String fileSystemType = localFlag ? "file" : "s3";
		//write file to s3
		if("s3".equalsIgnoreCase(fileSystemType)) {
			String objectKey = s3cveBasePath + "/nvd/" + id + ParserConstants.JSON_FILE_EXTENSION;
			PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
			s3Client.putObject(request, Paths.get(file));
		}
		
		//generate meta json file
		generateMetaFile(file, cveLocalDirectory);
		
		//create and return the kafka message
		return createKafkaMessage(id, file, ParserConstants.CVE, fileSystemType);
	}
	
	private void generateMetaFile(String cveFilePath, String cveLocalDirectory) {
		try {
			String shaChecksum = HashingUtil.getShaChecksum(Files.readAllBytes(Paths.get(cveFilePath)));
			ObjectMapper mapper = new ObjectMapper();
			
			Map<String, Object> map = new HashMap<>();
			map.put("sha256", shaChecksum);
			
			String fileName = FilenameUtils.getBaseName(cveFilePath);
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
			e.printStackTrace();
		}
		return message;
	}
	
	private Object createFileUri(String objectKey, String systemType) {
		if("s3".equalsIgnoreCase(systemType)) {
			return new StringBuilder().append("s3://").append(objectKey).toString();
		}
		else {
			return new StringBuilder().append("file:///").append(objectKey).toString();
		}
	}

}
