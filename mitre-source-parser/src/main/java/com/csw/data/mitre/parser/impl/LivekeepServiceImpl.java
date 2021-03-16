package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FilenameUtils;
import org.json.JSONObject;
import org.leadpony.justify.api.JsonSchema;
import org.leadpony.justify.api.JsonValidationService;
import org.leadpony.justify.api.ProblemHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.parser.LivekeepService;
import com.csw.data.mitre.pojo.cwe.WeaknessRoot;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.json.stream.JsonParser;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Service
@Qualifier("LivekeepService")
public class LivekeepServiceImpl implements LivekeepService {
	
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

	@Override
	public JSONObject writeToLiveKeep(WeaknessRoot weakness, String sourceFilePath) throws Exception {
		ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(Include.NON_NULL);
		String cweFile = liveKeepBasePath + weakness.getId() + ParserConstants.JSON_FILE_EXTENSION;
		File weaknessFile = new File(cweFile);
		
			//livekeep file is written
			mapper.writeValue(weaknessFile, weakness);
			
			//json schema validation here with justify
			JsonValidationService service = JsonValidationService.newInstance();
			JsonSchema schema = service.readSchema(Paths.get("src/main/resources/schema/cwe_schema.json"));
			ProblemHandler handler = service.createProblemPrinter(System.out::println);
			Path jsonSubject = weaknessFile.toPath();
			
			// Parses the JSON instance by JsonParser
			try (JsonParser parser = service.createParser(jsonSubject, schema, handler)) {
			    while (parser.hasNext()) {
			        JsonParser.Event event = parser.next();
			        // Do something useful here
			    }
			}
		
		return writeJsonAndMessage(cweFile, weakness.getId(), sourceFilePath);
	}
	
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

	private JSONObject createKafkaMessage(String weaknessId, String objectKey, String fileType, String systemType) {
		JSONObject message = new JSONObject();
		message.put("id", weaknessId);
		message.put("uri", createFileUri(objectKey, systemType));
		message.put("fileType", fileType);
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
