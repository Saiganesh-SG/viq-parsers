package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.io.FileUtils;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.parser.CveDataProcessor;
import com.csw.data.mitre.parser.helper.CveDataHelper;
import com.csw.data.mitre.cve.pojo.VulnerabilityRoot;
import com.csw.data.mitre.cve.pojo.VulnerabilitySourceRoot;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Service
public class CveDataProcessorImpl implements CveDataProcessor {

	private static final Logger LOGGER = LoggerFactory.getLogger(CveDataProcessorImpl.class);

	@Autowired
	private CveDataHelper cveDataHelper;
	
    @Autowired
    private S3Client s3Client;
    
    @Value("${data.livekeep.bucketName}")
    private String s3BucketName;
    
    @Value("${sourcekeep.cve.path}")
    private String sourceCveS3Path;
    
    @Value("${livekeep.cve.path}")
    private String liveCveS3Path;

	@Value("${sourcekeep.cve.mitre.path}")
	private String sourcekeepDirectory;
	
	@Value("${temp.sourcekeep.cve.mitre.path}")
	private String tempSourceDirectory;
	
	@Value("${livekeep.cve.mitre.path}")
	private String livekeepDirectory;
	
	@Value("${parse.cve.download.url}")
	private String downloadURL;
	
//    @Value("${data.kafka.vulnerability.topic}")
//    private String vulnerabilityKafkaTopic;
//    
//    @Value("${batch.kafka.size}")
//    private int kafkaBatchSize;
//	
//    @Autowired
//    private KafkaTemplate<String, String> kafkaTemplate;

	@Override
	public void process() throws Exception {
		
		Long startTime = System.nanoTime();

		//Downloading zip file from Github link
		LOGGER.info("Source file download started");
		cveDataHelper.downloadSourceFile(downloadURL, tempSourceDirectory+"sourceZipFile.zip", tempSourceDirectory);
		LOGGER.info("Source file download completed");

		//Extracting the zip file
		LOGGER.info("Source extraction started");
		cveDataHelper.extractSourceFile(tempSourceDirectory+"sourceZipFile.zip",tempSourceDirectory);
		LOGGER.info("Source extraction completed");

		ObjectMapper mapper = new ObjectMapper();
		
		//Create a list of file consisting all the source files
		List<File> sourceCveFiles = new ArrayList<>();
		cveDataHelper.getSourceFiles(tempSourceDirectory, sourceCveFiles);
		LOGGER.info("Total files in SourceKeep is {}", sourceCveFiles.size());

		//Writing the source files to S3 sourcekeep bucket
		for(File file: sourceCveFiles) {
			
			FileUtils.copyFileToDirectory(file, new File(sourcekeepDirectory));
			
            String objectKey = sourceCveS3Path + file.getName();
            PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
            s3Client.putObject(request, Paths.get(sourcekeepDirectory+file.getName()));
		}

		//Modifying the source files to eliminate parsing exceptions
		cveDataHelper.sourceModifier(sourceCveFiles, mapper);
		List<JSONArray> messagebatch = new ArrayList<>();

		LOGGER.info("Parsing started");
		for (File file : sourceCveFiles) {

			String fileName = file.getName();

			try {
			VulnerabilitySourceRoot source = mapper.readValue(file, VulnerabilitySourceRoot.class);
			VulnerabilityRoot liveKeep = new VulnerabilityRoot();

			cveDataHelper.setVulnerabilityId(source, liveKeep);
			cveDataHelper.setDescriptions(source, liveKeep);
			cveDataHelper.setAssignerEmail(source, liveKeep);
			cveDataHelper.setRequesterEmail(source, liveKeep);
			cveDataHelper.setVulnerabilityStatus(source, liveKeep);
			cveDataHelper.setVulnerabilityTitle(source, liveKeep);
			cveDataHelper.setWeaknessId(source, liveKeep);
			cveDataHelper.setReferences(source, liveKeep);
			cveDataHelper.setPublishedDate(source, liveKeep);
			cveDataHelper.getCvssV3(source, liveKeep);
			cveDataHelper.getCvssV2(source, liveKeep);
			
			mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
			
			File livekeepFile = new File(livekeepDirectory);
			if(!livekeepFile.exists())
				livekeepFile.mkdirs();
			mapper.writeValue(new File(livekeepDirectory + fileName), liveKeep);
			
            String objectKey = sourceCveS3Path + "/mitre/" + fileName;
            PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
            s3Client.putObject(request, Paths.get(livekeepDirectory + fileName));
			
            //Creating kafka message
//			createKafkaMessage(fileName, messagebatch);
			
			}catch(Exception e) {
				LOGGER.info("Parsing exception occurred at file {}",fileName);
			}
		}
		
		//Sending messages to kafka at 1000 message per batch
//		JSONObject kafkaMessage = new JSONObject();
//		List<List<JSONArray>> partitionKafkaMessage = ListUtils.partition(messagebatch, kafkaBatchSize);
//		for(int i=0;i<partitionKafkaMessage.size();i++) {
//			
//			kafkaMessage.put("messages", partitionKafkaMessage.get(i)).put("forceUpdate", true);
//			try {
//				kafkaTemplate.send(vulnerabilityKafkaTopic, kafkaMessage.toString());
//			}catch(Exception e) {
//				LOGGER.error("Error while sending the message : {}", e.getMessage());
//			}
//		}
		
		LOGGER.info("Parsing completed");
		
		Long endTime = System.nanoTime();
		String duration = cveDataHelper.findDuration(startTime, endTime);
		
		LOGGER.info(duration);

	}
	
	//Creating the kafka JSON message format
	public void createKafkaMessage(String fileName, List<JSONArray> messagebatch) {

		JSONArray message = new JSONArray();
		JSONObject messageObject = new JSONObject();	
		
		messageObject.put("id", fileName);
		messageObject.put("uri", livekeepDirectory+fileName);
		messageObject.put("fileType", "CVE");
		messageObject.put("source", "Mitre");
		messageObject.put("delete", false);
		message.put(messageObject);
		messagebatch.add(message);		
	}
}
