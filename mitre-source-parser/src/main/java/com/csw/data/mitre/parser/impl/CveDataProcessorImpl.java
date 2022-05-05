package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.collections4.ListUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.parser.CveDataProcessor;
import com.csw.data.mitre.parser.helper.CveDataHelper;
import com.csw.data.mitre.audit.MitreJobStatusEnumeration;
import com.csw.data.mitre.audit.MitreParserAudit;
import com.csw.data.mitre.audit.RecordDetails;
import com.csw.data.mitre.cve.pojo.VulnerabilityRoot;
import com.csw.data.mitre.cve.pojo.VulnerabilitySourceRoot;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

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
	
	@Value("${livekeep.cve.mitre.path}")
	private String livekeepDirectory;
	
	@Value("${parse.cve.download.url}")
	private String downloadURL;
	
    @Value("${data.kafka.vulnerability.topic}")
    private String vulnerabilityKafkaTopic;
    
    @Value("${batch.kafka.size}")
    private int kafkaBatchSize;
	
    @Autowired
    private KafkaTemplate<String, String> kafkaTemplate;

	@Override
	public void process() throws Exception {
		
		LocalDateTime startTime = LocalDateTime.now();

		//Downloading zip file from Github link
		LOGGER.info("Source file download started");
		cveDataHelper.downloadSourceFile(downloadURL, sourcekeepDirectory+"cvelist-master.zip", sourcekeepDirectory);
		LOGGER.info("Source file download completed");

		//Extracting the zip file
		LOGGER.info("Source extraction started");
		cveDataHelper.extractSourceFile(sourcekeepDirectory+"cvelist-master.zip",sourcekeepDirectory);
		LOGGER.info("Source extraction completed");

		ObjectMapper mapper = new ObjectMapper();
		
		//Create a list of file consisting all the source files
		List<File> sourceCveFiles = new ArrayList<>();
		cveDataHelper.getSourceFiles(sourcekeepDirectory, sourceCveFiles);
		LOGGER.info("Total count of files = {}", sourceCveFiles.size());

		//Modifying the source files to eliminate parsing exceptions
		cveDataHelper.sourceModifier(sourceCveFiles, mapper);
		List<JSONObject> messagebatch = new ArrayList<>();
		
		//Getting the modified source files
		List<File> modifiedFiles = new ArrayList<>();
		cveDataHelper.getSourceFiles(sourcekeepDirectory, modifiedFiles);
		
		//List to get the CVEs which failed parsing
		List<String> failedRecords = new ArrayList<>();
		
		//Create livekeep directory if it does not exists
		File livekeepFile = new File(livekeepDirectory);
		if(!livekeepFile.exists())
			livekeepFile.mkdirs();
		
		//Parsing sourcekeep files into livekeep format
		LOGGER.info("Parsing started");
		for (File file : modifiedFiles) {

			String fileName = file.getName();

			try {
			VulnerabilitySourceRoot source = mapper.readValue(file, VulnerabilitySourceRoot.class);
			VulnerabilityRoot liveKeep = new VulnerabilityRoot();

			cveDataHelper.setVulnerabilityId(source, liveKeep);
			cveDataHelper.setSource(source, liveKeep);
			cveDataHelper.setDescriptions(source, liveKeep);
			cveDataHelper.setAssignerEmail(source, liveKeep);
			cveDataHelper.setRequesterEmail(source, liveKeep);
			cveDataHelper.setVulnerabilityStatus(source, liveKeep, liveKeep.getDescriptions());
			cveDataHelper.setVulnerabilityTitle(source, liveKeep);
			cveDataHelper.setWeaknessId(source, liveKeep);
			cveDataHelper.setReferences(source, liveKeep);
			cveDataHelper.setPublishedDate(source, liveKeep);
			cveDataHelper.getCvssV3(source, liveKeep);
			cveDataHelper.getCvssV2(source, liveKeep);
			
			mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
			mapper.writeValue(new File(livekeepDirectory + fileName), liveKeep);
			
			//Writing file into S3
            String objectKey = liveCveS3Path + fileName;
            PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
            s3Client.putObject(request, Paths.get(livekeepDirectory + fileName));
			
            //Creating kafka message
			createKafkaMessage(fileName, messagebatch);
			
			}catch(Exception e) {
				LOGGER.info("Parsing exception occurred while genarating livekeep file {}",fileName);
				failedRecords.add(fileName);
				e.printStackTrace();
			}
		}
		
		//Sending messages to kafka at 1000 message per batch
		LOGGER.info("Sending message to Kafka");
		JSONObject kafkaMessage = new JSONObject();
		List<List<JSONObject>> partitionKafkaMessage = ListUtils.partition(messagebatch, kafkaBatchSize);
		for(int i=0;i<partitionKafkaMessage.size();i++) {
			
			kafkaMessage.put("messages", partitionKafkaMessage.get(i)).put("forceUpdate", true);
			try {
				kafkaTemplate.send(vulnerabilityKafkaTopic, kafkaMessage.toString());
			}catch(Exception e) {
				LOGGER.error("Error while sending the message : {}", e.getMessage());
			}
		}
		
		LOGGER.info("Parsing completed");
		LocalDateTime endTime = LocalDateTime.now();
		
		String jobAudit = auditLog(startTime, endTime, failedRecords.size(), modifiedFiles.size());
		LOGGER.info("Job Audit : {}", jobAudit);
	}
	
	//Creating the kafka message in JSON format
	public void createKafkaMessage(String fileName, List<JSONObject> messagebatch) {
		
		JSONObject messageObject = new JSONObject();
		String id = fileName.split("\\.")[0];
		
		messageObject.put("id", id);
		messageObject.put("uri","s3://"+s3BucketName+"/"+liveCveS3Path+fileName);
		messageObject.put("fileType", "CVE");
		messageObject.put("source", "Mitre");
		messageObject.put("delete", false);
		messagebatch.add(messageObject);		
	}
	
	//Method to create tje Job Audit Log JSON
	public String auditLog(LocalDateTime startTime, LocalDateTime endTime, int failed, int records) throws JsonProcessingException {
		
		MitreParserAudit audit = new MitreParserAudit();
		DateTimeFormatter auditTimeFormat = DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss");
		Long jobStartTime = TimeUnit.MILLISECONDS.toSeconds(Timestamp.valueOf(startTime).getTime()); 
		Long jobEndTime = TimeUnit.MILLISECONDS.toSeconds(Timestamp.valueOf(endTime).getTime());
		
		RecordDetails recordDetails = new RecordDetails();
		recordDetails.setFailedRecords(failed);
		recordDetails.setModifiedRecords(0);
		recordDetails.setNewRecords(records);
		recordDetails.setTotalRecords(records);
		
		audit.setStartTime(auditTimeFormat.format(startTime));
		audit.setEndTime(auditTimeFormat.format(endTime));
		audit.setJobName("Mitre CVE Parser");
		audit.setRefreshType("Full Refresh");
		audit.setTotalTime(String.valueOf(jobEndTime - jobStartTime));
		audit.setRecordDetails(recordDetails);
		audit.setJobStatus(MitreJobStatusEnumeration.COMPLETED);
		
		ObjectMapper mapper = new ObjectMapper();
		return mapper.writeValueAsString(audit);
	}
}