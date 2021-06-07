package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.audit.MitreJobStatusEnumeration;
import com.csw.data.mitre.audit.MitreParserAudit;
import com.csw.data.mitre.audit.RecordDetails;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog;
import com.csw.data.mitre.cwe.pojo.Reference;
import com.csw.data.mitre.cwe.pojo.WeaknessMetaData;
import com.csw.data.mitre.cwe.pojo.WeaknessRoot;
import com.csw.data.mitre.parser.DataProcessor;
import com.csw.data.mitre.parser.LivekeepService;
import com.csw.data.mitre.parser.helper.CweDataHelper;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The Class CweDataProcessorImpl.
 */
@Service
@Qualifier("CweDataProcessor")
public class CweDataProcessorImpl implements DataProcessor {

	/** The Constant logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CweDataProcessorImpl.class);
	
	/** The kafka template. */
	@Autowired
	private KafkaTemplate<String, String> kafkaTemplate;
	
	/** The kafka topic. */
	@Value("${data.kafka.topic}")
	private String kafkaTopic;
	
	/** The cwe data helper. */
	@Autowired
	private CweDataHelper cweDataHelper;
	
	/** The livekeep service. */
	@Autowired
	@Qualifier("LivekeepService")
	private LivekeepService livekeepService;
	
	/**
	 * Process.
	 *
	 * @param sourceFiles the source file path
	 * @throws Exception the exception
	 */
	public void process(List<String> sourceFiles) throws Exception {
		for (String sourceFilePath : sourceFiles) {
			WeaknessCatalog weaknessCatalog = unmarshalWeaknessCatalog(sourceFilePath);
			List<WeaknessRoot> weaknessList = new ArrayList<>();
			Map<String, Integer> recordStats = initializeRecordStatMap();
			
			//record the parser start time
			LocalDateTime startTime = LocalDateTime.now();
			
	        //extract weakness meta data and external references
	        Map<String, WeaknessMetaData> weaknessMetaDataList = cweDataHelper.extractWeaknessMetaData(weaknessCatalog);
	        Map<String, Reference> externalReferenceList = cweDataHelper.extractExternalReferences(weaknessCatalog.getExternalReferences());
	        
	        //extract all the weakness data
	        weaknessList.addAll(cweDataHelper.extractWeakness(weaknessCatalog.getWeaknesses(), externalReferenceList, weaknessMetaDataList));
	        weaknessList.addAll(cweDataHelper.extractViews(weaknessCatalog.getViews(), externalReferenceList, weaknessMetaDataList));
	        weaknessList.addAll(cweDataHelper.extractCategories(weaknessCatalog.getCategories(), externalReferenceList, weaknessMetaDataList));
	        
	        //write to livekeep and return the kafka message only for modified weakness
	        JSONArray kafkaMessage = new JSONArray();
	        for (WeaknessRoot weakness : weaknessList) {
	        	JSONObject jsonObject = livekeepService.writeToLiveKeep(weakness, sourceFilePath, recordStats);
	        	if(null != jsonObject) {
	        		kafkaMessage.put(jsonObject);
	        	}
			}
	        
	        LOGGER.info("kafkaMessage size :: {}", kafkaMessage.length());
	        
	        JSONObject updatedMessage = updateKafkaMessage(kafkaMessage);
	        
	        //publish the kafka message
			try {
				kafkaTemplate.send(kafkaTopic, updatedMessage.toString()).get();
			} catch (Exception e) {
				LOGGER.info("Error while sending the message : {}", e.getMessage());
			}
	        
	        //update the final job audit
			LocalDateTime endTime = LocalDateTime.now();
	        MitreParserAudit audit = logAudit(weaknessCatalog, startTime, endTime, recordStats);
	        
			ObjectMapper logMapper = new ObjectMapper();
			String jobAudit = logMapper.writeValueAsString(audit);
			
			LOGGER.info("Job Audit : {}", jobAudit);
		}
	}

	/**
	 * Update kafka message.
	 *
	 * @param kafkaMessage the kafka message
	 * @return the JSON object
	 * @throws JSONException the JSON exception
	 */
	private JSONObject updateKafkaMessage(JSONArray kafkaMessage) throws JSONException {
	    JSONObject jsonObject = new JSONObject();
	    jsonObject.put("forceUpdate", "true");
	    jsonObject.put("messages", kafkaMessage);
        return jsonObject;
    }

    /**
	 * Unmarshal weakness catalog.
	 *
	 * @param sourceFilePath the source file path
	 * @return the weakness catalog
	 * @throws JAXBException the JAXB exception
	 */
	private WeaknessCatalog unmarshalWeaknessCatalog(String sourceFilePath) throws JAXBException {
		File sourceFile = new File(sourceFilePath);
		if(!sourceFile.exists()) {
			LOGGER.error("The source file does not exist : {}", sourceFilePath);
		}
		JAXBContext context = JAXBContext.newInstance(WeaknessCatalog.class);
        Unmarshaller un = context.createUnmarshaller();
        Object obj = un.unmarshal(new File(sourceFilePath));
        return (WeaknessCatalog) obj;
	}
	
	/**
	 * Log audit.
	 *
	 * @param weaknessCatalog the weakness catalog
	 * @param startTime the start time
	 * @param endTime the end time
	 * @param recordStats the record stats
	 * @return the mitre parser audit
	 */
	private MitreParserAudit logAudit(WeaknessCatalog weaknessCatalog, LocalDateTime startTime, LocalDateTime endTime,
			Map<String, Integer> recordStats) {
		MitreParserAudit audit = new MitreParserAudit();
		DateTimeFormatter auditTimeFormat = DateTimeFormatter.ofPattern("uuuu/MM/dd HH:mm:ss");
		Long jobStartTime = TimeUnit.MILLISECONDS.toSeconds(Timestamp.valueOf(startTime).getTime()); 
		Long jobEndTime = TimeUnit.MILLISECONDS.toSeconds(Timestamp.valueOf(endTime).getTime());

		RecordDetails recordDetails = new RecordDetails();
		recordDetails.setTotalRecords(weaknessCatalog.getWeaknesses().size()
				+ weaknessCatalog.getViews().getView().size() + weaknessCatalog.getCategories().getCategory().size());
		recordDetails.setNewRecords(recordStats.get("newRecords"));
		recordDetails.setModifiedRecords(recordStats.get("modifiedRecords"));

		audit.setJobName("Mitre CWE Parser");
		audit.setRefreshType("Full Refresh");
		audit.setStartTime(auditTimeFormat.format(startTime));
		audit.setEndTime(auditTimeFormat.format(endTime));
		audit.setTotalTime(String.valueOf(jobEndTime - jobStartTime));
		audit.setRecordDetails(recordDetails);
		audit.setJobStatus(MitreJobStatusEnumeration.COMPLETED);
		return audit;
	}
	
	/**
	 * Initialize record stat map.
	 *
	 * @return the map
	 */
	private Map<String, Integer> initializeRecordStatMap() {
		Map<String, Integer> recordsStatMap = new HashMap<>();
		recordsStatMap.put("newRecords", 0);
		recordsStatMap.put("modifiedRecords", 0);
		recordsStatMap.put("failedRecords", 0);
		return recordsStatMap;
	}
}
