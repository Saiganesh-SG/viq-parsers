package com.csw.data.mitre.parser.impl;

import java.io.File;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureCallback;

import com.csw.data.mitre.jaxb.cwe.WeaknessCatalog;
import com.csw.data.mitre.parser.DataProcessor;
import com.csw.data.mitre.parser.helper.CweDataHelper;
import com.csw.data.mitre.pojo.cwe.Reference;

/**
 * The Class CweDataProcessorImpl.
 */
@Service
@Qualifier("CweDataProcessor")
public class CweDataProcessorImpl implements DataProcessor {

	/** The Constant logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CweDataProcessorImpl.class);
	
	/** The cwe data helper. */
	@Autowired
	private CweDataHelper cweDataHelper;
	
	/** The kafka template. */
	@Autowired
	private KafkaTemplate<String, String> kafkaTemplate;
	
	/** The kafka topic. */
	@Value("${data.kafka.topic}")
	private String kafkaTopic;
	
	/**
	 * Process.
	 *
	 * @param sourceFiles the source file path
	 * @throws Exception the exception
	 */
	public void process(List<String> sourceFiles) throws Exception {
		for (String sourceFilePath : sourceFiles) {
			WeaknessCatalog weaknessCatalog = unmarshalWeaknessCatalog(sourceFilePath);
			
	        JSONArray kafkaMessage = new JSONArray();
	        
	        Map<String, Reference> externalReferenceList = cweDataHelper.extractExternalReferences(weaknessCatalog.getExternalReferences());
	        cweDataHelper.extractWeakness(weaknessCatalog.getWeaknesses(), externalReferenceList, sourceFilePath, kafkaMessage);
	        cweDataHelper.extractViews(weaknessCatalog.getViews(), externalReferenceList, sourceFilePath, kafkaMessage);
	        cweDataHelper.extractCategories(weaknessCatalog.getCategories(), externalReferenceList, sourceFilePath, kafkaMessage);
	        LOGGER.info("Sending the message to kafka topic : {}", kafkaTopic);
	        LOGGER.info("Kafka message length : {}", kafkaMessage.length());
			ListenableFuture<SendResult<String, String>> future = kafkaTemplate.send(kafkaTopic, kafkaMessage.toString());
			LOGGER.info("running the kafka callback");
			future.addCallback(new ListenableFutureCallback<SendResult<String, String>>() {

				@Override
				public void onSuccess(SendResult<String, String> result) {
					System.out.println("Sent message with offset=[" + result.getRecordMetadata().offset() + "] to topic = " + result.getRecordMetadata().topic());
					LOGGER.info("Sent message with offset = {} to topic = {}", result.getRecordMetadata().offset(), result.getRecordMetadata().topic());
				}

				@Override
				public void onFailure(Throwable ex) {
					System.out.println("Unable to send message due to : {}"+ ex.getMessage());
					LOGGER.info("Unable to send message due to : {}", ex.getMessage());
					LOGGER.error("Unable to send message due to: {}", ex.getMessage(), ex);
				}
			});
	        
		}
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
}
