package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog;
import com.csw.data.nvd.parser.DataProcessor;
import com.csw.data.nvd.parser.helper.CweDataHelper;
import com.csw.data.nvd.pojo.cwe.Reference;

/**
 * The Class CweDataProcessorImpl.
 */
@Service
@Qualifier("CweDataProcessor")
public class CweDataProcessorImpl implements DataProcessor {

	/** The Constant logger. */
	private static final Logger logger = LoggerFactory.getLogger(CweDataProcessorImpl.class);
	
	/** The cwe data helper. */
	@Autowired
	private CweDataHelper cweDataHelper;
	
	@Autowired
	private KafkaTemplate<String, String> kafkaTemplate;
	
	@Value("${data.kafka.topic}")
	private String kafkaTopic;
	
	/**
	 * Process.
	 *
	 * @param sourceFilePath the source file path
	 * @throws Exception the exception
	 */
	public void process(String sourceFilePath) throws Exception {
		JAXBContext context = JAXBContext.newInstance(WeaknessCatalog.class);
        Unmarshaller un = context.createUnmarshaller();
        Object obj = un.unmarshal(new File(sourceFilePath));
        WeaknessCatalog weaknessCatalog = (WeaknessCatalog) obj;
        JSONArray kafkaMessage = new JSONArray();
        Map<String, Reference> externalReferenceList = cweDataHelper.extractExternalReferences(weaknessCatalog.getExternalReferences());
        cweDataHelper.extractWeakness(weaknessCatalog.getWeaknesses(), externalReferenceList, sourceFilePath, kafkaMessage);
        cweDataHelper.extractViews(weaknessCatalog.getViews(), externalReferenceList, sourceFilePath, kafkaMessage);
        cweDataHelper.extractCategories(weaknessCatalog.getCategories(), externalReferenceList, sourceFilePath, kafkaMessage);
        //TODO publish kafka message
        kafkaTemplate.send(kafkaTopic, kafkaMessage.toString());
	}
}
