package com.csw.data.mitre.parser.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.parser.MitreTopicParser;
import com.csw.data.mitre.parser.WeaknessParser;

/**
 * The Class MitreTopicParserImpl.
 */
@Service
@Qualifier("MitreTopicParser")
public class MitreTopicParserImpl implements MitreTopicParser {
	
	/** The Constant LOGGER. */
	private static final Logger LOGGER = LoggerFactory.getLogger(MitreTopicParserImpl.class);
	
	/** The weakness parser. */
	@Autowired
	private WeaknessParser weaknessParser;

	/**
	 * Parses the topic type.
	 *
	 * @param topicType the topic type
	 * @throws Exception the exception
	 */
	@Override
	public void parseTopicType(String topicType) throws Exception {
		switch (topicType) {
		case "cwe":
			LOGGER.info("started extracting CWE from mitre...");
			weaknessParser.extractWeaknessFile();
			break;
			
		case "cve":
			LOGGER.debug("Started Parsing CPE");
			break;
			
		default:
			break;
		}
	}

}
