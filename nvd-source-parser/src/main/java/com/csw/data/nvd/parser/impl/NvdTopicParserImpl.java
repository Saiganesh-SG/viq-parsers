package com.csw.data.nvd.parser.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.parser.CommonVulnerabilityExtractor;
import com.csw.data.nvd.parser.NvdTopicParser;

/**
 * The Class NvdSourceParserImpl.
 */
@Service
@Qualifier("NvdTopicParser")
public class NvdTopicParserImpl implements NvdTopicParser {

	private static final Logger LOGGER = LoggerFactory.getLogger(NvdTopicParserImpl.class);
	
	@Autowired
	private CommonVulnerabilityExtractor commonVulnerabilityExtractor;

	/**
	 * Run.
	 *
	 * @param parseType the parse type
	 * @param isLatest the is latest
	 * @throws Exception the exception
	 */
	@Override
	public void run(String parseType, boolean processLatest) throws Exception {
		switch (parseType) {
		case "cve":
			commonVulnerabilityExtractor.parseCve(processLatest);
			break;
			
		case "cpe":
		    commonVulnerabilityExtractor.parseCpe();
			break;
			
		case "cpe_dictionary":
            commonVulnerabilityExtractor.parseCpeDictionary();
            break;
			
		default:
			break;
		}
	}

}
