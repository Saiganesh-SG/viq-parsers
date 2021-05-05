package com.csw.data.mitre.parser.impl;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.parser.DataProcessor;
import com.csw.data.mitre.parser.WeaknessParser;
import com.csw.data.mitre.utils.ParserFileUtils;
import com.csw.data.util.ParserConstants;

/**
 * The Class MitreSourceParserImpl.
 */
@Service
public class WeaknessParserImpl implements WeaknessParser {

	/** The Constant LOGGER. */
	private static final Logger LOGGER = LoggerFactory.getLogger(WeaknessParserImpl.class);

	/** The source keep base path. */
	@Value("${sourcekeep.cwe.mitre.path}")
	private String sourceKeepBasePath;
	
	/** The cwe download urls. */
	@Value("#{'${parse.cwe.download.url}'.split(',')}")
	private List<String> cweDownloadUrls;

	/** The cwe data processor. */
	@Autowired
	@Qualifier("CweDataProcessor")
	private DataProcessor cweDataProcessor;
	
	/**
	 * Download and parse the weakness.
	 * @throws Exception 
	 */
	@Override
	public void extractWeaknessFile() throws Exception {
		List<String> sourceFiles = ParserFileUtils.extractSourceFilesWithExtension(sourceKeepBasePath, cweDownloadUrls, "cpe", ParserConstants.XML_FILE_EXTENSION);
		cweDataProcessor.process(sourceFiles);
		LOGGER.info("CWE data process completed");
	}

}
