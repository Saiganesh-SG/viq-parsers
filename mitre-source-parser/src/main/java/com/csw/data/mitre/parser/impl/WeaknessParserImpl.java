package com.csw.data.mitre.parser.impl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.mitre.config.ParseType;
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
	
	/** The s 3 bucket name. */
	@Value("${data.livekeep.bucketName}")
	private String s3BucketName;

	/** The cwe path. */
	@Value("${cwe.path}")
	private String cwePath;
	
	/** The cwe download urls. */
	@Value("#{'${parse.cwe.download.url}'.split(',')}")
	private List<String> cweDownloadUrls;

	/** The cwe data processor. */
	@Autowired
	@Qualifier("CweDataProcessor")
	private DataProcessor cweDataProcessor;
	
	/** The local flag. */
	@Value("${data.local.flag}")
	private boolean localFlag;
	
	/**
	 * Download and parse the weakness.
	 * @throws Exception 
	 */
	@Override
	public void extractWeaknessFile() throws Exception {
		ParserFileUtils.getDownloadedDirectoryPath(sourceKeepBasePath, cweDownloadUrls, ParseType.CWE.name());
		List<String> sourceFiles = processsFilesInDirectoryWithExtension(sourceKeepBasePath, ParserConstants.XML_FILE_EXTENSION);
		cweDataProcessor.process(sourceFiles);
		LOGGER.info("CWE data process completed");
	}
	
	/**
	 * Processs files in directory with selected extension.
	 *
	 * @param directoryPath the directory path
	 * @param fileExtension the file extension
	 * @return the list
	 */
	private List<String> processsFilesInDirectoryWithExtension(String directoryPath, String fileExtension) {
		List<String> files = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(Paths.get(directoryPath))) {
            files = walk
                    .filter(p -> !Files.isDirectory(p))
                    .map(p -> p.toString().toLowerCase())
                    .filter(f -> f.endsWith(fileExtension))
                    .collect(Collectors.toList());
        } catch (IOException e) {
        	LOGGER.error("Error in reading source file from the directory: {}", e.getMessage(), e);
		}
        return files;
	}

}
