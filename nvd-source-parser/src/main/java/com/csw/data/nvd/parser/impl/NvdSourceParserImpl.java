package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.config.ErrorMessage;
import com.csw.data.nvd.config.ParseType;
import com.csw.data.nvd.exception.InvalidParameterException;
import com.csw.data.nvd.parser.DataProcessor;
import com.csw.data.nvd.parser.NvdSourceParser;
import com.csw.data.nvd.utils.ParserFileUtils;
import com.csw.data.util.ParserConstants;

/**
 * The Class NvdSourceParserImpl.
 */
@Service
public class NvdSourceParserImpl implements NvdSourceParser {

	private static final Logger logger = LoggerFactory.getLogger(NvdSourceParserImpl.class);

	@Value("${sourcekeep.base.path}")
	private String sourceKeepBasePath;

	@Value("${cwe.path}")
	private String cwePath;
	
	@Value("${cpe.path}")
	private String cpePath;

	@Value("#{'${parse.cwe.download.url}'.split(',')}")
	private List<String> cweDownloadUrls;
	
	@Value("#{'${parse.cpe.download.url}'.split(',')}")
    private List<String> cpeDownloadUrls;

	@Autowired
	@Qualifier("CweDataProcessor")
	private DataProcessor cweDataProcessor;
	
	@Autowired
    @Qualifier("CpeDataProcessor")
    DataProcessor cpeDataProcessor;

	/**
	 * Run.
	 *
	 * @param parseType the parse type
	 * @param isLatest the is latest
	 * @throws Exception the exception
	 */
	@Override
	public void run(String parseType, boolean isLatest) throws Exception {

		if (parseType == null || !ParseType.isValidParseType(parseType)) {
			throw new InvalidParameterException(ErrorMessage.INVALID_PARSE_TYPE);
		}
		
		ParseType type = ParseType.forNameIgnoreCase(parseType);
		//Parse Common Weakness Enumeration from Mitre
		if (type.name().equalsIgnoreCase(ParseType.CWE.name())) {
			parseCwe(isLatest);
		}
		
		//Parse Common Platform Enumeration from NVD
		if (type.name().equalsIgnoreCase(ParseType.CPE.name())) {
            parseCpe(isLatest);
        }
	}

	/**
	 * Parses the cwe.
	 *
	 * @param isLatest the is latest
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private void parseCwe(Boolean isLatest) throws IOException {
		String directoryPath = sourceKeepBasePath + cwePath + "/" + ParserConstants.NVD;
		if (isLatest) {
			logger.info("Processing newly added and modified CWEs");
			directoryPath = ParserFileUtils.getDownloadedDirectoryPath(directoryPath, cweDownloadUrls,
					ParseType.CWE.name());
		}
		File cweDirectory = new File(directoryPath);
		if (!cweDirectory.exists()) {
			logger.error("CWE base directory " + directoryPath + " does not exist");
		}
		processsFilesInDirectoryWithSelectedExtension(directoryPath, ParserConstants.XML_FILE_EXTENSION,
				cweDataProcessor);
		logger.info("CWE data process completed");
	}
	
	/**
	 * Parses the cpe.
	 *
	 * @param isLatest the is latest
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private void parseCpe(Boolean isLatest) throws IOException {
        String directoryPath = sourceKeepBasePath + cpePath + "/" + ParserConstants.NVD;
        if (isLatest) {
            logger.info("Processing newly added and modified CPEs");
            directoryPath = ParserFileUtils.getDownloadedDirectoryPath(directoryPath, cpeDownloadUrls, ParseType.CPE.name());
        }
        File cpeDirectory = new File(directoryPath);
        if (!cpeDirectory.exists()) {
            logger.error("CPE base directory " + directoryPath + " does not exist");
        }
        processsFilesInDirectoryWithSelectedExtension(directoryPath, ParserConstants.JSON_FILE_EXTENSION, cpeDataProcessor);
        logger.info("Cpe data process completed");
    }

	/**
	 * Processs files in directory with selected extension.
	 *
	 * @param directoryPath the directory path
	 * @param fileExtension the file extension
	 * @param processor the processor
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private void processsFilesInDirectoryWithSelectedExtension(String directoryPath, String fileExtension,
			DataProcessor processor) throws IOException {
		Stream<Path> walk = Files.walk(Paths.get(directoryPath));
		walk.map(x -> x.toString()).filter(path -> {
			return path.endsWith(fileExtension);
		}).forEach(path -> process(path, processor));
	}

	/**
	 * Process.
	 *
	 * @param filePath the file path
	 * @param processor the processor
	 */
	private void process(String filePath, DataProcessor processor) {
		try {
			logger.debug("Processing the file - " + filePath);
			processor.process(filePath);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
	}

}
