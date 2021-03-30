package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.config.ParseType;
import com.csw.data.nvd.json.target.VendorComment;
import com.csw.data.nvd.json.target.Vulnerability;
import com.csw.data.nvd.parser.CveProcessor;
import com.csw.data.nvd.parser.helper.CveConstructor;
import com.csw.data.util.ParserConstants;
import com.csw.data.util.ParserFileUtils;

@Service
@Qualifier("CveProcessor")
public class CveProcessorImpl implements CveProcessor {

	private static final Logger LOGGER = LoggerFactory.getLogger(CveProcessorImpl.class);
	
	@Autowired
	private CveConstructor cveConstructor;

	@Override
	public Map<String, List<VendorComment>> extractVendorComments(List<String> vendorCommentUrls, String cveSourceDirectory) {
		Map<String, List<VendorComment>> vendorComments = new HashMap<>();
		try {
			String sourceDirectory = ParserFileUtils.getDownloadedDirectoryPath(cveSourceDirectory, vendorCommentUrls, ParseType.COMMENT.name());
			File cveDirectory = new File(sourceDirectory);
			if (!cveDirectory.exists()) {
				LOGGER.error("CVE base directory {} does not exist", cveDirectory);
			}
			List<Path> sourcePaths = extractFilePathByExtension(sourceDirectory, ParserConstants.XML_FILE_EXTENSION);
			vendorComments.putAll(processVendorCommentsFromSource(sourcePaths));
		} catch (IOException e) {
			LOGGER.error("Error while processing the vendor comments file : {}", e.getMessage());
		}
		return vendorComments;
	}

	@Override
	public List<Vulnerability> extractVulnerabilitiesFromSource(List<String> cveDownloadUrls, String cveSourceDirectory, Map<String, List<VendorComment>> vendorComments) {
		List<Vulnerability> vulnerabilities = new ArrayList<>();
		try {
			String sourceDirectory = ParserFileUtils.getDownloadedDirectoryPath(cveSourceDirectory, cveDownloadUrls, ParseType.CVE.name());
			File cveDirectory = new File(sourceDirectory);
			if (!cveDirectory.exists()) {
				LOGGER.error("CVE base directory {} does not exist", cveDirectory);
			}
			vulnerabilities.addAll(processVulnerabilitiesFromSource(extractFilePathByExtension(sourceDirectory, ParserConstants.JSON_FILE_EXTENSION), vendorComments));
			FileUtils.cleanDirectory(cveDirectory);
		} catch (IOException e) {
			LOGGER.error("Error while processing the source file : {}", e.getMessage());
		}
		
		return vulnerabilities;
	}

	private List<Path> extractFilePathByExtension(String sourceDirectory, String fileExtension) throws IOException {
		List<Path> result = new ArrayList<>();

		try (Stream<Path> walk = Files.walk(Paths.get(sourceDirectory))) {
			result = walk.filter(Files::isRegularFile)
					.filter(path -> path.getFileName().toString().endsWith(fileExtension))
					.collect(Collectors.toList());
		}
		return result;
	}

	private List<Vulnerability> processVulnerabilitiesFromSource(List<Path> sourceFiles, Map<String, List<VendorComment>> vendorComments) {
		List<Vulnerability> result = new ArrayList<>();
		for (Path sourceFile : sourceFiles) {
			result.addAll(cveConstructor.constructVulnerabilititesFromSource(sourceFile, vendorComments));
		}
		return result;
	}
	
	private Map<String, List<VendorComment>> processVendorCommentsFromSource(List<Path> sourceFiles) {
		Map<String, List<VendorComment>> result = new HashMap<>();
		for (Path sourceFile : sourceFiles) {
			result.putAll(cveConstructor.constructVendorCommentsFromSource(sourceFile));
		}
		return result;
	}

}
