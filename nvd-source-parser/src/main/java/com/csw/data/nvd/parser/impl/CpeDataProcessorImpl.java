package com.csw.data.nvd.parser.impl;

import com.csw.data.nvd.dto.cpe.CpeJsonData;
import com.csw.data.nvd.dto.cpe.CpeMatch;
import com.csw.data.nvd.parser.DataProcessor;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
@Qualifier("CpeDataProcessor")
public class CpeDataProcessorImpl implements DataProcessor {
    private static final Logger logger = LoggerFactory.getLogger(CpeDataProcessorImpl.class);

    @Value("${livekeep.base.path}")
	private String liveKeepBasePath;

	@Value("${cpe.path}")
	private String cpePath;

    @Override
    public void process(String sourceFilePath) throws Exception {
        Path path = Paths.get(sourceFilePath);
        byte[] jsonData = Files.readAllBytes(path);
        ObjectMapper mapper = new ObjectMapper();
        CpeJsonData cpeData = mapper.readValue(jsonData, CpeJsonData.class);
        List<CpeMatch> cpeMatches = cpeData.getCpeMatches();
        if (cpeMatches.isEmpty()) {
            return;
        }
        writeToLiveKeep(cpeMatches, sourceFilePath);
        System.out.println("Successfully parsed cpe");
    }

	private void writeToLiveKeep(List<CpeMatch> cpeMatches, String sourceFilePath) {
		ObjectMapper mapper = new ObjectMapper();
		for (CpeMatch cpeMatch : cpeMatches) {
			try {
				String cpeLiveKeepDirectory = liveKeepBasePath + cpePath + "/" + ParserConstants.NVD + "/";
				String cleansedFileName  = cleanseFileName(cpeMatch.getCpeKey());
				String cpeFile = cpeLiveKeepDirectory + cleansedFileName + ParserConstants.JSON_FILE_EXTENSION;
				mapper.writeValue(new File(cpeFile), cpeMatch);
				mapper.writerWithDefaultPrettyPrinter().writeValueAsString(cpeMatch);
				generateMetaFile(new File(cpeFile), sourceFilePath, cpeLiveKeepDirectory);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void generateMetaFile(File file, String sourceFilePath, String cpeLiveKeepDirectory) {
		try {
			String shaChecksum = "sdsdsds";
			ObjectMapper mapper = new ObjectMapper();
			Map<String, Object> map = new HashMap<>();
			map.put("sha256", shaChecksum);
			List<String> sourceFileLocation = new ArrayList<>();
			sourceFileLocation.add(sourceFilePath);
			map.put("sourceFiles", sourceFileLocation);
			String baseFileName = FilenameUtils.getBaseName(file.getName());
			mapper.writeValue(Paths.get(cpeLiveKeepDirectory + baseFileName + ".meta.json").toFile(), map);
		} catch (IOException e) {
			logger.error("IOException while reading the Json file");
		}
	}
	
	private String cleanseFileName(String cpeKey) {
		String cleansedFileName = cpeKey.replaceAll("[\\\\/:*?\"<>|]", "");
		return cleansedFileName;
	}
}
