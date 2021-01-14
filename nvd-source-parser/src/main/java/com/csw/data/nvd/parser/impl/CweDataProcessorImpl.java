package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.sax.SAXSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.xml.sax.InputSource;
import org.xml.sax.XMLReader;

import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog.Weaknesses;
import com.csw.data.nvd.jaxb.cwe.WeaknessType;
import com.csw.data.nvd.parser.DataProcessor;
import com.csw.data.nvd.parser.util.NamespaceFilter;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
@Qualifier("CweDataProcessor")
public class CweDataProcessorImpl implements DataProcessor {

	private static final Logger logger = LoggerFactory.getLogger(CweDataProcessorImpl.class);

	@Value("${livekeep.base.path}")
	private String liveKeepBasePath;

	@Value("${cwe.path}")
	private String cwePath;

	public void process(String sourceFilePath) throws Exception {
		JAXBContext context = JAXBContext.newInstance(WeaknessCatalog.class);
		Unmarshaller unmarshaller = context.createUnmarshaller();

		SAXParserFactory parserFactory = SAXParserFactory.newInstance();
		SAXParser parser = parserFactory.newSAXParser();
		XMLReader reader = parser.getXMLReader();
		NamespaceFilter outFilter = new NamespaceFilter("http://cwe.mitre.org/cwe-6", false);
		outFilter.setParent(reader);

		Path path = Paths.get(sourceFilePath);
		InputSource is = new InputSource(Files.newInputStream(path));
		SAXSource source = new SAXSource(outFilter, is);

		JAXBElement<WeaknessCatalog> element = unmarshaller.unmarshal(source, WeaknessCatalog.class);
		WeaknessCatalog weaknessCatalog = element.getValue();
		Weaknesses weaknessesList = weaknessCatalog.getWeaknesses();
		List<WeaknessType> weaknesses = weaknessesList.getWeakness();

		writeToLiveKeep(weaknesses, sourceFilePath);
	}

	private void writeToLiveKeep(List<WeaknessType> weaknesses, String sourceFilePath) {
		ObjectMapper mapper = new ObjectMapper();
		for (WeaknessType weakness : weaknesses) {
			try {
				String cweLiveKeepDirectory = liveKeepBasePath + cwePath + "/" + ParserConstants.NVD + "/";
				String cweFile = cweLiveKeepDirectory + weakness.getID() + ParserConstants.JSON_FILE_EXTENSION;
				mapper.writeValue(new File(cweFile), weakness);
				mapper.writerWithDefaultPrettyPrinter().writeValueAsString(weakness);
				generateMetaFile(new File(cweFile), sourceFilePath, cweLiveKeepDirectory);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private void generateMetaFile(File file, String sourceFilePath, String cweLiveKeepDirectory) {
		try {
			String shaChecksum = HashingUtil.getShaChecksum(file);
			ObjectMapper mapper = new ObjectMapper();
			Map<String, Object> map = new HashMap<>();
			map.put("sha256", shaChecksum);
			List<String> sourceFileLocation = new ArrayList<>();
			sourceFileLocation.add(sourceFilePath);
			map.put("sourceFiles", sourceFileLocation);
			String[] fileNameSplitArray = file.getName().split("\\.");
			Arrays.deepToString(fileNameSplitArray);
			mapper.writeValue(Paths.get(cweLiveKeepDirectory + fileNameSplitArray[0] + ".meta.json").toFile(), map);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage());
		} catch (IOException e) {
			logger.error("IOException while reading the Json file");
		}

	}

}
