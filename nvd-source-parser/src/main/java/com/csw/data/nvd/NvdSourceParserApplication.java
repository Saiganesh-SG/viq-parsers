package com.csw.data.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.csw.data.nvd.parser.NvdTopicParser;

@SpringBootApplication
public class NvdSourceParserApplication implements CommandLineRunner {

	private static final Logger LOGGER = LoggerFactory.getLogger(NvdSourceParserApplication.class);

	@Autowired
	private NvdTopicParser nvdTopicParser;
	
	public static void main(String[] args) {
		SpringApplication.run(NvdSourceParserApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		LOGGER.info("started the nvd parsing...");
		String parseType = System.getProperty("topic");
		parseType = "cve";
		if (parseType != null) {
			nvdTopicParser.run(parseType);
		} else {
			LOGGER.error("Arguments are not present. Please pass the required arguments");
		}
		LOGGER.info("Completed the nvd parsing...");
	}
}
