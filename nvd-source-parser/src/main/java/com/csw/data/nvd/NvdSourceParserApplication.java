package com.csw.data.nvd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.csw.data.nvd.parser.NvdSourceParser;

@SpringBootApplication
public class NvdSourceParserApplication implements CommandLineRunner {

	private static final Logger logger = LoggerFactory.getLogger(NvdSourceParserApplication.class);

	@Autowired
	private NvdSourceParser nvdSourceParser;

	public static void main(String[] args) {
		SpringApplication.run(NvdSourceParserApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		logger.info("started the nvd parsing...");
		// TODO change the below code to fetch the parse type from environment
		String parseType = "CWE";
		Boolean isLatest = true;
		isLatest = (isLatest == null) ? true : isLatest;
		if (parseType != null) {
			nvdSourceParser.run(parseType, isLatest);
		} else {
			logger.error("Arguments are not present. Please pass the required arguments");
		}
	}

}
