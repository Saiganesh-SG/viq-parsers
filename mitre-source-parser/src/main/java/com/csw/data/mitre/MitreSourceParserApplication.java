package com.csw.data.mitre;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.csw.data.mitre.parser.MitreTopicParser;

@SpringBootApplication
public class MitreSourceParserApplication implements CommandLineRunner {

	private static final Logger LOGGER = LoggerFactory.getLogger(MitreSourceParserApplication.class);

	@Autowired
	private MitreTopicParser mitreTopicParser;

	@Override
	public void run(String... args) throws Exception {
		LOGGER.info("started the Mitre parsing...");
		String topicType = System.getProperty("topic");
		if (null != topicType) {
			mitreTopicParser.parseTopicType(topicType);
		} else {
			LOGGER.error("Arguments are not present. Please pass the required arguments");
		}
		LOGGER.info("Completed the Mitre parsing...");
	}

	public static void main(String[] args) {
		SpringApplication.run(MitreSourceParserApplication.class, args);
	}

}
