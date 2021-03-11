package com.csw.data.mitre;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.csw.data.mitre.parser.WeaknessParser;

@SpringBootApplication
public class MitreSourceParserApplication implements CommandLineRunner {

	private static final Logger LOGGER = LoggerFactory.getLogger(MitreSourceParserApplication.class);

	@Autowired
	private WeaknessParser weaknessParser;

	public static void main(String[] args) {
		SpringApplication.run(MitreSourceParserApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		LOGGER.info("started extracting CWE from mitre...");
		weaknessParser.extractWeaknessFile();
	}

}
