package com.csw.data.nvd.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

@Configuration
public class AmazonS3Client {

	@Bean
	public S3Client buildAmazonS3Client() {
		return S3Client.builder().region(Region.US_WEST_2).build();
	}
	
}
