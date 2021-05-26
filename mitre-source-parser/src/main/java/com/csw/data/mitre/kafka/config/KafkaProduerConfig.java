package com.csw.data.mitre.kafka.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

/**
 * The Class KafkaProduerConfig.
 */
@Configuration
public class KafkaProduerConfig {
	
	/** The producer factory. */
	@Autowired
	private ProducerFactory<Integer, String> producerFactory;
	
	/**
	 * Kafka template.
	 *
	 * @return the kafka template
	 */
	@Bean
    public KafkaTemplate<String, String> kafkaTemplate(){
        return new KafkaTemplate<>(new DefaultKafkaProducerFactory<>(producerConfig()));
    }

	/**
	 * Producer config.
	 *
	 * @return the map
	 */
	public Map<String, Object> producerConfig(){
		Map<String, Object> kafkaAutoConfig = ((DefaultKafkaProducerFactory<Integer, String>) producerFactory).getConfigurationProperties();
		Map<String, Object> producerConfig = new HashMap<>();
		producerConfig.putAll(kafkaAutoConfig);
		return producerConfig;
	}
	
}
