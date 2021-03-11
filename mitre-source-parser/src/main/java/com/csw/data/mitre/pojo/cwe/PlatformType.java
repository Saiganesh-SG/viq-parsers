package com.csw.data.mitre.pojo.cwe;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PlatformType {
	
	private String name;
	
	@JsonProperty("class")
    private String clazz;
    
    private String prevalence;

}
