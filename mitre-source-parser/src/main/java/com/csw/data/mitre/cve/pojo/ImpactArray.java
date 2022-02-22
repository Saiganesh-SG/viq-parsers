package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class ImpactArray {
	
	@JsonProperty("lang")
	private String lang;
	
	@JsonProperty("url")
	private String url;
	
	@JsonProperty("value")
	private String value;
	
	@JsonProperty("other")
	private String other;

}
