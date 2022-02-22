package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class ReferenceData {
	
	@JsonProperty("name")
	private String name;
	
	@JsonProperty("refsource")
	private String refsource;
	
	@JsonProperty("url")
	private String url;
	
	@JsonProperty("title")
	private String title;

}
