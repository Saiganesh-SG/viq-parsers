package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class Bm {
	
	@JsonProperty("AV")
	private String av;
	
	@JsonProperty("C")
	private String c;
	
	@JsonProperty("PR")
	private String pr;
	
	@JsonProperty("AC")
	private String ac;
	
	@JsonProperty("S")
	private String s;
	
	@JsonProperty("SCORE")
	private String score;
	
	@JsonProperty("UI")
	private String ui;
	
	@JsonProperty("I")
	private String i;
	
	@JsonProperty("A")
	private String a;

}
