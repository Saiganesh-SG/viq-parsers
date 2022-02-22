package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class Cvssv3Source {
	
	@JsonProperty("TM")
	private Tm tm;
	
	@JsonProperty("BM")
	private Bm bm;
	
	@JsonProperty("EM")
	private Em em;
	
	@JsonProperty("AV")
	private String Av;
	
	@JsonProperty("AC")
	private String Ac;
	
	@JsonProperty("PR")
	private String Pr;
	
	@JsonProperty("UI")
	private String Ui;

	@JsonProperty("S")
	private String S;
	
	@JsonProperty("C")
	private String C;
	
	@JsonProperty("I")
	private String I;
	
	@JsonProperty("A")
	private String A;
	
	@JsonProperty("SCORE")
	private String Score;
}
