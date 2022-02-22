package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class CvssArray {
	
	@JsonProperty("attackComplexity")
	private String attackComplexity;
	
	@JsonProperty("attackVector")
	private String attackVector;
	
	@JsonProperty("availabilityImpact")
	private String availabilityImpact;
	
	@JsonProperty("baseScore")
	private Double baseScore;
	
	@JsonProperty("baseScoreString")
	private String baseScoreString;
	
	@JsonProperty("baseSeverity")
	private String baseSeverity;
	
	@JsonProperty("confidentialityImpact")
	private String confidentialityImpact;
	
	@JsonProperty("integrityImpact")
	private String integrityImpact;
	
	@JsonProperty("privilegesRequired")
	private String privilegesRequired;
	
	@JsonProperty("scope")
	private String scope;
	
	@JsonProperty("userInteraction")
	private String userInteraction;
	
	@JsonProperty("vectorString")
	private String vectorString;
	
	@JsonProperty("version")
	private String version;

}
