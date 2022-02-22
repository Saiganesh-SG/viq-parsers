package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.ALWAYS)
@JsonPropertyOrder({
	"version",
	"vector",
	"attackVector",
	"attackComplexity",
	"privilegesRequired",
	"userInteraction",
	"scope",
	"confidentialityImpact",
	"integrityImpact",
	"availabilityImpact",
	"score",
	"severity",    
	"exploitabilityScore",
    "impactScore",
	"temporalMetrics"
})
@Getter
@Setter
public class Cvssv3 {
	
	@JsonProperty("version")
	private String version;
	
	@JsonProperty("score")
	private Double score;
	
	@JsonProperty("severity")
	private String severity;
	
	@JsonProperty("vector")
	private String vector;
	
	@JsonProperty("attackVector")
	private String attackVector;
	
	@JsonProperty("attackComplexity")
	private String attackComplexity;
	
	@JsonProperty("privilegesRequired")
	private String privilegesRequired;
	
	@JsonProperty("userInteraction")
	private String userInteraction;
	
	@JsonProperty("scope")
	private String scope;
	
	@JsonProperty("confidentialityImpact")
	private String confidentialityImpact;
	
	@JsonProperty("integrityImpact")
	private String integrityImpact;
	
	@JsonProperty("availabilityImpact")
	private String availabilityImpact;
	
    @JsonProperty("exploitabilityScore")
    private Float baseMetricV3exploitabilityScore;
    
    @JsonProperty("impactScore")
    private Float baseMetricV3impactScore;
	
	@JsonProperty("temporalMetrics")
	private TemporalMetrics temporalMetrics;

}
