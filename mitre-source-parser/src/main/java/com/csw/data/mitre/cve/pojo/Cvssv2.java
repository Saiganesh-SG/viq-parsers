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
	"accessVector",
	"accessComplexity",
	"authentication",
	"confidentialityImpact",
	"integrityImpact",
	"availabilityImpact",
	"score",
	"severity",
    "baseMetricAcInsufInfo",
    "exploitabilityScore",
    "impactScore",
    "userInteraction"

})
@Getter
@Setter
public class Cvssv2 {

	@JsonProperty("version")
	private String version;
	
	@JsonProperty("score")
	private Double score;
	
	@JsonProperty("severity")
	private String severity;
	
	@JsonProperty("vector")
	private String vector;
	
	@JsonProperty("accessVector")
	private String accessVector;
	
	@JsonProperty("accessComplexity")
	private String accessComplexity;
	
	@JsonProperty("authentication")
	private String authentication;
	
	@JsonProperty("confidentialityImpact")
	private String confidentialityImpact;
	
	@JsonProperty("integrityImpact")
	private String integrityImpact;
	
	@JsonProperty("availabilityImpact")
	private String availabilityImpact;
	
    @JsonProperty("baseMetricAcInsufInfo")
    private String baseMetricAcInsufInfo;
    
    @JsonProperty("exploitabilityScore")
    private Float baseMetricV2exploitabilityScore;
    
    @JsonProperty("impactScore")
    private Float baseMetricV2impactScore;
    
    @JsonProperty("userInteraction")
    private String userInteractionRequired;
    
	@Override
	public String toString() {
		return "Cvssv2 [version=" + version + ", score=" + score + ", severity=" + severity + ", vector=" + vector
				+ ", accessVector=" + accessVector + ", accessComplexity=" + accessComplexity + ", authentication="
				+ authentication + ", confidentialityImpact=" + confidentialityImpact + ", integrityImpact="
				+ integrityImpact + ", availabilityImpact=" + availabilityImpact + ", baseMetricAcInsufInfo="
				+ baseMetricAcInsufInfo + ", baseMetricV2exploitabilityScore=" + baseMetricV2exploitabilityScore
				+ ", baseMetricV2impactScore=" + baseMetricV2impactScore + ", userInteractionRequired="
				+ userInteractionRequired + "]";
	}

}
