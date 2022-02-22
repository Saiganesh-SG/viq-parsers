package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.ALWAYS)
@JsonPropertyOrder({
	"exploitCodeMaturity",
	"remediationLevel",
	"reportConfidence",
	"vector"
})
@Getter
@Setter
public class TemporalMetrics {
	
	@JsonProperty("reportConfidence")
	private String reportConfidence;
	
	@JsonProperty("exploitCodeMaturity")
	private String exploitCodeMaturity;
	
	@JsonProperty("remediationLevel")
	private String remediationLevel;
	
	@JsonProperty("vector")
	private String vector;

}
