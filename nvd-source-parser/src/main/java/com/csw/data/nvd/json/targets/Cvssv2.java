
package com.csw.data.nvd.json.targets;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
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
    private String cvssV2version;
    @JsonProperty("vector")
    private String cvssV2vectorString;
    @JsonProperty("accessVector")
    private String cvssV2accessVector;
    @JsonProperty("accessComplexity")
    private String cvssV2accessComplexity;
    @JsonProperty("authentication")
    private String cvssV2authentication;
    @JsonProperty("confidentialityImpact")
    private String cvssV2confidentialityImpact;
    @JsonProperty("integrityImpact")
    private String cvssv2integrityImpact;
    @JsonProperty("availabilityImpact")
    private String cvssV2availabilityImpact;
    @JsonProperty("score")
    private float cvssV2baseScore;
    @JsonProperty("severity")
    private String baseMetricV2severity;
    @JsonProperty("baseMetricAcInsufInfo")
    private String baseMetricAcInsufInfo;
    @JsonProperty("exploitabilityScore")
    private float baseMetricV2exploitabilityScore;
    @JsonProperty("impactScore")
    private float baseMetricV2impactScore;
    @JsonProperty("userInteraction")
    private String userInteractionRequired;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<>();
    
}
