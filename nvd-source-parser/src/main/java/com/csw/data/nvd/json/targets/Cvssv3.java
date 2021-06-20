
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
    "vectorString",
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
    "impactScore"
})
@Getter
@Setter
public class Cvssv3 {

    @JsonProperty("version")
    private String cvssV3version;
    @JsonProperty("vectorString")
    private String cvssV3vectorString;
    @JsonProperty("attackVector")
    private String cvssV3attackVector;
    @JsonProperty("attackComplexity")
    private String cvssV3attackComplexity;
    @JsonProperty("privilegesRequired")
    private String cvssV3privilegesRequired;
    @JsonProperty("userInteraction")
    private String cvssV3userInteraction;
    @JsonProperty("scope")
    private String cvssV3scope;
    @JsonProperty("confidentialityImpact")
    private String cvssV3confidentialityImpact;
    @JsonProperty("integrityImpact")
    private String cvssV3integrityImpact;
    @JsonProperty("availabilityImpact")
    private String cvssV3availabilityImpact;
    @JsonProperty("score")
    private String cvssV3baseScore;
    @JsonProperty("severity")
    private String cvssV3baseSeverity;
    @JsonProperty("exploitabilityScore")
    private String baseMetricV3exploitabilityScore;
    @JsonProperty("impactScore")
    private String baseMetricV3impactScore;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<>();
}
