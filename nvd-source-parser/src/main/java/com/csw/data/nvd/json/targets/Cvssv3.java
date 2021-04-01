
package com.csw.data.nvd.json.targets;

import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cvssV3version",
    "cvssV3vectorString",
    "cvssV3attackVector",
    "cvssV3attackComplexity",
    "cvssV3privilegesRequired",
    "cvssV3userInteraction",
    "cvssV3scope",
    "cvssV3confidentialityImpact",
    "cvssV3integrityImpact",
    "cvssV3availabilityImpact",
    "cvssV3baseScore",
    "cvssV3baseSeverity",
    "baseMetricV3exploitabilityScore",
    "baseMetricV3impactScore"
})
public class Cvssv3 {

    @JsonProperty("cvssV3version")
    private String cvssV3version;
    @JsonProperty("cvssV3vectorString")
    private String cvssV3vectorString;
    @JsonProperty("cvssV3attackVector")
    private String cvssV3attackVector;
    @JsonProperty("cvssV3attackComplexity")
    private String cvssV3attackComplexity;
    @JsonProperty("cvssV3privilegesRequired")
    private String cvssV3privilegesRequired;
    @JsonProperty("cvssV3userInteraction")
    private String cvssV3userInteraction;
    @JsonProperty("cvssV3scope")
    private String cvssV3scope;
    @JsonProperty("cvssV3confidentialityImpact")
    private String cvssV3confidentialityImpact;
    @JsonProperty("cvssV3integrityImpact")
    private String cvssV3integrityImpact;
    @JsonProperty("cvssV3availabilityImpact")
    private String cvssV3availabilityImpact;
    @JsonProperty("cvssV3baseScore")
    private String cvssV3baseScore;
    @JsonProperty("cvssV3baseSeverity")
    private String cvssV3baseSeverity;
    @JsonProperty("baseMetricV3exploitabilityScore")
    private String baseMetricV3exploitabilityScore;
    @JsonProperty("baseMetricV3impactScore")
    private String baseMetricV3impactScore;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("cvssV3version")
    public String getCvssV3version() {
        return cvssV3version;
    }

    @JsonProperty("cvssV3version")
    public void setCvssV3version(String cvssV3version) {
        this.cvssV3version = cvssV3version;
    }

    @JsonProperty("cvssV3vectorString")
    public String getCvssV3vectorString() {
        return cvssV3vectorString;
    }

    @JsonProperty("cvssV3vectorString")
    public void setCvssV3vectorString(String cvssV3vectorString) {
        this.cvssV3vectorString = cvssV3vectorString;
    }

    @JsonProperty("cvssV3attackVector")
    public String getCvssV3attackVector() {
        return cvssV3attackVector;
    }

    @JsonProperty("cvssV3attackVector")
    public void setCvssV3attackVector(String cvssV3attackVector) {
        this.cvssV3attackVector = cvssV3attackVector;
    }

    @JsonProperty("cvssV3attackComplexity")
    public String getCvssV3attackComplexity() {
        return cvssV3attackComplexity;
    }

    @JsonProperty("cvssV3attackComplexity")
    public void setCvssV3attackComplexity(String cvssV3attackComplexity) {
        this.cvssV3attackComplexity = cvssV3attackComplexity;
    }

    @JsonProperty("cvssV3privilegesRequired")
    public String getCvssV3privilegesRequired() {
        return cvssV3privilegesRequired;
    }

    @JsonProperty("cvssV3privilegesRequired")
    public void setCvssV3privilegesRequired(String cvssV3privilegesRequired) {
        this.cvssV3privilegesRequired = cvssV3privilegesRequired;
    }

    @JsonProperty("cvssV3userInteraction")
    public String getCvssV3userInteraction() {
        return cvssV3userInteraction;
    }

    @JsonProperty("cvssV3userInteraction")
    public void setCvssV3userInteraction(String cvssV3userInteraction) {
        this.cvssV3userInteraction = cvssV3userInteraction;
    }

    @JsonProperty("cvssV3scope")
    public String getCvssV3scope() {
        return cvssV3scope;
    }

    @JsonProperty("cvssV3scope")
    public void setCvssV3scope(String cvssV3scope) {
        this.cvssV3scope = cvssV3scope;
    }

    @JsonProperty("cvssV3confidentialityImpact")
    public String getCvssV3confidentialityImpact() {
        return cvssV3confidentialityImpact;
    }

    @JsonProperty("cvssV3confidentialityImpact")
    public void setCvssV3confidentialityImpact(String cvssV3confidentialityImpact) {
        this.cvssV3confidentialityImpact = cvssV3confidentialityImpact;
    }

    @JsonProperty("cvssV3integrityImpact")
    public String getCvssV3integrityImpact() {
        return cvssV3integrityImpact;
    }

    @JsonProperty("cvssV3integrityImpact")
    public void setCvssV3integrityImpact(String cvssV3integrityImpact) {
        this.cvssV3integrityImpact = cvssV3integrityImpact;
    }

    @JsonProperty("cvssV3availabilityImpact")
    public String getCvssV3availabilityImpact() {
        return cvssV3availabilityImpact;
    }

    @JsonProperty("cvssV3availabilityImpact")
    public void setCvssV3availabilityImpact(String cvssV3availabilityImpact) {
        this.cvssV3availabilityImpact = cvssV3availabilityImpact;
    }

    @JsonProperty("cvssV3baseScore")
    public String getCvssV3baseScore() {
        return cvssV3baseScore;
    }

    @JsonProperty("cvssV3baseScore")
    public void setCvssV3baseScore(String cvssV3baseScore) {
        this.cvssV3baseScore = cvssV3baseScore;
    }

    @JsonProperty("cvssV3baseSeverity")
    public String getCvssV3baseSeverity() {
        return cvssV3baseSeverity;
    }

    @JsonProperty("cvssV3baseSeverity")
    public void setCvssV3baseSeverity(String cvssV3baseSeverity) {
        this.cvssV3baseSeverity = cvssV3baseSeverity;
    }

    @JsonProperty("baseMetricV3exploitabilityScore")
    public String getBaseMetricV3exploitabilityScore() {
        return baseMetricV3exploitabilityScore;
    }

    @JsonProperty("baseMetricV3exploitabilityScore")
    public void setBaseMetricV3exploitabilityScore(String baseMetricV3exploitabilityScore) {
        this.baseMetricV3exploitabilityScore = baseMetricV3exploitabilityScore;
    }

    @JsonProperty("baseMetricV3impactScore")
    public String getBaseMetricV3impactScore() {
        return baseMetricV3impactScore;
    }

    @JsonProperty("baseMetricV3impactScore")
    public void setBaseMetricV3impactScore(String baseMetricV3impactScore) {
        this.baseMetricV3impactScore = baseMetricV3impactScore;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
