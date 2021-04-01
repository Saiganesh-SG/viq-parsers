
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
    "cvssV2version",
    "cvssV2vectorString",
    "cvssV2accessVector",
    "cvssV2accessComplexity",
    "cvssV2authentication",
    "cvssV2confidentialityImpact",
    "cvssv2integrityImpact",
    "cvssV2availabilityImpact",
    "cvssV2baseScore",
    "baseMetricV2severity",
    "baseMetricAcInsufInfo",
    "baseMetricV2exploitabilityScore",
    "baseMetricV2impactScore"
})
public class Cvssv2 {

    @JsonProperty("cvssV2version")
    private String cvssV2version;
    @JsonProperty("cvssV2vectorString")
    private String cvssV2vectorString;
    @JsonProperty("cvssV2accessVector")
    private String cvssV2accessVector;
    @JsonProperty("cvssV2accessComplexity")
    private String cvssV2accessComplexity;
    @JsonProperty("cvssV2authentication")
    private String cvssV2authentication;
    @JsonProperty("cvssV2confidentialityImpact")
    private String cvssV2confidentialityImpact;
    @JsonProperty("cvssv2integrityImpact")
    private String cvssv2integrityImpact;
    @JsonProperty("cvssV2availabilityImpact")
    private String cvssV2availabilityImpact;
    @JsonProperty("cvssV2baseScore")
    private String cvssV2baseScore;
    @JsonProperty("baseMetricV2severity")
    private String baseMetricV2severity;
    @JsonProperty("baseMetricAcInsufInfo")
    private String baseMetricAcInsufInfo;
    @JsonProperty("baseMetricV2exploitabilityScore")
    private String baseMetricV2exploitabilityScore;
    @JsonProperty("baseMetricV2impactScore")
    private String baseMetricV2impactScore;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("cvssV2version")
    public String getCvssV2version() {
        return cvssV2version;
    }

    @JsonProperty("cvssV2version")
    public void setCvssV2version(String cvssV2version) {
        this.cvssV2version = cvssV2version;
    }

    @JsonProperty("cvssV2vectorString")
    public String getCvssV2vectorString() {
        return cvssV2vectorString;
    }

    @JsonProperty("cvssV2vectorString")
    public void setCvssV2vectorString(String cvssV2vectorString) {
        this.cvssV2vectorString = cvssV2vectorString;
    }

    @JsonProperty("cvssV2accessVector")
    public String getCvssV2accessVector() {
        return cvssV2accessVector;
    }

    @JsonProperty("cvssV2accessVector")
    public void setCvssV2accessVector(String cvssV2accessVector) {
        this.cvssV2accessVector = cvssV2accessVector;
    }

    @JsonProperty("cvssV2accessComplexity")
    public String getCvssV2accessComplexity() {
        return cvssV2accessComplexity;
    }

    @JsonProperty("cvssV2accessComplexity")
    public void setCvssV2accessComplexity(String cvssV2accessComplexity) {
        this.cvssV2accessComplexity = cvssV2accessComplexity;
    }

    @JsonProperty("cvssV2authentication")
    public String getCvssV2authentication() {
        return cvssV2authentication;
    }

    @JsonProperty("cvssV2authentication")
    public void setCvssV2authentication(String cvssV2authentication) {
        this.cvssV2authentication = cvssV2authentication;
    }

    @JsonProperty("cvssV2confidentialityImpact")
    public String getCvssV2confidentialityImpact() {
        return cvssV2confidentialityImpact;
    }

    @JsonProperty("cvssV2confidentialityImpact")
    public void setCvssV2confidentialityImpact(String cvssV2confidentialityImpact) {
        this.cvssV2confidentialityImpact = cvssV2confidentialityImpact;
    }

    @JsonProperty("cvssv2integrityImpact")
    public String getCvssv2integrityImpact() {
        return cvssv2integrityImpact;
    }

    @JsonProperty("cvssv2integrityImpact")
    public void setCvssv2integrityImpact(String cvssv2integrityImpact) {
        this.cvssv2integrityImpact = cvssv2integrityImpact;
    }

    @JsonProperty("cvssV2availabilityImpact")
    public String getCvssV2availabilityImpact() {
        return cvssV2availabilityImpact;
    }

    @JsonProperty("cvssV2availabilityImpact")
    public void setCvssV2availabilityImpact(String cvssV2availabilityImpact) {
        this.cvssV2availabilityImpact = cvssV2availabilityImpact;
    }

    @JsonProperty("cvssV2baseScore")
    public String getCvssV2baseScore() {
        return cvssV2baseScore;
    }

    @JsonProperty("cvssV2baseScore")
    public void setCvssV2baseScore(String cvssV2baseScore) {
        this.cvssV2baseScore = cvssV2baseScore;
    }

    @JsonProperty("baseMetricV2severity")
    public String getBaseMetricV2severity() {
        return baseMetricV2severity;
    }

    @JsonProperty("baseMetricV2severity")
    public void setBaseMetricV2severity(String baseMetricV2severity) {
        this.baseMetricV2severity = baseMetricV2severity;
    }

    @JsonProperty("baseMetricAcInsufInfo")
    public String getBaseMetricAcInsufInfo() {
        return baseMetricAcInsufInfo;
    }

    @JsonProperty("baseMetricAcInsufInfo")
    public void setBaseMetricAcInsufInfo(String baseMetricAcInsufInfo) {
        this.baseMetricAcInsufInfo = baseMetricAcInsufInfo;
    }

    @JsonProperty("baseMetricV2exploitabilityScore")
    public String getBaseMetricV2exploitabilityScore() {
        return baseMetricV2exploitabilityScore;
    }

    @JsonProperty("baseMetricV2exploitabilityScore")
    public void setBaseMetricV2exploitabilityScore(String baseMetricV2exploitabilityScore) {
        this.baseMetricV2exploitabilityScore = baseMetricV2exploitabilityScore;
    }

    @JsonProperty("baseMetricV2impactScore")
    public String getBaseMetricV2impactScore() {
        return baseMetricV2impactScore;
    }

    @JsonProperty("baseMetricV2impactScore")
    public void setBaseMetricV2impactScore(String baseMetricV2impactScore) {
        this.baseMetricV2impactScore = baseMetricV2impactScore;
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
