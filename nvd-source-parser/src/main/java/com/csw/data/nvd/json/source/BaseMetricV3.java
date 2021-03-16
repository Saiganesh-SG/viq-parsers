package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * CVSS V3.x score.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cvssV3",
    "exploitabilityScore",
    "impactScore"
})
@Generated("jsonschema2pojo")
public class BaseMetricV3 {

    /**
     * JSON Schema for Common Vulnerability Scoring System version 3.x
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV3")
    private CvssV3X cvssV3;
    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("exploitabilityScore")
    @JsonPropertyDescription("CVSS subscore.")
    private Double exploitabilityScore;
    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("impactScore")
    @JsonPropertyDescription("CVSS subscore.")
    private Double impactScore;

    /**
     * JSON Schema for Common Vulnerability Scoring System version 3.x
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV3")
    public CvssV3X getCvssV3() {
        return cvssV3;
    }

    /**
     * JSON Schema for Common Vulnerability Scoring System version 3.x
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV3")
    public void setCvssV3(CvssV3X cvssV3) {
        this.cvssV3 = cvssV3;
    }

    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("exploitabilityScore")
    public Double getExploitabilityScore() {
        return exploitabilityScore;
    }

    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("exploitabilityScore")
    public void setExploitabilityScore(Double exploitabilityScore) {
        this.exploitabilityScore = exploitabilityScore;
    }

    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("impactScore")
    public Double getImpactScore() {
        return impactScore;
    }

    /**
     * CVSS subscore.
     * 
     */
    @JsonProperty("impactScore")
    public void setImpactScore(Double impactScore) {
        this.impactScore = impactScore;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(BaseMetricV3 .class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cvssV3");
        sb.append('=');
        sb.append(((this.cvssV3 == null)?"<null>":this.cvssV3));
        sb.append(',');
        sb.append("exploitabilityScore");
        sb.append('=');
        sb.append(((this.exploitabilityScore == null)?"<null>":this.exploitabilityScore));
        sb.append(',');
        sb.append("impactScore");
        sb.append('=');
        sb.append(((this.impactScore == null)?"<null>":this.impactScore));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.exploitabilityScore == null)? 0 :this.exploitabilityScore.hashCode()));
        result = ((result* 31)+((this.cvssV3 == null)? 0 :this.cvssV3 .hashCode()));
        result = ((result* 31)+((this.impactScore == null)? 0 :this.impactScore.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof BaseMetricV3) == false) {
            return false;
        }
        BaseMetricV3 rhs = ((BaseMetricV3) other);
        return ((((this.exploitabilityScore == rhs.exploitabilityScore)||((this.exploitabilityScore!= null)&&this.exploitabilityScore.equals(rhs.exploitabilityScore)))&&((this.cvssV3 == rhs.cvssV3)||((this.cvssV3 != null)&&this.cvssV3 .equals(rhs.cvssV3))))&&((this.impactScore == rhs.impactScore)||((this.impactScore!= null)&&this.impactScore.equals(rhs.impactScore))));
    }

}
