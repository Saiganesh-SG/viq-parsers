package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * CVSS V2.0 score.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cvssV2",
    "severity",
    "exploitabilityScore",
    "impactScore",
    "acInsufInfo",
    "obtainAllPrivilege",
    "obtainUserPrivilege",
    "obtainOtherPrivilege",
    "userInteractionRequired"
})
@Generated("jsonschema2pojo")
public class BaseMetricV2 {

    /**
     * JSON Schema for Common Vulnerability Scoring System version 2.0
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV2")
    private CvssV20 cvssV2;
    @JsonProperty("severity")
    private String severity;
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
    @JsonProperty("acInsufInfo")
    private Boolean acInsufInfo;
    @JsonProperty("obtainAllPrivilege")
    private Boolean obtainAllPrivilege;
    @JsonProperty("obtainUserPrivilege")
    private Boolean obtainUserPrivilege;
    @JsonProperty("obtainOtherPrivilege")
    private Boolean obtainOtherPrivilege;
    @JsonProperty("userInteractionRequired")
    private Boolean userInteractionRequired;

    /**
     * JSON Schema for Common Vulnerability Scoring System version 2.0
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV2")
    public CvssV20 getCvssV2() {
        return cvssV2;
    }

    /**
     * JSON Schema for Common Vulnerability Scoring System version 2.0
     * <p>
     * 
     * 
     */
    @JsonProperty("cvssV2")
    public void setCvssV2(CvssV20 cvssV2) {
        this.cvssV2 = cvssV2;
    }

    @JsonProperty("severity")
    public String getSeverity() {
        return severity;
    }

    @JsonProperty("severity")
    public void setSeverity(String severity) {
        this.severity = severity;
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

    @JsonProperty("acInsufInfo")
    public Boolean getAcInsufInfo() {
        return acInsufInfo;
    }

    @JsonProperty("acInsufInfo")
    public void setAcInsufInfo(Boolean acInsufInfo) {
        this.acInsufInfo = acInsufInfo;
    }

    @JsonProperty("obtainAllPrivilege")
    public Boolean getObtainAllPrivilege() {
        return obtainAllPrivilege;
    }

    @JsonProperty("obtainAllPrivilege")
    public void setObtainAllPrivilege(Boolean obtainAllPrivilege) {
        this.obtainAllPrivilege = obtainAllPrivilege;
    }

    @JsonProperty("obtainUserPrivilege")
    public Boolean getObtainUserPrivilege() {
        return obtainUserPrivilege;
    }

    @JsonProperty("obtainUserPrivilege")
    public void setObtainUserPrivilege(Boolean obtainUserPrivilege) {
        this.obtainUserPrivilege = obtainUserPrivilege;
    }

    @JsonProperty("obtainOtherPrivilege")
    public Boolean getObtainOtherPrivilege() {
        return obtainOtherPrivilege;
    }

    @JsonProperty("obtainOtherPrivilege")
    public void setObtainOtherPrivilege(Boolean obtainOtherPrivilege) {
        this.obtainOtherPrivilege = obtainOtherPrivilege;
    }

    @JsonProperty("userInteractionRequired")
    public Boolean getUserInteractionRequired() {
        return userInteractionRequired;
    }

    @JsonProperty("userInteractionRequired")
    public void setUserInteractionRequired(Boolean userInteractionRequired) {
        this.userInteractionRequired = userInteractionRequired;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(BaseMetricV2 .class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cvssV2");
        sb.append('=');
        sb.append(((this.cvssV2 == null)?"<null>":this.cvssV2));
        sb.append(',');
        sb.append("severity");
        sb.append('=');
        sb.append(((this.severity == null)?"<null>":this.severity));
        sb.append(',');
        sb.append("exploitabilityScore");
        sb.append('=');
        sb.append(((this.exploitabilityScore == null)?"<null>":this.exploitabilityScore));
        sb.append(',');
        sb.append("impactScore");
        sb.append('=');
        sb.append(((this.impactScore == null)?"<null>":this.impactScore));
        sb.append(',');
        sb.append("acInsufInfo");
        sb.append('=');
        sb.append(((this.acInsufInfo == null)?"<null>":this.acInsufInfo));
        sb.append(',');
        sb.append("obtainAllPrivilege");
        sb.append('=');
        sb.append(((this.obtainAllPrivilege == null)?"<null>":this.obtainAllPrivilege));
        sb.append(',');
        sb.append("obtainUserPrivilege");
        sb.append('=');
        sb.append(((this.obtainUserPrivilege == null)?"<null>":this.obtainUserPrivilege));
        sb.append(',');
        sb.append("obtainOtherPrivilege");
        sb.append('=');
        sb.append(((this.obtainOtherPrivilege == null)?"<null>":this.obtainOtherPrivilege));
        sb.append(',');
        sb.append("userInteractionRequired");
        sb.append('=');
        sb.append(((this.userInteractionRequired == null)?"<null>":this.userInteractionRequired));
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
        result = ((result* 31)+((this.severity == null)? 0 :this.severity.hashCode()));
        result = ((result* 31)+((this.exploitabilityScore == null)? 0 :this.exploitabilityScore.hashCode()));
        result = ((result* 31)+((this.obtainAllPrivilege == null)? 0 :this.obtainAllPrivilege.hashCode()));
        result = ((result* 31)+((this.userInteractionRequired == null)? 0 :this.userInteractionRequired.hashCode()));
        result = ((result* 31)+((this.obtainOtherPrivilege == null)? 0 :this.obtainOtherPrivilege.hashCode()));
        result = ((result* 31)+((this.cvssV2 == null)? 0 :this.cvssV2 .hashCode()));
        result = ((result* 31)+((this.impactScore == null)? 0 :this.impactScore.hashCode()));
        result = ((result* 31)+((this.acInsufInfo == null)? 0 :this.acInsufInfo.hashCode()));
        result = ((result* 31)+((this.obtainUserPrivilege == null)? 0 :this.obtainUserPrivilege.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof BaseMetricV2) == false) {
            return false;
        }
        BaseMetricV2 rhs = ((BaseMetricV2) other);
        return ((((((((((this.severity == rhs.severity)||((this.severity!= null)&&this.severity.equals(rhs.severity)))&&((this.exploitabilityScore == rhs.exploitabilityScore)||((this.exploitabilityScore!= null)&&this.exploitabilityScore.equals(rhs.exploitabilityScore))))&&((this.obtainAllPrivilege == rhs.obtainAllPrivilege)||((this.obtainAllPrivilege!= null)&&this.obtainAllPrivilege.equals(rhs.obtainAllPrivilege))))&&((this.userInteractionRequired == rhs.userInteractionRequired)||((this.userInteractionRequired!= null)&&this.userInteractionRequired.equals(rhs.userInteractionRequired))))&&((this.obtainOtherPrivilege == rhs.obtainOtherPrivilege)||((this.obtainOtherPrivilege!= null)&&this.obtainOtherPrivilege.equals(rhs.obtainOtherPrivilege))))&&((this.cvssV2 == rhs.cvssV2)||((this.cvssV2 != null)&&this.cvssV2 .equals(rhs.cvssV2))))&&((this.impactScore == rhs.impactScore)||((this.impactScore!= null)&&this.impactScore.equals(rhs.impactScore))))&&((this.acInsufInfo == rhs.acInsufInfo)||((this.acInsufInfo!= null)&&this.acInsufInfo.equals(rhs.acInsufInfo))))&&((this.obtainUserPrivilege == rhs.obtainUserPrivilege)||((this.obtainUserPrivilege!= null)&&this.obtainUserPrivilege.equals(rhs.obtainUserPrivilege))));
    }

}
