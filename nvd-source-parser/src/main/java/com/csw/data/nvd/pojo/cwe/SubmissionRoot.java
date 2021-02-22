
package com.csw.data.nvd.pojo.cwe;

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
    "submissionName",
    "submissionOrganization",
    "submissionDate",
    "submissionComment"
})
public class SubmissionRoot {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionName")
    private String submissionName;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionOrganization")
    private String submissionOrganization;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionDate")
    private String submissionDate;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionComment")
    private String submissionComment;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionName")
    public String getSubmissionName() {
        return submissionName;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionName")
    public void setSubmissionName(String submissionName) {
        this.submissionName = submissionName;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionOrganization")
    public String getSubmissionOrganization() {
        return submissionOrganization;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionOrganization")
    public void setSubmissionOrganization(String submissionOrganization) {
        this.submissionOrganization = submissionOrganization;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionDate")
    public String getSubmissionDate() {
        return submissionDate;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionDate")
    public void setSubmissionDate(String submissionDate) {
        this.submissionDate = submissionDate;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionComment")
    public String getSubmissionComment() {
        return submissionComment;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submissionComment")
    public void setSubmissionComment(String submissionComment) {
        this.submissionComment = submissionComment;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(SubmissionRoot.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("submissionName");
        sb.append('=');
        sb.append(((this.submissionName == null)?"<null>":this.submissionName));
        sb.append(',');
        sb.append("submissionOrganization");
        sb.append('=');
        sb.append(((this.submissionOrganization == null)?"<null>":this.submissionOrganization));
        sb.append(',');
        sb.append("submissionDate");
        sb.append('=');
        sb.append(((this.submissionDate == null)?"<null>":this.submissionDate));
        sb.append(',');
        sb.append("submissionComment");
        sb.append('=');
        sb.append(((this.submissionComment == null)?"<null>":this.submissionComment));
        sb.append(',');
        sb.append("additionalProperties");
        sb.append('=');
        sb.append(((this.additionalProperties == null)?"<null>":this.additionalProperties));
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
        result = ((result* 31)+((this.submissionDate == null)? 0 :this.submissionDate.hashCode()));
        result = ((result* 31)+((this.submissionComment == null)? 0 :this.submissionComment.hashCode()));
        result = ((result* 31)+((this.submissionName == null)? 0 :this.submissionName.hashCode()));
        result = ((result* 31)+((this.additionalProperties == null)? 0 :this.additionalProperties.hashCode()));
        result = ((result* 31)+((this.submissionOrganization == null)? 0 :this.submissionOrganization.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof SubmissionRoot) == false) {
            return false;
        }
        SubmissionRoot rhs = ((SubmissionRoot) other);
        return ((((((this.submissionDate == rhs.submissionDate)||((this.submissionDate!= null)&&this.submissionDate.equals(rhs.submissionDate)))&&((this.submissionComment == rhs.submissionComment)||((this.submissionComment!= null)&&this.submissionComment.equals(rhs.submissionComment))))&&((this.submissionName == rhs.submissionName)||((this.submissionName!= null)&&this.submissionName.equals(rhs.submissionName))))&&((this.additionalProperties == rhs.additionalProperties)||((this.additionalProperties!= null)&&this.additionalProperties.equals(rhs.additionalProperties))))&&((this.submissionOrganization == rhs.submissionOrganization)||((this.submissionOrganization!= null)&&this.submissionOrganization.equals(rhs.submissionOrganization))));
    }

}
