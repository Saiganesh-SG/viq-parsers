
package com.csw.data.nvd.json.cwe;

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
public class Submission {

    @JsonProperty("submissionName")
    private String submissionName;
    @JsonProperty("submissionOrganization")
    private String submissionOrganization;
    @JsonProperty("submissionDate")
    private String submissionDate;
    @JsonProperty("submissionComment")
    private String submissionComment;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("submissionName")
    public String getSubmissionName() {
        return submissionName;
    }

    @JsonProperty("submissionName")
    public void setSubmissionName(String submissionName) {
        this.submissionName = submissionName;
    }

    @JsonProperty("submissionOrganization")
    public String getSubmissionOrganization() {
        return submissionOrganization;
    }

    @JsonProperty("submissionOrganization")
    public void setSubmissionOrganization(String submissionOrganization) {
        this.submissionOrganization = submissionOrganization;
    }

    @JsonProperty("submissionDate")
    public String getSubmissionDate() {
        return submissionDate;
    }

    @JsonProperty("submissionDate")
    public void setSubmissionDate(String submissionDate) {
        this.submissionDate = submissionDate;
    }

    @JsonProperty("submissionComment")
    public String getSubmissionComment() {
        return submissionComment;
    }

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

}
