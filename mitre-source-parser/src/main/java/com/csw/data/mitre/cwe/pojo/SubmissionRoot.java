
package com.csw.data.mitre.cwe.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "submissionName",
    "submissionOrganization",
    "submissionDate",
    "submissionComment"
})
@Getter
@Setter
public class SubmissionRoot {

    @JsonProperty("submissionName")
    private String submissionName;
    @JsonProperty("submissionOrganization")
    private String submissionOrganization;
    @JsonProperty("submissionDate")
    private String submissionDate;
    @JsonProperty("submissionComment")
    private String submissionComment;

}
