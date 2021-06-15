
package com.csw.data.mitre.cwe.pojo;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "submission",
    "modification",
    "contribution",
    "previousEntryName"
})
@Getter
@Setter
public class ContentHistoryRoot {

    @JsonProperty("submission")
    private SubmissionRoot submission;
    @JsonProperty("modification")
    private List<ModificationType> modification = new ArrayList<>();
    @JsonProperty("contribution")
    private List<ContributionType> contribution = new ArrayList<>();
    @JsonProperty("previousEntryName")
    private List<PreviousEntryNameType> previousEntryName = new ArrayList<>();

}
