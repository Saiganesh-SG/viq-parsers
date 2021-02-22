
package com.csw.data.nvd.json.cwe;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "submission",
    "modification",
    "contribution",
    "previousEntryName"
})
public class ContentHistory {

    @JsonProperty("submission")
    private Submission submission;
    @JsonProperty("modification")
    private List<Modification> modification = null;
    @JsonProperty("contribution")
    private List<Contribution> contribution = null;
    @JsonProperty("previousEntryName")
    private List<PreviousEntryName> previousEntryName = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("submission")
    public Submission getSubmission() {
        return submission;
    }

    @JsonProperty("submission")
    public void setSubmission(Submission submission) {
        this.submission = submission;
    }

    @JsonProperty("modification")
    public List<Modification> getModification() {
        return modification;
    }

    @JsonProperty("modification")
    public void setModification(List<Modification> modification) {
        this.modification = modification;
    }

    @JsonProperty("contribution")
    public List<Contribution> getContribution() {
        return contribution;
    }

    @JsonProperty("contribution")
    public void setContribution(List<Contribution> contribution) {
        this.contribution = contribution;
    }

    @JsonProperty("previousEntryName")
    public List<PreviousEntryName> getPreviousEntryName() {
        return previousEntryName;
    }

    @JsonProperty("previousEntryName")
    public void setPreviousEntryName(List<PreviousEntryName> previousEntryName) {
        this.previousEntryName = previousEntryName;
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
