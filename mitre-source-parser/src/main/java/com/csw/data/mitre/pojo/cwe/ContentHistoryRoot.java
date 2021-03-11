
package com.csw.data.mitre.pojo.cwe;

import java.util.ArrayList;
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
public class ContentHistoryRoot {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submission")
    private SubmissionRoot submission;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("modification")
    private List<ModificationType> modification = new ArrayList<>();
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("contribution")
    private List<ContributionType> contribution = new ArrayList<>();
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("previousEntryName")
    private List<PreviousEntryNameType> previousEntryName = new ArrayList<>();
    
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submission")
    public SubmissionRoot getSubmission() {
        return submission;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("submission")
    public void setSubmission(SubmissionRoot submission) {
        this.submission = submission;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("modification")
    public List<ModificationType> getModification() {
        return modification;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("modification")
    public void setModification(List<ModificationType> modification) {
        this.modification = modification;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("contribution")
    public List<ContributionType> getContribution() {
        return contribution;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("contribution")
    public void setContribution(List<ContributionType> contribution) {
        this.contribution = contribution;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("previousEntryName")
    public List<PreviousEntryNameType> getPreviousEntryName() {
        return previousEntryName;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("previousEntryName")
    public void setPreviousEntryName(List<PreviousEntryNameType> previousEntryName) {
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(ContentHistoryRoot.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("submission");
        sb.append('=');
        sb.append(((this.submission == null)?"<null>":this.submission));
        sb.append(',');
        sb.append("modification");
        sb.append('=');
        sb.append(((this.modification == null)?"<null>":this.modification));
        sb.append(',');
        sb.append("contribution");
        sb.append('=');
        sb.append(((this.contribution == null)?"<null>":this.contribution));
        sb.append(',');
        sb.append("previousEntryName");
        sb.append('=');
        sb.append(((this.previousEntryName == null)?"<null>":this.previousEntryName));
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
        result = ((result* 31)+((this.previousEntryName == null)? 0 :this.previousEntryName.hashCode()));
        result = ((result* 31)+((this.submission == null)? 0 :this.submission.hashCode()));
        result = ((result* 31)+((this.contribution == null)? 0 :this.contribution.hashCode()));
        result = ((result* 31)+((this.additionalProperties == null)? 0 :this.additionalProperties.hashCode()));
        result = ((result* 31)+((this.modification == null)? 0 :this.modification.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof ContentHistoryRoot) == false) {
            return false;
        }
        ContentHistoryRoot rhs = ((ContentHistoryRoot) other);
        return ((((((this.previousEntryName == rhs.previousEntryName)||((this.previousEntryName!= null)&&this.previousEntryName.equals(rhs.previousEntryName)))&&((this.submission == rhs.submission)||((this.submission!= null)&&this.submission.equals(rhs.submission))))&&((this.contribution == rhs.contribution)||((this.contribution!= null)&&this.contribution.equals(rhs.contribution))))&&((this.additionalProperties == rhs.additionalProperties)||((this.additionalProperties!= null)&&this.additionalProperties.equals(rhs.additionalProperties))))&&((this.modification == rhs.modification)||((this.modification!= null)&&this.modification.equals(rhs.modification))));
    }

}
