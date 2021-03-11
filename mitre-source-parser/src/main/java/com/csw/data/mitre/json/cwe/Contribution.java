
package com.csw.data.mitre.json.cwe;

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
    "type",
    "contributionName",
    "contributionOrganization",
    "contributionDate",
    "contributionComment"
})
public class Contribution {

    @JsonProperty("type")
    private String type;
    @JsonProperty("contributionName")
    private String contributionName;
    @JsonProperty("contributionOrganization")
    private String contributionOrganization;
    @JsonProperty("contributionDate")
    private String contributionDate;
    @JsonProperty("contributionComment")
    private String contributionComment;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("type")
    public String getType() {
        return type;
    }

    @JsonProperty("type")
    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("contributionName")
    public String getContributionName() {
        return contributionName;
    }

    @JsonProperty("contributionName")
    public void setContributionName(String contributionName) {
        this.contributionName = contributionName;
    }

    @JsonProperty("contributionOrganization")
    public String getContributionOrganization() {
        return contributionOrganization;
    }

    @JsonProperty("contributionOrganization")
    public void setContributionOrganization(String contributionOrganization) {
        this.contributionOrganization = contributionOrganization;
    }

    @JsonProperty("contributionDate")
    public String getContributionDate() {
        return contributionDate;
    }

    @JsonProperty("contributionDate")
    public void setContributionDate(String contributionDate) {
        this.contributionDate = contributionDate;
    }

    @JsonProperty("contributionComment")
    public String getContributionComment() {
        return contributionComment;
    }

    @JsonProperty("contributionComment")
    public void setContributionComment(String contributionComment) {
        this.contributionComment = contributionComment;
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
