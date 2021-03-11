
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
    "modificationName",
    "modificationOrganization",
    "modificationDate",
    "modificationImportance",
    "modificationComment"
})
public class Modification {

    @JsonProperty("modificationName")
    private String modificationName;
    @JsonProperty("modificationOrganization")
    private String modificationOrganization;
    @JsonProperty("modificationDate")
    private String modificationDate;
    @JsonProperty("modificationImportance")
    private String modificationImportance;
    @JsonProperty("modificationComment")
    private String modificationComment;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("modificationName")
    public String getModificationName() {
        return modificationName;
    }

    @JsonProperty("modificationName")
    public void setModificationName(String modificationName) {
        this.modificationName = modificationName;
    }

    @JsonProperty("modificationOrganization")
    public String getModificationOrganization() {
        return modificationOrganization;
    }

    @JsonProperty("modificationOrganization")
    public void setModificationOrganization(String modificationOrganization) {
        this.modificationOrganization = modificationOrganization;
    }

    @JsonProperty("modificationDate")
    public String getModificationDate() {
        return modificationDate;
    }

    @JsonProperty("modificationDate")
    public void setModificationDate(String modificationDate) {
        this.modificationDate = modificationDate;
    }

    @JsonProperty("modificationImportance")
    public String getModificationImportance() {
        return modificationImportance;
    }

    @JsonProperty("modificationImportance")
    public void setModificationImportance(String modificationImportance) {
        this.modificationImportance = modificationImportance;
    }

    @JsonProperty("modificationComment")
    public String getModificationComment() {
        return modificationComment;
    }

    @JsonProperty("modificationComment")
    public void setModificationComment(String modificationComment) {
        this.modificationComment = modificationComment;
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
