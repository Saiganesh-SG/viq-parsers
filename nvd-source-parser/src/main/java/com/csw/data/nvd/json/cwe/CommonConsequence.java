
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
    "scope",
    "impact",
    "likelihood",
    "note"
})
public class CommonConsequence {

    @JsonProperty("scope")
    private List<String> scope = null;
    @JsonProperty("impact")
    private List<String> impact = null;
    @JsonProperty("likelihood")
    private String likelihood;
    @JsonProperty("note")
    private String note;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("scope")
    public List<String> getScope() {
        return scope;
    }

    @JsonProperty("scope")
    public void setScope(List<String> scope) {
        this.scope = scope;
    }

    @JsonProperty("impact")
    public List<String> getImpact() {
        return impact;
    }

    @JsonProperty("impact")
    public void setImpact(List<String> impact) {
        this.impact = impact;
    }

    @JsonProperty("likelihood")
    public String getLikelihood() {
        return likelihood;
    }

    @JsonProperty("likelihood")
    public void setLikelihood(String likelihood) {
        this.likelihood = likelihood;
    }

    @JsonProperty("note")
    public String getNote() {
        return note;
    }

    @JsonProperty("note")
    public void setNote(String note) {
        this.note = note;
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
