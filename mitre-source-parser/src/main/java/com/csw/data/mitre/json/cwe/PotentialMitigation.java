
package com.csw.data.mitre.json.cwe;

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
    "mitigationId",
    "phases",
    "strategy",
    "description",
    "effectiveness",
    "effectivenessNotes"
})
public class PotentialMitigation {

    @JsonProperty("mitigationId")
    private String mitigationId;
    @JsonProperty("phases")
    private List<String> phases = null;
    @JsonProperty("strategy")
    private String strategy;
    @JsonProperty("description")
    private List<String> description = null;
    @JsonProperty("effectiveness")
    private String effectiveness;
    @JsonProperty("effectivenessNotes")
    private List<String> effectivenessNotes = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("mitigationId")
    public String getMitigationId() {
        return mitigationId;
    }

    @JsonProperty("mitigationId")
    public void setMitigationId(String mitigationId) {
        this.mitigationId = mitigationId;
    }

    @JsonProperty("phases")
    public List<String> getPhases() {
        return phases;
    }

    @JsonProperty("phases")
    public void setPhases(List<String> phases) {
        this.phases = phases;
    }

    @JsonProperty("strategy")
    public String getStrategy() {
        return strategy;
    }

    @JsonProperty("strategy")
    public void setStrategy(String strategy) {
        this.strategy = strategy;
    }

    @JsonProperty("description")
    public List<String> getDescription() {
        return description;
    }

    @JsonProperty("description")
    public void setDescription(List<String> description) {
        this.description = description;
    }

    @JsonProperty("effectiveness")
    public String getEffectiveness() {
        return effectiveness;
    }

    @JsonProperty("effectiveness")
    public void setEffectiveness(String effectiveness) {
        this.effectiveness = effectiveness;
    }

    @JsonProperty("effectivenessNotes")
    public List<String> getEffectivenessNotes() {
        return effectivenessNotes;
    }

    @JsonProperty("effectivenessNotes")
    public void setEffectivenessNotes(List<String> effectivenessNotes) {
        this.effectivenessNotes = effectivenessNotes;
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
