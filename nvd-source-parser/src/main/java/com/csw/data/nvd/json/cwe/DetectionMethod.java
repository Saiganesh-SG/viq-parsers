
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
    "detectionMethodID",
    "method",
    "description",
    "effectiveness",
    "effectivenessNotes"
})
public class DetectionMethod {

    @JsonProperty("detectionMethodID")
    private String detectionMethodID;
    @JsonProperty("method")
    private String method;
    @JsonProperty("description")
    private List<String> description = null;
    @JsonProperty("effectiveness")
    private String effectiveness;
    @JsonProperty("effectivenessNotes")
    private List<String> effectivenessNotes = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("detectionMethodID")
    public String getDetectionMethodID() {
        return detectionMethodID;
    }

    @JsonProperty("detectionMethodID")
    public void setDetectionMethodID(String detectionMethodID) {
        this.detectionMethodID = detectionMethodID;
    }

    @JsonProperty("method")
    public String getMethod() {
        return method;
    }

    @JsonProperty("method")
    public void setMethod(String method) {
        this.method = method;
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
