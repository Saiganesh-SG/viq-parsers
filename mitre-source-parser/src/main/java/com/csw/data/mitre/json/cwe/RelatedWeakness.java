
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
    "id",
    "nature",
    "chainId",
    "viewId",
    "ordinal"
})
public class RelatedWeakness {

    @JsonProperty("id")
    private String id;
    @JsonProperty("nature")
    private String nature;
    @JsonProperty("chainId")
    private String chainId;
    @JsonProperty("viewId")
    private String viewId;
    @JsonProperty("ordinal")
    private String ordinal;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("nature")
    public String getNature() {
        return nature;
    }

    @JsonProperty("nature")
    public void setNature(String nature) {
        this.nature = nature;
    }

    @JsonProperty("chainId")
    public String getChainId() {
        return chainId;
    }

    @JsonProperty("chainId")
    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    @JsonProperty("viewId")
    public String getViewId() {
        return viewId;
    }

    @JsonProperty("viewId")
    public void setViewId(String viewId) {
        this.viewId = viewId;
    }

    @JsonProperty("ordinal")
    public String getOrdinal() {
        return ordinal;
    }

    @JsonProperty("ordinal")
    public void setOrdinal(String ordinal) {
        this.ordinal = ordinal;
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
