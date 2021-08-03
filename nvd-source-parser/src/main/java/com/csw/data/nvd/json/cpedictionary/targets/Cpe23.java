
package com.csw.data.nvd.json.cpedictionary.targets;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Generated;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cpe23Uri",
    "deprecated",
    "deprecatedBy",
    "deprecationDate",
    "deprecationReason",
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "softwareEdition",
    "targetSoftware",
    "targetHardware",
    "other"
})
@Getter
@Setter
public class Cpe23 {

    @JsonProperty("cpe23Uri")
    public String cpe23Uri;
    @JsonProperty(defaultValue = "false")
    public boolean deprecated;
    @JsonProperty("deprecatedBy")
    public String deprecatedBy;
    @JsonProperty("deprecationDate")
    public String deprecationDate;
    @JsonProperty("deprecationReason")
    public String deprecationReason;
    @JsonProperty("part")
    public String part;
    @JsonProperty("vendor")
    public String vendor;
    @JsonProperty("product")
    public String product;
    @JsonProperty("version")
    public String version;
    @JsonProperty("update")
    public String update;
    @JsonProperty("edition")
    public String edition;
    @JsonProperty("language")
    public String language;
    @JsonProperty("softwareEdition")
    public String softwareEdition;
    @JsonProperty("targetSoftware")
    public String targetSoftware;
    @JsonProperty("targetHardware")
    public String targetHardware;
    @JsonProperty("other")
    public String other;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
