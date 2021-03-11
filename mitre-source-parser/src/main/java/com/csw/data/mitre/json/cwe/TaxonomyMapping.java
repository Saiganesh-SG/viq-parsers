
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
    "taxonomyName",
    "entryID",
    "entryName",
    "mappingFit",
    "entryId"
})
public class TaxonomyMapping {

    @JsonProperty("taxonomyName")
    private String taxonomyName;
    @JsonProperty("entryID")
    private String entryID;
    @JsonProperty("entryName")
    private String entryName;
    @JsonProperty("mappingFit")
    private String mappingFit;
    @JsonProperty("entryId")
    private String entryId;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("taxonomyName")
    public String getTaxonomyName() {
        return taxonomyName;
    }

    @JsonProperty("taxonomyName")
    public void setTaxonomyName(String taxonomyName) {
        this.taxonomyName = taxonomyName;
    }

    @JsonProperty("entryID")
    public String getEntryID() {
        return entryID;
    }

    @JsonProperty("entryID")
    public void setEntryID(String entryID) {
        this.entryID = entryID;
    }

    @JsonProperty("entryName")
    public String getEntryName() {
        return entryName;
    }

    @JsonProperty("entryName")
    public void setEntryName(String entryName) {
        this.entryName = entryName;
    }

    @JsonProperty("mappingFit")
    public String getMappingFit() {
        return mappingFit;
    }

    @JsonProperty("mappingFit")
    public void setMappingFit(String mappingFit) {
        this.mappingFit = mappingFit;
    }

    @JsonProperty("entryId")
    public String getEntryId() {
        return entryId;
    }

    @JsonProperty("entryId")
    public void setEntryId(String entryId) {
        this.entryId = entryId;
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
