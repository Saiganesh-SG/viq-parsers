
package com.csw.data.nvd.json.targets;

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
    "vendorName",
    "dateIssued",
    "contributor",
    "commentary"
})
public class VendorComment {

    @JsonProperty("vendorName")
    private String vendorName;
    @JsonProperty("dateIssued")
    private String dateIssued;
    @JsonProperty("contributor")
    private String contributor;
    @JsonProperty("commentary")
    private String commentary;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("vendorName")
    public String getVendorName() {
        return vendorName;
    }

    @JsonProperty("vendorName")
    public void setVendorName(String vendorName) {
        this.vendorName = vendorName;
    }

    @JsonProperty("dateIssued")
    public String getDateIssued() {
        return dateIssued;
    }

    @JsonProperty("dateIssued")
    public void setDateIssued(String dateIssued) {
        this.dateIssued = dateIssued;
    }

    @JsonProperty("contributor")
    public String getContributor() {
        return contributor;
    }

    @JsonProperty("contributor")
    public void setContributor(String contributor) {
        this.contributor = contributor;
    }

    @JsonProperty("commentary")
    public String getCommentary() {
        return commentary;
    }

    @JsonProperty("commentary")
    public void setCommentary(String commentary) {
        this.commentary = commentary;
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
