
package com.csw.data.nvd.json.cpe.source;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Generated;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * JSON Schema for NVD CVE Applicability Statement CPE Data Feed version 1.0
 * <p>
 * 
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "matches"
})
@Generated("jsonschema2pojo")
public class NvdCpeMatch {

    /**
     * Array of CPE match strings
     * (Required)
     * 
     */
    @JsonProperty("matches")
    @JsonPropertyDescription("Array of CPE match strings")
    private List<DefCpeMatch> matches = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * Array of CPE match strings
     * (Required)
     * 
     */
    @JsonProperty("matches")
    public List<DefCpeMatch> getMatches() {
        return matches;
    }

    /**
     * Array of CPE match strings
     * (Required)
     * 
     */
    @JsonProperty("matches")
    public void setMatches(List<DefCpeMatch> matches) {
        this.matches = matches;
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
