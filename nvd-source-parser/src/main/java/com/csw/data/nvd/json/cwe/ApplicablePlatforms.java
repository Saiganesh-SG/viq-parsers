
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
    "language",
    "operatingSystem",
    "architecture",
    "technology"
})
public class ApplicablePlatforms {

    @JsonProperty("language")
    private List<Language> language = null;
    @JsonProperty("operatingSystem")
    private List<OperatingSystem> operatingSystem = null;
    @JsonProperty("architecture")
    private List<Architecture> architecture = null;
    @JsonProperty("technology")
    private List<Technology> technology = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("language")
    public List<Language> getLanguage() {
        return language;
    }

    @JsonProperty("language")
    public void setLanguage(List<Language> language) {
        this.language = language;
    }

    @JsonProperty("operatingSystem")
    public List<OperatingSystem> getOperatingSystem() {
        return operatingSystem;
    }

    @JsonProperty("operatingSystem")
    public void setOperatingSystem(List<OperatingSystem> operatingSystem) {
        this.operatingSystem = operatingSystem;
    }

    @JsonProperty("architecture")
    public List<Architecture> getArchitecture() {
        return architecture;
    }

    @JsonProperty("architecture")
    public void setArchitecture(List<Architecture> architecture) {
        this.architecture = architecture;
    }

    @JsonProperty("technology")
    public List<Technology> getTechnology() {
        return technology;
    }

    @JsonProperty("technology")
    public void setTechnology(List<Technology> technology) {
        this.technology = technology;
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
