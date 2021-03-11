
package com.csw.data.mitre.pojo.cwe;

import java.util.ArrayList;
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
public class ApplicablePlatformsRoot {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("language")
    private List<PlatformType> language = new ArrayList<>();
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("operatingSystem")
    private List<PlatformType> operatingSystem = new ArrayList<>();
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("architecture")
    private List<PlatformType> architecture = new ArrayList<>();
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("technology")
    private List<PlatformType> technology = new ArrayList<>();
    
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("language")
    public List<PlatformType> getLanguage() {
        return language;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("language")
    public void setLanguage(List<PlatformType> language) {
        this.language = language;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("operatingSystem")
    public List<PlatformType> getOperatingSystem() {
        return operatingSystem;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("operatingSystem")
    public void setOperatingSystem(List<PlatformType> operatingSystem) {
        this.operatingSystem = operatingSystem;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("architecture")
    public List<PlatformType> getArchitecture() {
        return architecture;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("architecture")
    public void setArchitecture(List<PlatformType> architecture) {
        this.architecture = architecture;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("technology")
    public List<PlatformType> getTechnology() {
        return technology;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("technology")
    public void setTechnology(List<PlatformType> technology) {
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

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(ApplicablePlatformsRoot.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("language");
        sb.append('=');
        sb.append(((this.language == null)?"<null>":this.language));
        sb.append(',');
        sb.append("operatingSystem");
        sb.append('=');
        sb.append(((this.operatingSystem == null)?"<null>":this.operatingSystem));
        sb.append(',');
        sb.append("architecture");
        sb.append('=');
        sb.append(((this.architecture == null)?"<null>":this.architecture));
        sb.append(',');
        sb.append("technology");
        sb.append('=');
        sb.append(((this.technology == null)?"<null>":this.technology));
        sb.append(',');
        sb.append("additionalProperties");
        sb.append('=');
        sb.append(((this.additionalProperties == null)?"<null>":this.additionalProperties));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.language == null)? 0 :this.language.hashCode()));
        result = ((result* 31)+((this.technology == null)? 0 :this.technology.hashCode()));
        result = ((result* 31)+((this.additionalProperties == null)? 0 :this.additionalProperties.hashCode()));
        result = ((result* 31)+((this.operatingSystem == null)? 0 :this.operatingSystem.hashCode()));
        result = ((result* 31)+((this.architecture == null)? 0 :this.architecture.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof ApplicablePlatformsRoot) == false) {
            return false;
        }
        ApplicablePlatformsRoot rhs = ((ApplicablePlatformsRoot) other);
        return ((((((this.language == rhs.language)||((this.language!= null)&&this.language.equals(rhs.language)))&&((this.technology == rhs.technology)||((this.technology!= null)&&this.technology.equals(rhs.technology))))&&((this.additionalProperties == rhs.additionalProperties)||((this.additionalProperties!= null)&&this.additionalProperties.equals(rhs.additionalProperties))))&&((this.operatingSystem == rhs.operatingSystem)||((this.operatingSystem!= null)&&this.operatingSystem.equals(rhs.operatingSystem))))&&((this.architecture == rhs.architecture)||((this.architecture!= null)&&this.architecture.equals(rhs.architecture))));
    }

}
