
package com.csw.data.nvd.json.targets;

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
    "cpeUri",
    "versionStart",
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEnd",
    "versionEndIncluding",
    "versionEndExcluding",
    "vulnerable",
    "cpeName"
})
public class CpeList {

    @JsonProperty("cpeUri")
    private String cpeUri;
    @JsonProperty("versionStart")
    private String versionStart;
    @JsonProperty("versionStartIncluding")
    private String versionStartIncluding;
    @JsonProperty("versionStartExcluding")
    private String versionStartExcluding;
    @JsonProperty("versionEnd")
    private String versionEnd;
    @JsonProperty("versionEndIncluding")
    private String versionEndIncluding;
    @JsonProperty("versionEndExcluding")
    private String versionEndExcluding;
    @JsonProperty("vulnerable")
    private String vulnerable;
    @JsonProperty("cpeName")
    private List<String> cpeName = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("cpeUri")
    public String getCpeUri() {
        return cpeUri;
    }

    @JsonProperty("cpeUri")
    public void setCpeUri(String cpeUri) {
        this.cpeUri = cpeUri;
    }

    @JsonProperty("versionStart")
    public String getVersionStart() {
        return versionStart;
    }

    @JsonProperty("versionStart")
    public void setVersionStart(String versionStart) {
        this.versionStart = versionStart;
    }

    @JsonProperty("versionStartIncluding")
    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    @JsonProperty("versionStartIncluding")
    public void setVersionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
    }

    @JsonProperty("versionStartExcluding")
    public String getVersionStartExcluding() {
        return versionStartExcluding;
    }

    @JsonProperty("versionStartExcluding")
    public void setVersionStartExcluding(String versionStartExcluding) {
        this.versionStartExcluding = versionStartExcluding;
    }

    @JsonProperty("versionEnd")
    public String getVersionEnd() {
        return versionEnd;
    }

    @JsonProperty("versionEnd")
    public void setVersionEnd(String versionEnd) {
        this.versionEnd = versionEnd;
    }

    @JsonProperty("versionEndIncluding")
    public String getVersionEndIncluding() {
        return versionEndIncluding;
    }

    @JsonProperty("versionEndIncluding")
    public void setVersionEndIncluding(String versionEndIncluding) {
        this.versionEndIncluding = versionEndIncluding;
    }

    @JsonProperty("versionEndExcluding")
    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    @JsonProperty("versionEndExcluding")
    public void setVersionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
    }

    @JsonProperty("vulnerable")
    public String getVulnerable() {
        return vulnerable;
    }

    @JsonProperty("vulnerable")
    public void setVulnerable(String vulnerable) {
        this.vulnerable = vulnerable;
    }

    @JsonProperty("cpeName")
    public List<String> getCpeName() {
        return cpeName;
    }

    @JsonProperty("cpeName")
    public void setCpeName(List<String> cpeName) {
        this.cpeName = cpeName;
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
