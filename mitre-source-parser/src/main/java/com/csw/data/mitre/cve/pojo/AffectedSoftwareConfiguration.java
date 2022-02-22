package com.csw.data.mitre.cve.pojo;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "vulnerable",
    "runningOnOrWith",
    "cpe23Uri",
    "title",
    "vendor",
    "product",
    "softwareConfigurationGroup",
    "versionStart",
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEnd",
    "versionEndIncluding",
    "versionEndExcluding",
    "matchingSoftwareConfigurations"
})
@Getter
@Setter
public class AffectedSoftwareConfiguration {

    @JsonProperty("vulnerable")
    private boolean vulnerable;
    @JsonProperty("runningOnOrWith")
    private boolean runningOnOrWith;
    @JsonProperty("cpe23Uri")
    private String cpe23Uri;
    @JsonProperty("title")
    private String title;
    @JsonProperty("vendor")
    private String vendor;
    @JsonProperty("product")
    private String product;
    @JsonProperty("softwareConfigurationGroup")
    private String softwareConfigurationGroup;
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
    @JsonProperty("matchingSoftwareConfigurations")
    private List<MatchingSoftwareConfiguration> matchingSoftwareConfigurations = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();
}
