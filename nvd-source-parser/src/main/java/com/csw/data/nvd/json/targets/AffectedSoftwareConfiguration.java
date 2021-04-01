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
public class AffectedSoftwareConfiguration {

    @JsonProperty("vulnerable")
    private String vulnerable;
    @JsonProperty("runningOnOrWith")
    private String runningOnOrWith;
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

	@JsonProperty("vulnerable")
    public String getVulnerable() {
        return vulnerable;
    }

    @JsonProperty("vulnerable")
    public void setVulnerable(String vulnerable) {
        this.vulnerable = vulnerable;
    }

    @JsonProperty("runningOnOrWith")
    public String getRunningOnOrWith() {
        return runningOnOrWith;
    }

    @JsonProperty("runningOnOrWith")
    public void setRunningOnOrWith(String runningOnOrWith) {
        this.runningOnOrWith = runningOnOrWith;
    }

    @JsonProperty("cpe23Uri")
    public String getCpe23Uri() {
        return cpe23Uri;
    }

    @JsonProperty("cpe23Uri")
    public void setCpe23Uri(String cpe23Uri) {
        this.cpe23Uri = cpe23Uri;
    }

    @JsonProperty("title")
    public String getTitle() {
        return title;
    }

    @JsonProperty("title")
    public void setTitle(String title) {
        this.title = title;
    }

    @JsonProperty("softwareConfigurationGroup")
    public String getSoftwareConfigurationGroup() {
        return softwareConfigurationGroup;
    }

    @JsonProperty("softwareConfigurationGroup")
    public void setSoftwareConfigurationGroup(String softwareConfigurationGroup) {
        this.softwareConfigurationGroup = softwareConfigurationGroup;
    }

    @JsonProperty("versionStartIncluding")
    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    @JsonProperty("versionStartIncluding")
    public void setVersionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
    }

    @JsonProperty("versionEndExcluding")
    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    @JsonProperty("versionEndExcluding")
    public void setVersionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
    }

    @JsonProperty("matchingSoftwareConfigurations")
    public List<MatchingSoftwareConfiguration> getMatchingSoftwareConfigurations() {
        return matchingSoftwareConfigurations;
    }

    @JsonProperty("matchingSoftwareConfigurations")
    public void setMatchingSoftwareConfigurations(List<MatchingSoftwareConfiguration> matchingSoftwareConfigurations) {
        this.matchingSoftwareConfigurations = matchingSoftwareConfigurations;
    }
    
    public String getVersionStartExcluding() {
  		return versionStartExcluding;
  	}

  	public void setVersionStartExcluding(String versionStartExcluding) {
  		this.versionStartExcluding = versionStartExcluding;
  	}

  	public String getVersionEndIncluding() {
  		return versionEndIncluding;
  	}

  	public void setVersionEndIncluding(String versionEndIncluding) {
  		this.versionEndIncluding = versionEndIncluding;
  	}
  	
  	public String getVersionStart() {
		return versionStart;
	}

	public void setVersionStart(String versionStart) {
		this.versionStart = versionStart;
	}

	public String getVersionEnd() {
		return versionEnd;
	}

	public void setVersionEnd(String versionEnd) {
		this.versionEnd = versionEnd;
	}

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

	public String getVendor() {
		return vendor;
	}

	public void setVendor(String vendor) {
		this.vendor = vendor;
	}

	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}

}
