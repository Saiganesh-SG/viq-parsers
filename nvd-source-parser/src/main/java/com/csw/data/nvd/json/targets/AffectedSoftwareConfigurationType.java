package com.csw.data.nvd.json.targets;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffectedSoftwareConfigurationType {

	@JsonProperty("affectedProductCount")
	private String affectedProductCount;

	@JsonProperty("softwareConfigurations")
	private List<AffectedSoftwareConfiguration> softwareConfigurations;
	
	public String getAffectedProductCount() {
		return affectedProductCount;
	}

	public void setAffectedProductCount(String affectedProductCount) {
		this.affectedProductCount = affectedProductCount;
	}

	public List<AffectedSoftwareConfiguration> getSoftwareConfigurations() {
		return softwareConfigurations;
	}

	public void setSoftwareConfigurations(List<AffectedSoftwareConfiguration> softwareConfigurations) {
		this.softwareConfigurations = softwareConfigurations;
	}

}
