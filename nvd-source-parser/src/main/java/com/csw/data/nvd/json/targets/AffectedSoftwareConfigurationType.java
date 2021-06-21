package com.csw.data.nvd.json.targets;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class AffectedSoftwareConfigurationType {

	@JsonProperty("affectedProductCount")
	private int affectedProductCount;

	@JsonProperty("softwareConfigurations")
	private List<AffectedSoftwareConfiguration> softwareConfigurations;
	
}
