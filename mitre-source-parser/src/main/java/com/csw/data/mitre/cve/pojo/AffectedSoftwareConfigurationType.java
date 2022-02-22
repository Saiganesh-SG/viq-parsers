package com.csw.data.mitre.cve.pojo;

import java.util.ArrayList;
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
	private Integer affectedProductCount;

	@JsonProperty("softwareConfigurations")
	private List<AffectedSoftwareConfiguration> softwareConfigurations = new ArrayList<>();
	
}
