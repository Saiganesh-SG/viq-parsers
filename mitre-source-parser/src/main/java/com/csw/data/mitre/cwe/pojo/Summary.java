package com.csw.data.mitre.cwe.pojo;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Summary {
	
    @JsonProperty("vulnerabilitiesCount")
	private int vulnerabilitiesCount;

}
