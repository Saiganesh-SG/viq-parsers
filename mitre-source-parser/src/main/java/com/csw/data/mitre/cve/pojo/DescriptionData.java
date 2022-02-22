package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class DescriptionData {

	@JsonProperty("lang")
	private String lang;
	
	@JsonProperty("value")
	private String value;
	
	@Override
	public String toString() {
		return "DescriptionData [lang=" + lang + ", value=" + value + "]";
	}

}
