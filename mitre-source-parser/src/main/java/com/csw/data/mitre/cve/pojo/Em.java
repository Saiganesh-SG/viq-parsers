package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class Em {

	@JsonProperty("CR")
	private String cr;

	@JsonProperty("IR")
	private String ir;

	@JsonProperty("AR")
	private String ar;

	@JsonProperty("MAV")
	private String mav;

	@JsonProperty("MAC")
	private String mac;

	@JsonProperty("MPR")
	private String mpr;

	@JsonProperty("MUI")
	private String mui;

	@JsonProperty("MS")
	private String ms;

	@JsonProperty("MC")
	private String mc;

	@JsonProperty("MI")
	private String mi;

	@JsonProperty("MA")
	private String ma;

}
