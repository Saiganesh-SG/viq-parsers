package com.csw.data.mitre.cwe.pojo;

import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;

@Getter
@Setter
public class Cvssv2 {
    @JsonProperty("score")
	private float cvssV2baseScore;
    @JsonProperty("severity")
    private String baseMetricV2severity;
}
