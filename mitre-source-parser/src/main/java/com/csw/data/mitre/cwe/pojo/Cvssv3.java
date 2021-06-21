package com.csw.data.mitre.cwe.pojo;

import lombok.Setter;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;

@Getter
@Setter
public class Cvssv3 {
    @JsonProperty("score")
	private float cvssV3baseScore;
    @JsonProperty("severity")
    private String cvssV3baseSeverity;
}
