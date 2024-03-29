package com.csw.data.mitre.cwe.pojo;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PotentialMitigation {
    @JsonProperty("id")
	public String mitigationId;
    public List<String> phases;
    public String strategy;
    public List<String> description;
    public String effectiveness;
    public List<String> effectivenessNotes;
}
