package com.csw.data.mitre.cwe.pojo;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class PotentialMitigation {
	public String mitigationId;
    public List<String> phases;
    public String strategy;
    public List<String> description;
    public String effectiveness;
    public List<String> effectivenessNotes;
}
