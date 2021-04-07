package com.csw.data.mitre.cwe.pojo;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CommonConsequence {
	public List<String> scope;
    public List<String> impact;
    public String likelihood;
    public String note;
}
