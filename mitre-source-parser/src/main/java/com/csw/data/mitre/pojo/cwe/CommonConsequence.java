package com.csw.data.mitre.pojo.cwe;

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
