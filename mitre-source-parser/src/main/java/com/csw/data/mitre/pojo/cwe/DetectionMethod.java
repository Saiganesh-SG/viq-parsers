package com.csw.data.mitre.pojo.cwe;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DetectionMethod {
	public String detectionMethodID;
    public String method;
    public List<String> description;
    public String effectiveness;
    public List<String> effectivenessNotes;
}
