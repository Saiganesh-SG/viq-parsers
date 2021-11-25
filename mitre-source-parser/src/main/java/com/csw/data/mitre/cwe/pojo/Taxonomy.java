package com.csw.data.mitre.cwe.pojo;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Taxonomy {
	private String name;
	private Integer year;
	private String source;
	private Integer rank;
	private List<OwaspVulnerability> vulnerabilities;
}
