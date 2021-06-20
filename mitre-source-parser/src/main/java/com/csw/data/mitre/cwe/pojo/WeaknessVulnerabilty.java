package com.csw.data.mitre.cwe.pojo;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WeaknessVulnerabilty {
	private String id;
	private Cvssv2 cvssv2;
	private Cvssv3 cvssv3;

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof WeaknessVulnerabilty) {
			return ((WeaknessVulnerabilty) obj).id.equals(id);
		}
		return super.equals(obj);
	}

	@Override
	public int hashCode() {
		return this.id.hashCode();
	}
}
