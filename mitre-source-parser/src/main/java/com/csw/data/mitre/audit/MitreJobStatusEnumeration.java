package com.csw.data.mitre.audit;

public enum MitreJobStatusEnumeration {

	COMPLETED("Completed"), FAILED("Failed");

	private final String status;

	MitreJobStatusEnumeration(String s) {
		status = s;
	}

	public String value() {
		return status;
	}
	
	public static MitreJobStatusEnumeration fromValue(String v) {
        for (MitreJobStatusEnumeration c: MitreJobStatusEnumeration.values()) {
            if (c.status.equals(v)) {
                return c;
            }
        }
		throw new IllegalArgumentException(v);
	}
}
