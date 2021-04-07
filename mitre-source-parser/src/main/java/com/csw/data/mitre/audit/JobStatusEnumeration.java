package com.csw.data.mitre.audit;

public enum JobStatusEnumeration {

	COMPLETED("Completed"), FAILED("Failed");

	private final String status;

	JobStatusEnumeration(String s) {
		status = s;
	}

	public String value() {
		return status;
	}
	
	public static JobStatusEnumeration fromValue(String v) {
        for (JobStatusEnumeration c: JobStatusEnumeration.values()) {
            if (c.status.equals(v)) {
                return c;
            }
        }
		throw new IllegalArgumentException(v);
	}
}
