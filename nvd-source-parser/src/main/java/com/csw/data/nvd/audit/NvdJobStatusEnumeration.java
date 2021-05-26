package com.csw.data.nvd.audit;

public enum NvdJobStatusEnumeration {

	COMPLETED("Completed"), FAILED("Failed");

	private final String status;

	NvdJobStatusEnumeration(String s) {
		status = s;
	}

	public String value() {
		return status;
	}
	
	public static NvdJobStatusEnumeration fromValue(String v) {
        for (NvdJobStatusEnumeration c: NvdJobStatusEnumeration.values()) {
            if (c.status.equals(v)) {
                return c;
            }
        }
		throw new IllegalArgumentException(v);
	}
}
