package com.csw.data.nvd.config;

import com.csw.data.nvd.exception.InvalidParameterException;

public enum ParseType {
	CVE("cve"), CPE("cpe"), COMMENT("comment"), CPE_DICTIONARY("cpe_dictionary");
	
	private static final String INVALID_PARSE_TYPE = "Invalid parse type. The parse type should be any of the one (CVE, CPE, CPE DICTIONARY)";

	private final String type;

	ParseType(String type) {
		this.type = type;
	}

	public String getType() {
		return type;
	}

	public static Boolean isValidParseType(String name) {
		for (ParseType parseType : ParseType.values()) {
			if (parseType.name().equalsIgnoreCase(name)) {
				return true;
			}
		}
		return false;
	}

	public static ParseType forNameIgnoreCase(String name) throws InvalidParameterException {
		for (ParseType parseType : ParseType.values()) {
			if (parseType.name().equalsIgnoreCase(name)) {
				return parseType;
			}
		}
		throw new InvalidParameterException(INVALID_PARSE_TYPE);
	}
}
