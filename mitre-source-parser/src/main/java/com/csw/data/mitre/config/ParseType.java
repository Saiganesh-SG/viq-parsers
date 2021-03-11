package com.csw.data.mitre.config;

import com.csw.data.mitre.exception.InvalidParameterException;

public enum ParseType {
	CVE("cve"), CPE("cpe"), CWE("cwe"), EXPLOIT("exploit"), EXPLOIT_CURATE("exploit_curate");

	private final String type;

	ParseType(String type) {
		this.type = type;
	}

	public String getType() {
		return type;
	}

	static public Boolean isValidParseType(String name) {
		for (ParseType parseType : ParseType.values()) {
			if (parseType.name().equalsIgnoreCase(name)) {
				return true;
			}
		}
		return false;
	}

	static public ParseType forNameIgnoreCase(String name) throws InvalidParameterException {
		for (ParseType parseType : ParseType.values()) {
			if (parseType.name().equalsIgnoreCase(name)) {
				return parseType;
			}
		}
		throw new InvalidParameterException(ErrorMessage.INVALID_PARSE_TYPE);
	}
}
