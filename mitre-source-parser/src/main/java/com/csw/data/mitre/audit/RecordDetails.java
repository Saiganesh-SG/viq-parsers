package com.csw.data.mitre.audit;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RecordDetails {

	private int totalRecords;

	private int newRecords;

	private int modifiedRecords;

	private int failedRecords;

}
