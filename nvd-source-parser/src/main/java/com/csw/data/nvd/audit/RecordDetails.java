package com.csw.data.nvd.audit;

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
