package com.csw.data.mitre.audit;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MitreParserAudit {

	private String jobName;

	private String startTime;

	private String endTime;

	private String totalTime;

	private JobStatusEnumeration jobStatus;

	private RecordDetails recordDetails;

	private String refreshType;

}
