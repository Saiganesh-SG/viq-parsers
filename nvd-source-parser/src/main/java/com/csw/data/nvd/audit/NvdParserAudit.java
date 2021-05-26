package com.csw.data.nvd.audit;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NvdParserAudit {

	private String jobName;

	private String startTime;

	private String endTime;

	private String totalTime;

	private NvdJobStatusEnumeration jobStatus;

	private RecordDetails recordDetails;

	private String refreshType;

}
