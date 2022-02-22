package com.csw.data.mitre.cve.pojo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Getter
@Setter
public class CVEDataMeta {
	
	@JsonProperty("ID")
	private String id;
	
	@JsonProperty("ASSIGNER")
	private String assigner;
	
	@JsonProperty("STATE")
	private String state;
	
	@JsonProperty("DATE_PUBLIC")
	private String datePublic;
	
	@JsonProperty("TITLE")
	private String title;
	
	@JsonProperty("DATE_ASSIGNED")
	private String dateAssigned;
	
	@JsonProperty("DATA_ASSIGNED")
	private String dataAssigned;
	
	@JsonProperty("REQUESTER")
	private String requester;
	
	@JsonProperty("AKA")
	private String aka;
	
	@JsonProperty("UPDATED")
	private String updated;
	
	@JsonProperty("DATE_REQUESTED")
	private String dateRequested;
	
	@JsonProperty("STATE_DETAIL")
	private String stateDetail;
	
	@JsonProperty("vendor_name")
	private String vendorName;
	
	@JsonProperty("DATE_ASSIGNEDE")
	private String dateAssignede;

}
