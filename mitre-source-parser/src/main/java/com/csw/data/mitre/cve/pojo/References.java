package com.csw.data.mitre.cve.pojo;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.ALWAYS)
@JsonPropertyOrder({
	"name",
	"title",
	"source",
	"url",
	"tags"
})
@Getter
@Setter
public class References {
	
	@JsonProperty("name")
	private String name;
	
	@JsonProperty("title")
	private String title;
	
	@JsonProperty("source")
	private String source;
	
	@JsonProperty("url")
	private String url;
	
    @JsonProperty("tags")
    private List<String> tags = new ArrayList<>();

}
