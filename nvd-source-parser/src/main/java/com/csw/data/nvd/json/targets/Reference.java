package com.csw.data.nvd.json.targets;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Reference {
    
    @JsonProperty("url")
    private String url;
    
    @JsonProperty("name")
    private String name;
    
    @JsonProperty("refsource")
    private String refsource;
    
    @JsonProperty("tags")
    private List<String> tags;
}