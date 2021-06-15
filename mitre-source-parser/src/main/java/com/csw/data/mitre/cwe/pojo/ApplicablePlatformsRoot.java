
package com.csw.data.mitre.cwe.pojo;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "language",
    "operatingSystem",
    "architecture",
    "technology"
})
@Getter
@Setter
public class ApplicablePlatformsRoot {

    @JsonProperty("language")
    private List<PlatformType> language = new ArrayList<>();
    @JsonProperty("operatingSystem")
    private List<PlatformType> operatingSystem = new ArrayList<>();
    @JsonProperty("architecture")
    private List<PlatformType> architecture = new ArrayList<>();
    @JsonProperty("technology")
    private List<PlatformType> technology = new ArrayList<>();

}
