package com.csw.data.mitre.dto.cpe;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CpeJsonData {

    @JsonProperty("matches")
    private List<CpeMatch> cpeMatches = new ArrayList<>();
}
