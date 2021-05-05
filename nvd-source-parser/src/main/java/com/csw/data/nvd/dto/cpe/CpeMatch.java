package com.csw.data.nvd.dto.cpe;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CpeMatch {

    @JsonProperty("cpe23Uri")
    private String cpeKey;

    @JsonProperty("versionStartIncluding")
    private String versionStartIncluding;

    @JsonProperty("versionEndIncluding")
    private String versionEndIncluding;

    @JsonProperty("versionStartExcluding")
    private String versionStartExcluding;

    @JsonProperty("versionEndExcluding")
    private String versionEndExcluding;

    @JsonProperty("vulnerable")
    private boolean vulnerable;

    @JsonProperty("cpe_name")
    private List<CpeName> cpeNames = new ArrayList<>();
}
