package com.csw.data.mitre.cwe.pojo;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;


@JsonPropertyOrder({
        "score",
        "version",
        "severity",
        "reasonForChange",
        "lastModifiedDate"
})
@Getter
@Setter
public class WeaknessRiskScore {

    private Double score;

    private String version;

    private String severity;

    private String lastModifiedDate;

    private List<String> reasonForChange;
}
