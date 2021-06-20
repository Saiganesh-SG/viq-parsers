
package com.csw.data.nvd.json.targets;

import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "vendor",
    "dateIssued",
    "contributor",
    "commentary"
})
@Getter
@Setter
public class VendorComment {

    @JsonProperty("vendor")
    private String vendorName;
    @JsonProperty("dateIssued")
    private String dateIssued;
    @JsonProperty("contributor")
    private String contributor;
    @JsonProperty("commentary")
    private String commentary;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<>();
}
