
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
    "id"
})
@Getter
@Setter
public class CweList {

    @JsonProperty("id")
    private String id;
    
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<>();
}
