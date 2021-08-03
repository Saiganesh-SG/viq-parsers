
package com.csw.data.nvd.json.cpedictionary.targets;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Generated;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.Getter;
import lombok.Setter;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "title",
    "cpe22",
    "cpe23",
    "references",
    "notes"
})
@Getter
@Setter
public class CpeDictionary {

    @JsonProperty("title")
    public String title;
    @JsonProperty("cpe22")
    public Cpe22 cpe22;
    @JsonProperty("cpe23")
    public Cpe23 cpe23;
    @JsonProperty("references")
    public List<Reference> references = null;
    @JsonProperty("notes")
    public List<Note> notes = null;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
