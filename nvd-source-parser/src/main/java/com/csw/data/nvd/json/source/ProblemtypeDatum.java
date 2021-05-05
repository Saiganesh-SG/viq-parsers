package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "description"
})
@Generated("jsonschema2pojo")
public class ProblemtypeDatum {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    private List<LangString> description = new ArrayList<LangString>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    public List<LangString> getDescription() {
        return description;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    public void setDescription(List<LangString> description) {
        this.description = description;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(ProblemtypeDatum.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("description");
        sb.append('=');
        sb.append(((this.description == null)?"<null>":this.description));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.description == null)? 0 :this.description.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof ProblemtypeDatum) == false) {
            return false;
        }
        ProblemtypeDatum rhs = ((ProblemtypeDatum) other);
        return ((this.description == rhs.description)||((this.description!= null)&&this.description.equals(rhs.description)));
    }

}
