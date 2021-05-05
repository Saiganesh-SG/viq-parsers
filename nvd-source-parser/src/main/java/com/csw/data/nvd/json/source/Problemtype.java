package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "problemtype_data"
})
@Generated("jsonschema2pojo")
public class Problemtype {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype_data")
    private List<ProblemtypeDatum> problemtypeData = new ArrayList<ProblemtypeDatum>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype_data")
    public List<ProblemtypeDatum> getProblemtypeData() {
        return problemtypeData;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype_data")
    public void setProblemtypeData(List<ProblemtypeDatum> problemtypeData) {
        this.problemtypeData = problemtypeData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Problemtype.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("problemtypeData");
        sb.append('=');
        sb.append(((this.problemtypeData == null)?"<null>":this.problemtypeData));
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
        result = ((result* 31)+((this.problemtypeData == null)? 0 :this.problemtypeData.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Problemtype) == false) {
            return false;
        }
        Problemtype rhs = ((Problemtype) other);
        return ((this.problemtypeData == rhs.problemtypeData)||((this.problemtypeData!= null)&&this.problemtypeData.equals(rhs.problemtypeData)));
    }

}
