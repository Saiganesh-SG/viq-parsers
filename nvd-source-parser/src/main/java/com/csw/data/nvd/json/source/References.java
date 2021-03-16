package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "reference_data"
})
@Generated("jsonschema2pojo")
public class References {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("reference_data")
    private List<Reference> referenceData = new ArrayList<Reference>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("reference_data")
    public List<Reference> getReferenceData() {
        return referenceData;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("reference_data")
    public void setReferenceData(List<Reference> referenceData) {
        this.referenceData = referenceData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(References.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("referenceData");
        sb.append('=');
        sb.append(((this.referenceData == null)?"<null>":this.referenceData));
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
        result = ((result* 31)+((this.referenceData == null)? 0 :this.referenceData.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof References) == false) {
            return false;
        }
        References rhs = ((References) other);
        return ((this.referenceData == rhs.referenceData)||((this.referenceData!= null)&&this.referenceData.equals(rhs.referenceData)));
    }

}
