package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "description_data"
})
@Generated("jsonschema2pojo")
public class Description {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description_data")
    private List<LangString> descriptionData = new ArrayList<LangString>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description_data")
    public List<LangString> getDescriptionData() {
        return descriptionData;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description_data")
    public void setDescriptionData(List<LangString> descriptionData) {
        this.descriptionData = descriptionData;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Description.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("descriptionData");
        sb.append('=');
        sb.append(((this.descriptionData == null)?"<null>":this.descriptionData));
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
        result = ((result* 31)+((this.descriptionData == null)? 0 :this.descriptionData.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Description) == false) {
            return false;
        }
        Description rhs = ((Description) other);
        return ((this.descriptionData == rhs.descriptionData)||((this.descriptionData!= null)&&this.descriptionData.equals(rhs.descriptionData)));
    }

}
