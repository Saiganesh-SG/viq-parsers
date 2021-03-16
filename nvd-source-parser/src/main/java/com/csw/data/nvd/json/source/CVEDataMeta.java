package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "ID",
    "ASSIGNER"
})
@Generated("jsonschema2pojo")
public class CVEDataMeta {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("ID")
    private String id;
    
    @JsonProperty("ASSIGNER")
    private String assigner;

	/**
     * 
     * (Required)
     * 
     */
    @JsonProperty("ID")
    public String getId() {
        return id;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("ID")
    public void setId(String id) {
        this.id = id;
    }
    
    public String getAssigner() {
		return assigner;
	}

	public void setAssigner(String assigner) {
		this.assigner = assigner;
	}

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(CVEDataMeta.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null)?"<null>":this.id));
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
        result = ((result* 31)+((this.id == null)? 0 :this.id.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof CVEDataMeta) == false) {
            return false;
        }
        CVEDataMeta rhs = ((CVEDataMeta) other);
        return ((this.id == rhs.id)||((this.id!= null)&&this.id.equals(rhs.id)));
    }

}
