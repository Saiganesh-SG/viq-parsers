package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "CVE_data_meta",
    "problemtype",
    "references",
    "description"
})
@Generated("jsonschema2pojo")
public class CVEJSON40Min11 {
	
	@JsonIgnore
	private String dataType;
	
	@JsonIgnore
	private String dataFormat;
	
	@JsonIgnore
	private String dataVersion;

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("CVE_data_meta")
    private CVEDataMeta cVEDataMeta;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype")
    private Problemtype problemtype;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("references")
    private References references;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    private Description description;

    @JsonProperty("CVE_data_meta")
    public CVEDataMeta getCVEDataMeta() {
        return cVEDataMeta;
    }

    @JsonProperty("CVE_data_meta")
    public void setCVEDataMeta(CVEDataMeta cVEDataMeta) {
        this.cVEDataMeta = cVEDataMeta;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype")
    public Problemtype getProblemtype() {
        return problemtype;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("problemtype")
    public void setProblemtype(Problemtype problemtype) {
        this.problemtype = problemtype;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("references")
    public References getReferences() {
        return references;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("references")
    public void setReferences(References references) {
        this.references = references;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    public Description getDescription() {
        return description;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("description")
    public void setDescription(Description description) {
        this.description = description;
    }
    
    @JsonProperty("data_type")
    public String getDataType() {
		return dataType;
	}

    @JsonProperty("data_type")
	public void setDataType(String dataType) {
		this.dataType = dataType;
	}

    @JsonProperty("data_format")
	public String getDataFormat() {
		return dataFormat;
	}

    @JsonProperty("data_format")
	public void setDataFormat(String dataFormat) {
		this.dataFormat = dataFormat;
	}

    @JsonProperty("data_version")
	public String getDataVersion() {
		return dataVersion;
	}

    @JsonProperty("data_version")
	public void setDataVersion(String dataVersion) {
		this.dataVersion = dataVersion;
	}

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(CVEJSON40Min11 .class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cVEDataMeta");
        sb.append('=');
        sb.append(((this.cVEDataMeta == null)?"<null>":this.cVEDataMeta));
        sb.append(',');
        sb.append("problemtype");
        sb.append('=');
        sb.append(((this.problemtype == null)?"<null>":this.problemtype));
        sb.append(',');
        sb.append("references");
        sb.append('=');
        sb.append(((this.references == null)?"<null>":this.references));
        sb.append(',');
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
        result = ((result* 31)+((this.cVEDataMeta == null)? 0 :this.cVEDataMeta.hashCode()));
        result = ((result* 31)+((this.description == null)? 0 :this.description.hashCode()));
        result = ((result* 31)+((this.problemtype == null)? 0 :this.problemtype.hashCode()));
        result = ((result* 31)+((this.references == null)? 0 :this.references.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof CVEJSON40Min11) == false) {
            return false;
        }
        CVEJSON40Min11 rhs = ((CVEJSON40Min11) other);
        return (((((this.cVEDataMeta == rhs.cVEDataMeta)||((this.cVEDataMeta!= null)&&this.cVEDataMeta.equals(rhs.cVEDataMeta)))&&((this.description == rhs.description)||((this.description!= null)&&this.description.equals(rhs.description))))&&((this.problemtype == rhs.problemtype)||((this.problemtype!= null)&&this.problemtype.equals(rhs.problemtype))))&&((this.references == rhs.references)||((this.references!= null)&&this.references.equals(rhs.references))));
    }

}
