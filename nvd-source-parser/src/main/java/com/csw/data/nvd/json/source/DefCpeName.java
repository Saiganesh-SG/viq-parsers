package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * CPE name
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cpe22Uri",
    "cpe23Uri",
    "lastModifiedDate"
})
@Generated("jsonschema2pojo")
public class DefCpeName {

    @JsonProperty("cpe22Uri")
    private String cpe22Uri;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cpe23Uri")
    private String cpe23Uri;
    @JsonProperty("lastModifiedDate")
    private String lastModifiedDate;

    @JsonProperty("cpe22Uri")
    public String getCpe22Uri() {
        return cpe22Uri;
    }

    @JsonProperty("cpe22Uri")
    public void setCpe22Uri(String cpe22Uri) {
        this.cpe22Uri = cpe22Uri;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cpe23Uri")
    public String getCpe23Uri() {
        return cpe23Uri;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cpe23Uri")
    public void setCpe23Uri(String cpe23Uri) {
        this.cpe23Uri = cpe23Uri;
    }

    @JsonProperty("lastModifiedDate")
    public String getLastModifiedDate() {
        return lastModifiedDate;
    }

    @JsonProperty("lastModifiedDate")
    public void setLastModifiedDate(String lastModifiedDate) {
        this.lastModifiedDate = lastModifiedDate;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(DefCpeName.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cpe22Uri");
        sb.append('=');
        sb.append(((this.cpe22Uri == null)?"<null>":this.cpe22Uri));
        sb.append(',');
        sb.append("cpe23Uri");
        sb.append('=');
        sb.append(((this.cpe23Uri == null)?"<null>":this.cpe23Uri));
        sb.append(',');
        sb.append("lastModifiedDate");
        sb.append('=');
        sb.append(((this.lastModifiedDate == null)?"<null>":this.lastModifiedDate));
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
        result = ((result* 31)+((this.cpe23Uri == null)? 0 :this.cpe23Uri.hashCode()));
        result = ((result* 31)+((this.cpe22Uri == null)? 0 :this.cpe22Uri.hashCode()));
        result = ((result* 31)+((this.lastModifiedDate == null)? 0 :this.lastModifiedDate.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof DefCpeName) == false) {
            return false;
        }
        DefCpeName rhs = ((DefCpeName) other);
        return ((((this.cpe23Uri == rhs.cpe23Uri)||((this.cpe23Uri!= null)&&this.cpe23Uri.equals(rhs.cpe23Uri)))&&((this.cpe22Uri == rhs.cpe22Uri)||((this.cpe22Uri!= null)&&this.cpe22Uri.equals(rhs.cpe22Uri))))&&((this.lastModifiedDate == rhs.lastModifiedDate)||((this.lastModifiedDate!= null)&&this.lastModifiedDate.equals(rhs.lastModifiedDate))));
    }

}
