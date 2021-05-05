package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * CPE match string or range
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "vulnerable",
    "cpe22Uri",
    "cpe23Uri",
    "versionStartExcluding",
    "versionStartIncluding",
    "versionEndExcluding",
    "versionEndIncluding",
    "cpe_name"
})
@Generated("jsonschema2pojo")
public class DefCpeMatch {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("vulnerable")
    private Boolean vulnerable;
    @JsonProperty("cpe22Uri")
    private String cpe22Uri;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cpe23Uri")
    private String cpe23Uri;
    @JsonProperty("versionStartExcluding")
    private String versionStartExcluding;
    @JsonProperty("versionStartIncluding")
    private String versionStartIncluding;
    @JsonProperty("versionEndExcluding")
    private String versionEndExcluding;
    @JsonProperty("versionEndIncluding")
    private String versionEndIncluding;
    @JsonProperty("cpe_name")
    private List<DefCpeName> cpeName = new ArrayList<DefCpeName>();

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("vulnerable")
    public Boolean getVulnerable() {
        return vulnerable;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("vulnerable")
    public void setVulnerable(Boolean vulnerable) {
        this.vulnerable = vulnerable;
    }

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

    @JsonProperty("versionStartExcluding")
    public String getVersionStartExcluding() {
        return versionStartExcluding;
    }

    @JsonProperty("versionStartExcluding")
    public void setVersionStartExcluding(String versionStartExcluding) {
        this.versionStartExcluding = versionStartExcluding;
    }

    @JsonProperty("versionStartIncluding")
    public String getVersionStartIncluding() {
        return versionStartIncluding;
    }

    @JsonProperty("versionStartIncluding")
    public void setVersionStartIncluding(String versionStartIncluding) {
        this.versionStartIncluding = versionStartIncluding;
    }

    @JsonProperty("versionEndExcluding")
    public String getVersionEndExcluding() {
        return versionEndExcluding;
    }

    @JsonProperty("versionEndExcluding")
    public void setVersionEndExcluding(String versionEndExcluding) {
        this.versionEndExcluding = versionEndExcluding;
    }

    @JsonProperty("versionEndIncluding")
    public String getVersionEndIncluding() {
        return versionEndIncluding;
    }

    @JsonProperty("versionEndIncluding")
    public void setVersionEndIncluding(String versionEndIncluding) {
        this.versionEndIncluding = versionEndIncluding;
    }

    @JsonProperty("cpe_name")
    public List<DefCpeName> getCpeName() {
        return cpeName;
    }

    @JsonProperty("cpe_name")
    public void setCpeName(List<DefCpeName> cpeName) {
        this.cpeName = cpeName;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(DefCpeMatch.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("vulnerable");
        sb.append('=');
        sb.append(((this.vulnerable == null)?"<null>":this.vulnerable));
        sb.append(',');
        sb.append("cpe22Uri");
        sb.append('=');
        sb.append(((this.cpe22Uri == null)?"<null>":this.cpe22Uri));
        sb.append(',');
        sb.append("cpe23Uri");
        sb.append('=');
        sb.append(((this.cpe23Uri == null)?"<null>":this.cpe23Uri));
        sb.append(',');
        sb.append("versionStartExcluding");
        sb.append('=');
        sb.append(((this.versionStartExcluding == null)?"<null>":this.versionStartExcluding));
        sb.append(',');
        sb.append("versionStartIncluding");
        sb.append('=');
        sb.append(((this.versionStartIncluding == null)?"<null>":this.versionStartIncluding));
        sb.append(',');
        sb.append("versionEndExcluding");
        sb.append('=');
        sb.append(((this.versionEndExcluding == null)?"<null>":this.versionEndExcluding));
        sb.append(',');
        sb.append("versionEndIncluding");
        sb.append('=');
        sb.append(((this.versionEndIncluding == null)?"<null>":this.versionEndIncluding));
        sb.append(',');
        sb.append("cpeName");
        sb.append('=');
        sb.append(((this.cpeName == null)?"<null>":this.cpeName));
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
        result = ((result* 31)+((this.vulnerable == null)? 0 :this.vulnerable.hashCode()));
        result = ((result* 31)+((this.cpe23Uri == null)? 0 :this.cpe23Uri.hashCode()));
        result = ((result* 31)+((this.versionStartExcluding == null)? 0 :this.versionStartExcluding.hashCode()));
        result = ((result* 31)+((this.cpe22Uri == null)? 0 :this.cpe22Uri.hashCode()));
        result = ((result* 31)+((this.versionEndExcluding == null)? 0 :this.versionEndExcluding.hashCode()));
        result = ((result* 31)+((this.cpeName == null)? 0 :this.cpeName.hashCode()));
        result = ((result* 31)+((this.versionEndIncluding == null)? 0 :this.versionEndIncluding.hashCode()));
        result = ((result* 31)+((this.versionStartIncluding == null)? 0 :this.versionStartIncluding.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof DefCpeMatch) == false) {
            return false;
        }
        DefCpeMatch rhs = ((DefCpeMatch) other);
        return (((((((((this.vulnerable == rhs.vulnerable)||((this.vulnerable!= null)&&this.vulnerable.equals(rhs.vulnerable)))&&((this.cpe23Uri == rhs.cpe23Uri)||((this.cpe23Uri!= null)&&this.cpe23Uri.equals(rhs.cpe23Uri))))&&((this.versionStartExcluding == rhs.versionStartExcluding)||((this.versionStartExcluding!= null)&&this.versionStartExcluding.equals(rhs.versionStartExcluding))))&&((this.cpe22Uri == rhs.cpe22Uri)||((this.cpe22Uri!= null)&&this.cpe22Uri.equals(rhs.cpe22Uri))))&&((this.versionEndExcluding == rhs.versionEndExcluding)||((this.versionEndExcluding!= null)&&this.versionEndExcluding.equals(rhs.versionEndExcluding))))&&((this.cpeName == rhs.cpeName)||((this.cpeName!= null)&&this.cpeName.equals(rhs.cpeName))))&&((this.versionEndIncluding == rhs.versionEndIncluding)||((this.versionEndIncluding!= null)&&this.versionEndIncluding.equals(rhs.versionEndIncluding))))&&((this.versionStartIncluding == rhs.versionStartIncluding)||((this.versionStartIncluding!= null)&&this.versionStartIncluding.equals(rhs.versionStartIncluding))));
    }

}
