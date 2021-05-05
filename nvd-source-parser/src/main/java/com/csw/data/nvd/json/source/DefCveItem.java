package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * Defines a vulnerability in the NVD data feed.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "cve",
    "configurations",
    "impact",
    "publishedDate",
    "lastModifiedDate"
})
@Generated("jsonschema2pojo")
public class DefCveItem {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cve")
    private CVEJSON40Min11 cve;
    /**
     * Defines the set of product configurations for a NVD applicability statement.
     * 
     */
    @JsonProperty("configurations")
    @JsonPropertyDescription("Defines the set of product configurations for a NVD applicability statement.")
    private DefConfigurations configurations;
    /**
     * Impact scores for a vulnerability as found on NVD.
     * 
     */
    @JsonProperty("impact")
    @JsonPropertyDescription("Impact scores for a vulnerability as found on NVD.")
    private DefImpact impact;
    @JsonProperty("publishedDate")
    private String publishedDate;
    @JsonProperty("lastModifiedDate")
    private String lastModifiedDate;

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cve")
    public CVEJSON40Min11 getCve() {
        return cve;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("cve")
    public void setCve(CVEJSON40Min11 cve) {
        this.cve = cve;
    }

    /**
     * Defines the set of product configurations for a NVD applicability statement.
     * 
     */
    @JsonProperty("configurations")
    public DefConfigurations getConfigurations() {
        return configurations;
    }

    /**
     * Defines the set of product configurations for a NVD applicability statement.
     * 
     */
    @JsonProperty("configurations")
    public void setConfigurations(DefConfigurations configurations) {
        this.configurations = configurations;
    }

    /**
     * Impact scores for a vulnerability as found on NVD.
     * 
     */
    @JsonProperty("impact")
    public DefImpact getImpact() {
        return impact;
    }

    /**
     * Impact scores for a vulnerability as found on NVD.
     * 
     */
    @JsonProperty("impact")
    public void setImpact(DefImpact impact) {
        this.impact = impact;
    }

    @JsonProperty("publishedDate")
    public String getPublishedDate() {
        return publishedDate;
    }

    @JsonProperty("publishedDate")
    public void setPublishedDate(String publishedDate) {
        this.publishedDate = publishedDate;
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
        sb.append(DefCveItem.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cve");
        sb.append('=');
        sb.append(((this.cve == null)?"<null>":this.cve));
        sb.append(',');
        sb.append("configurations");
        sb.append('=');
        sb.append(((this.configurations == null)?"<null>":this.configurations));
        sb.append(',');
        sb.append("impact");
        sb.append('=');
        sb.append(((this.impact == null)?"<null>":this.impact));
        sb.append(',');
        sb.append("publishedDate");
        sb.append('=');
        sb.append(((this.publishedDate == null)?"<null>":this.publishedDate));
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
        result = ((result* 31)+((this.cve == null)? 0 :this.cve.hashCode()));
        result = ((result* 31)+((this.publishedDate == null)? 0 :this.publishedDate.hashCode()));
        result = ((result* 31)+((this.lastModifiedDate == null)? 0 :this.lastModifiedDate.hashCode()));
        result = ((result* 31)+((this.configurations == null)? 0 :this.configurations.hashCode()));
        result = ((result* 31)+((this.impact == null)? 0 :this.impact.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof DefCveItem) == false) {
            return false;
        }
        DefCveItem rhs = ((DefCveItem) other);
        return ((((((this.cve == rhs.cve)||((this.cve!= null)&&this.cve.equals(rhs.cve)))&&((this.publishedDate == rhs.publishedDate)||((this.publishedDate!= null)&&this.publishedDate.equals(rhs.publishedDate))))&&((this.lastModifiedDate == rhs.lastModifiedDate)||((this.lastModifiedDate!= null)&&this.lastModifiedDate.equals(rhs.lastModifiedDate))))&&((this.configurations == rhs.configurations)||((this.configurations!= null)&&this.configurations.equals(rhs.configurations))))&&((this.impact == rhs.impact)||((this.impact!= null)&&this.impact.equals(rhs.impact))));
    }

}
