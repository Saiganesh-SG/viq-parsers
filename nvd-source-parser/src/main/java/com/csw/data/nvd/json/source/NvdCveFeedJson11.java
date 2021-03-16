package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * JSON Schema for NVD Vulnerability Data Feed version 1.1
 * <p>
 * 
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "CVE_data_type",
    "CVE_data_format",
    "CVE_data_version",
    "CVE_data_numberOfCVEs",
    "CVE_data_timestamp",
    "CVE_Items"
})
@Generated("jsonschema2pojo")
public class NvdCveFeedJson11 {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("CVE_data_type")
    private String cVEDataType;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("CVE_data_format")
    private String cVEDataFormat;
    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("CVE_data_version")
    private String cVEDataVersion;
    /**
     * NVD adds number of CVE in this feed
     * 
     */
    @JsonProperty("CVE_data_numberOfCVEs")
    @JsonPropertyDescription("NVD adds number of CVE in this feed")
    private String cVEDataNumberOfCVEs;
    /**
     * NVD adds feed date timestamp
     * 
     */
    @JsonProperty("CVE_data_timestamp")
    @JsonPropertyDescription("NVD adds feed date timestamp")
    private String cVEDataTimestamp;
    /**
     * NVD feed array of CVE
     * (Required)
     * 
     */
    @JsonProperty("CVE_Items")
    @JsonPropertyDescription("NVD feed array of CVE")
    private List<DefCveItem> cVEItems = new ArrayList<DefCveItem>();

    @JsonProperty("CVE_data_type")
    public String getCVEDataType() {
        return cVEDataType;
    }

    @JsonProperty("CVE_data_type")
    public void setCVEDataType(String cVEDataType) {
        this.cVEDataType = cVEDataType;
    }

    @JsonProperty("CVE_data_format")
    public String getCVEDataFormat() {
        return cVEDataFormat;
    }

    @JsonProperty("CVE_data_format")
    public void setCVEDataFormat(String cVEDataFormat) {
        this.cVEDataFormat = cVEDataFormat;
    }

    @JsonProperty("CVE_data_version")
    public String getCVEDataVersion() {
        return cVEDataVersion;
    }

    @JsonProperty("CVE_data_version")
    public void setCVEDataVersion(String cVEDataVersion) {
        this.cVEDataVersion = cVEDataVersion;
    }

    /**
     * NVD adds number of CVE in this feed
     * 
     */
    @JsonProperty("CVE_data_numberOfCVEs")
    public String getCVEDataNumberOfCVEs() {
        return cVEDataNumberOfCVEs;
    }

    /**
     * NVD adds number of CVE in this feed
     * 
     */
    @JsonProperty("CVE_data_numberOfCVEs")
    public void setCVEDataNumberOfCVEs(String cVEDataNumberOfCVEs) {
        this.cVEDataNumberOfCVEs = cVEDataNumberOfCVEs;
    }

    /**
     * NVD adds feed date timestamp
     * 
     */
    @JsonProperty("CVE_data_timestamp")
    public String getCVEDataTimestamp() {
        return cVEDataTimestamp;
    }

    /**
     * NVD adds feed date timestamp
     * 
     */
    @JsonProperty("CVE_data_timestamp")
    public void setCVEDataTimestamp(String cVEDataTimestamp) {
        this.cVEDataTimestamp = cVEDataTimestamp;
    }

    /**
     * NVD feed array of CVE
     * 
     */
    @JsonProperty("CVE_Items")
    public List<DefCveItem> getCVEItems() {
        return cVEItems;
    }

    /**
     * NVD feed array of CVE
     * 
     */
    @JsonProperty("CVE_Items")
    public void setCVEItems(List<DefCveItem> cVEItems) {
        this.cVEItems = cVEItems;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(NvdCveFeedJson11 .class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("cVEDataType");
        sb.append('=');
        sb.append(((this.cVEDataType == null)?"<null>":this.cVEDataType));
        sb.append(',');
        sb.append("cVEDataFormat");
        sb.append('=');
        sb.append(((this.cVEDataFormat == null)?"<null>":this.cVEDataFormat));
        sb.append(',');
        sb.append("cVEDataVersion");
        sb.append('=');
        sb.append(((this.cVEDataVersion == null)?"<null>":this.cVEDataVersion));
        sb.append(',');
        sb.append("cVEDataNumberOfCVEs");
        sb.append('=');
        sb.append(((this.cVEDataNumberOfCVEs == null)?"<null>":this.cVEDataNumberOfCVEs));
        sb.append(',');
        sb.append("cVEDataTimestamp");
        sb.append('=');
        sb.append(((this.cVEDataTimestamp == null)?"<null>":this.cVEDataTimestamp));
        sb.append(',');
        sb.append("cVEItems");
        sb.append('=');
        sb.append(((this.cVEItems == null)?"<null>":this.cVEItems));
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
        result = ((result* 31)+((this.cVEDataNumberOfCVEs == null)? 0 :this.cVEDataNumberOfCVEs.hashCode()));
        result = ((result* 31)+((this.cVEDataFormat == null)? 0 :this.cVEDataFormat.hashCode()));
        result = ((result* 31)+((this.cVEDataTimestamp == null)? 0 :this.cVEDataTimestamp.hashCode()));
        result = ((result* 31)+((this.cVEDataType == null)? 0 :this.cVEDataType.hashCode()));
        result = ((result* 31)+((this.cVEItems == null)? 0 :this.cVEItems.hashCode()));
        result = ((result* 31)+((this.cVEDataVersion == null)? 0 :this.cVEDataVersion.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof NvdCveFeedJson11) == false) {
            return false;
        }
        NvdCveFeedJson11 rhs = ((NvdCveFeedJson11) other);
        return (((((((this.cVEDataNumberOfCVEs == rhs.cVEDataNumberOfCVEs)||((this.cVEDataNumberOfCVEs!= null)&&this.cVEDataNumberOfCVEs.equals(rhs.cVEDataNumberOfCVEs)))&&((this.cVEDataFormat == rhs.cVEDataFormat)||((this.cVEDataFormat!= null)&&this.cVEDataFormat.equals(rhs.cVEDataFormat))))&&((this.cVEDataTimestamp == rhs.cVEDataTimestamp)||((this.cVEDataTimestamp!= null)&&this.cVEDataTimestamp.equals(rhs.cVEDataTimestamp))))&&((this.cVEDataType == rhs.cVEDataType)||((this.cVEDataType!= null)&&this.cVEDataType.equals(rhs.cVEDataType))))&&((this.cVEItems == rhs.cVEItems)||((this.cVEItems!= null)&&this.cVEItems.equals(rhs.cVEItems))))&&((this.cVEDataVersion == rhs.cVEDataVersion)||((this.cVEDataVersion!= null)&&this.cVEDataVersion.equals(rhs.cVEDataVersion))));
    }

}
