package com.csw.data.nvd.json.source;

import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * Impact scores for a vulnerability as found on NVD.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "baseMetricV3",
    "baseMetricV2"
})
@Generated("jsonschema2pojo")
public class DefImpact {

    /**
     * CVSS V3.x score.
     * 
     */
    @JsonProperty("baseMetricV3")
    @JsonPropertyDescription("CVSS V3.x score.")
    private BaseMetricV3 baseMetricV3;
    /**
     * CVSS V2.0 score.
     * 
     */
    @JsonProperty("baseMetricV2")
    @JsonPropertyDescription("CVSS V2.0 score.")
    private BaseMetricV2 baseMetricV2;

    /**
     * CVSS V3.x score.
     * 
     */
    @JsonProperty("baseMetricV3")
    public BaseMetricV3 getBaseMetricV3() {
        return baseMetricV3;
    }

    /**
     * CVSS V3.x score.
     * 
     */
    @JsonProperty("baseMetricV3")
    public void setBaseMetricV3(BaseMetricV3 baseMetricV3) {
        this.baseMetricV3 = baseMetricV3;
    }

    /**
     * CVSS V2.0 score.
     * 
     */
    @JsonProperty("baseMetricV2")
    public BaseMetricV2 getBaseMetricV2() {
        return baseMetricV2;
    }

    /**
     * CVSS V2.0 score.
     * 
     */
    @JsonProperty("baseMetricV2")
    public void setBaseMetricV2(BaseMetricV2 baseMetricV2) {
        this.baseMetricV2 = baseMetricV2;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(DefImpact.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("baseMetricV3");
        sb.append('=');
        sb.append(((this.baseMetricV3 == null)?"<null>":this.baseMetricV3));
        sb.append(',');
        sb.append("baseMetricV2");
        sb.append('=');
        sb.append(((this.baseMetricV2 == null)?"<null>":this.baseMetricV2));
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
        result = ((result* 31)+((this.baseMetricV2 == null)? 0 :this.baseMetricV2 .hashCode()));
        result = ((result* 31)+((this.baseMetricV3 == null)? 0 :this.baseMetricV3 .hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof DefImpact) == false) {
            return false;
        }
        DefImpact rhs = ((DefImpact) other);
        return (((this.baseMetricV2 == rhs.baseMetricV2)||((this.baseMetricV2 != null)&&this.baseMetricV2 .equals(rhs.baseMetricV2)))&&((this.baseMetricV3 == rhs.baseMetricV3)||((this.baseMetricV3 != null)&&this.baseMetricV3 .equals(rhs.baseMetricV3))));
    }

}
