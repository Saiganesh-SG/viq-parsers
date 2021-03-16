package com.csw.data.nvd.json.source;

import java.util.ArrayList;
import java.util.List;
import javax.annotation.processing.Generated;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;


/**
 * Defines a node or sub-node in an NVD applicability statement.
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "operator",
    "negate",
    "children",
    "cpe_match"
})
@Generated("jsonschema2pojo")
public class DefNode {

    @JsonProperty("operator")
    private String operator;
    @JsonProperty("negate")
    private Boolean negate;
    @JsonProperty("children")
    private List<DefNode> children = new ArrayList<DefNode>();
    @JsonProperty("cpe_match")
    private List<DefCpeMatch> cpeMatch = new ArrayList<DefCpeMatch>();

    @JsonProperty("operator")
    public String getOperator() {
        return operator;
    }

    @JsonProperty("operator")
    public void setOperator(String operator) {
        this.operator = operator;
    }

    @JsonProperty("negate")
    public Boolean getNegate() {
        return negate;
    }

    @JsonProperty("negate")
    public void setNegate(Boolean negate) {
        this.negate = negate;
    }

    @JsonProperty("children")
    public List<DefNode> getChildren() {
        return children;
    }

    @JsonProperty("children")
    public void setChildren(List<DefNode> children) {
        this.children = children;
    }

    @JsonProperty("cpe_match")
    public List<DefCpeMatch> getCpeMatch() {
        return cpeMatch;
    }

    @JsonProperty("cpe_match")
    public void setCpeMatch(List<DefCpeMatch> cpeMatch) {
        this.cpeMatch = cpeMatch;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(DefNode.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("operator");
        sb.append('=');
        sb.append(((this.operator == null)?"<null>":this.operator));
        sb.append(',');
        sb.append("negate");
        sb.append('=');
        sb.append(((this.negate == null)?"<null>":this.negate));
        sb.append(',');
        sb.append("children");
        sb.append('=');
        sb.append(((this.children == null)?"<null>":this.children));
        sb.append(',');
        sb.append("cpeMatch");
        sb.append('=');
        sb.append(((this.cpeMatch == null)?"<null>":this.cpeMatch));
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
        result = ((result* 31)+((this.children == null)? 0 :this.children.hashCode()));
        result = ((result* 31)+((this.operator == null)? 0 :this.operator.hashCode()));
        result = ((result* 31)+((this.negate == null)? 0 :this.negate.hashCode()));
        result = ((result* 31)+((this.cpeMatch == null)? 0 :this.cpeMatch.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof DefNode) == false) {
            return false;
        }
        DefNode rhs = ((DefNode) other);
        return (((((this.children == rhs.children)||((this.children!= null)&&this.children.equals(rhs.children)))&&((this.operator == rhs.operator)||((this.operator!= null)&&this.operator.equals(rhs.operator))))&&((this.negate == rhs.negate)||((this.negate!= null)&&this.negate.equals(rhs.negate))))&&((this.cpeMatch == rhs.cpeMatch)||((this.cpeMatch!= null)&&this.cpeMatch.equals(rhs.cpeMatch))));
    }

}
