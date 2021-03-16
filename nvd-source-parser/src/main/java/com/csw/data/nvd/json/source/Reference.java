package com.csw.data.nvd.json.source;

import java.util.List;

import javax.annotation.processing.Generated;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "url",
    "name",
    "refsource"
})
@Generated("jsonschema2pojo")
public class Reference {

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("url")
    private String url;
    @JsonProperty("name")
    private String name;
    @JsonProperty("refsource")
    private String refsource;
    @JsonIgnore
    private List<String> tags;

	/**
     * 
     * (Required)
     * 
     */
    @JsonProperty("url")
    public String getUrl() {
        return url;
    }

    /**
     * 
     * (Required)
     * 
     */
    @JsonProperty("url")
    public void setUrl(String url) {
        this.url = url;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("refsource")
    public String getRefsource() {
        return refsource;
    }

    @JsonProperty("refsource")
    public void setRefsource(String refsource) {
        this.refsource = refsource;
    }
    
    @JsonProperty("tags")
    public List<String> getTags() {
		return tags;
	}

    @JsonProperty("tags")
	public void setTags(List<String> tags) {
		this.tags = tags;
	}

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(Reference.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("url");
        sb.append('=');
        sb.append(((this.url == null)?"<null>":this.url));
        sb.append(',');
        sb.append("name");
        sb.append('=');
        sb.append(((this.name == null)?"<null>":this.name));
        sb.append(',');
        sb.append("refsource");
        sb.append('=');
        sb.append(((this.refsource == null)?"<null>":this.refsource));
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
        result = ((result* 31)+((this.name == null)? 0 :this.name.hashCode()));
        result = ((result* 31)+((this.refsource == null)? 0 :this.refsource.hashCode()));
        result = ((result* 31)+((this.url == null)? 0 :this.url.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof Reference) == false) {
            return false;
        }
        Reference rhs = ((Reference) other);
        return ((((this.name == rhs.name)||((this.name!= null)&&this.name.equals(rhs.name)))&&((this.refsource == rhs.refsource)||((this.refsource!= null)&&this.refsource.equals(rhs.refsource))))&&((this.url == rhs.url)||((this.url!= null)&&this.url.equals(rhs.url))));
    }

}
