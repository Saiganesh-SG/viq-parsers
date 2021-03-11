
package com.csw.data.mitre.json.cwe;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "id",
    "section",
    "author",
    "title",
    "edition",
    "publication",
    "publisher",
    "publicationYear",
    "publicationMonth",
    "publicationDay",
    "url",
    "urlDate"
})
public class Reference {

    @JsonProperty("id")
    private String id;
    @JsonProperty("section")
    private String section;
    @JsonProperty("author")
    private List<String> author = null;
    @JsonProperty("title")
    private String title;
    @JsonProperty("edition")
    private String edition;
    @JsonProperty("publication")
    private String publication;
    @JsonProperty("publisher")
    private String publisher;
    @JsonProperty("publicationYear")
    private String publicationYear;
    @JsonProperty("publicationMonth")
    private String publicationMonth;
    @JsonProperty("publicationDay")
    private String publicationDay;
    @JsonProperty("url")
    private String url;
    @JsonProperty("urlDate")
    private String urlDate;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("section")
    public String getSection() {
        return section;
    }

    @JsonProperty("section")
    public void setSection(String section) {
        this.section = section;
    }

    @JsonProperty("author")
    public List<String> getAuthor() {
        return author;
    }

    @JsonProperty("author")
    public void setAuthor(List<String> author) {
        this.author = author;
    }

    @JsonProperty("title")
    public String getTitle() {
        return title;
    }

    @JsonProperty("title")
    public void setTitle(String title) {
        this.title = title;
    }

    @JsonProperty("edition")
    public String getEdition() {
        return edition;
    }

    @JsonProperty("edition")
    public void setEdition(String edition) {
        this.edition = edition;
    }

    @JsonProperty("publication")
    public String getPublication() {
        return publication;
    }

    @JsonProperty("publication")
    public void setPublication(String publication) {
        this.publication = publication;
    }

    @JsonProperty("publisher")
    public String getPublisher() {
        return publisher;
    }

    @JsonProperty("publisher")
    public void setPublisher(String publisher) {
        this.publisher = publisher;
    }

    @JsonProperty("publicationYear")
    public String getPublicationYear() {
        return publicationYear;
    }

    @JsonProperty("publicationYear")
    public void setPublicationYear(String publicationYear) {
        this.publicationYear = publicationYear;
    }

    @JsonProperty("publicationMonth")
    public String getPublicationMonth() {
        return publicationMonth;
    }

    @JsonProperty("publicationMonth")
    public void setPublicationMonth(String publicationMonth) {
        this.publicationMonth = publicationMonth;
    }

    @JsonProperty("publicationDay")
    public String getPublicationDay() {
        return publicationDay;
    }

    @JsonProperty("publicationDay")
    public void setPublicationDay(String publicationDay) {
        this.publicationDay = publicationDay;
    }

    @JsonProperty("url")
    public String getUrl() {
        return url;
    }

    @JsonProperty("url")
    public void setUrl(String url) {
        this.url = url;
    }

    @JsonProperty("urlDate")
    public String getUrlDate() {
        return urlDate;
    }

    @JsonProperty("urlDate")
    public void setUrlDate(String urlDate) {
        this.urlDate = urlDate;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
