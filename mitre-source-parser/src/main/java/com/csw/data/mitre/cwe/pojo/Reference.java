package com.csw.data.mitre.cwe.pojo;

import java.util.List;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Reference {
	public String id;
    public String section;
    public List<String> author;
    public String title;
    public String edition;
    public String publication;
    public String publisher;
    public String publicationYear;
    public String publicationMonth;
    public String publicationDay;
    public String url;
    public String urlDate;
}
