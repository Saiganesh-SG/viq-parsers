package com.csw.data.mitre.jaxb.cwe;

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.ValidationEventHandler;
import javax.xml.bind.annotation.DomHandler;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

public class StructuredTextTypeHandler implements DomHandler<String, StreamResult> {
	
	private static final String XHTML_START_TAG = "<Extended_Description>";
    private static final String XHTML_END_TAG = "</Extended_Description>";

    private StringWriter xmlWriter = new StringWriter(); 

    public StreamResult createUnmarshaller(ValidationEventHandler errorHandler) {
        return new StreamResult(xmlWriter);
    }

    public String getElement(StreamResult rt) {
        String xml = rt.getWriter().toString();
        int beginIndex = xml.indexOf(XHTML_START_TAG) + XHTML_START_TAG.length();
        int endIndex = xml.indexOf(XHTML_END_TAG);
        return xml.substring(beginIndex, endIndex);
    }

    public Source marshal(String n, ValidationEventHandler errorHandler) {
        try {
            String xml = XHTML_START_TAG + n.trim() + XHTML_END_TAG;
            StringReader xmlReader = new StringReader(xml);
            return new StreamSource(xmlReader);
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

}
