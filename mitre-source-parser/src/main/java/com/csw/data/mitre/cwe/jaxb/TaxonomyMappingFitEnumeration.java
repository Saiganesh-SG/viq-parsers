//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.mitre.cwe.jaxb;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for TaxonomyMappingFitEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="TaxonomyMappingFitEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Exact"/>
 *     &lt;enumeration value="CWE More Abstract"/>
 *     &lt;enumeration value="CWE More Specific"/>
 *     &lt;enumeration value="Imprecise"/>
 *     &lt;enumeration value="Perspective"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "TaxonomyMappingFitEnumeration")
@XmlEnum
public enum TaxonomyMappingFitEnumeration {

    @XmlEnumValue("Exact")
    EXACT("Exact"),
    @XmlEnumValue("CWE More Abstract")
    CWE_MORE_ABSTRACT("CWE More Abstract"),
    @XmlEnumValue("CWE More Specific")
    CWE_MORE_SPECIFIC("CWE More Specific"),
    @XmlEnumValue("Imprecise")
    IMPRECISE("Imprecise"),
    @XmlEnumValue("Perspective")
    PERSPECTIVE("Perspective");
    private final String value;

    TaxonomyMappingFitEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static TaxonomyMappingFitEnumeration fromValue(String v) {
        for (TaxonomyMappingFitEnumeration c: TaxonomyMappingFitEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
