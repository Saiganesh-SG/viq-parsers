//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.nvd.jaxb.cwe;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ScopeEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ScopeEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Confidentiality"/>
 *     &lt;enumeration value="Integrity"/>
 *     &lt;enumeration value="Availability"/>
 *     &lt;enumeration value="Access Control"/>
 *     &lt;enumeration value="Accountability"/>
 *     &lt;enumeration value="Authentication"/>
 *     &lt;enumeration value="Authorization"/>
 *     &lt;enumeration value="Non-Repudiation"/>
 *     &lt;enumeration value="Other"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ScopeEnumeration")
@XmlEnum
public enum ScopeEnumeration {

    @XmlEnumValue("Confidentiality")
    CONFIDENTIALITY("Confidentiality"),
    @XmlEnumValue("Integrity")
    INTEGRITY("Integrity"),
    @XmlEnumValue("Availability")
    AVAILABILITY("Availability"),
    @XmlEnumValue("Access Control")
    ACCESS_CONTROL("Access Control"),
    @XmlEnumValue("Accountability")
    ACCOUNTABILITY("Accountability"),
    @XmlEnumValue("Authentication")
    AUTHENTICATION("Authentication"),
    @XmlEnumValue("Authorization")
    AUTHORIZATION("Authorization"),
    @XmlEnumValue("Non-Repudiation")
    NON_REPUDIATION("Non-Repudiation"),
    @XmlEnumValue("Other")
    OTHER("Other");
    private final String value;

    ScopeEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ScopeEnumeration fromValue(String v) {
        for (ScopeEnumeration c: ScopeEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
