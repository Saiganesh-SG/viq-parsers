//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.mitre.jaxb.cwe;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlEnumValue;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for OrdinalityEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="OrdinalityEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Indirect"/>
 *     &lt;enumeration value="Primary"/>
 *     &lt;enumeration value="Resultant"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "OrdinalityEnumeration")
@XmlEnum
public enum OrdinalityEnumeration {

    @XmlEnumValue("Indirect")
    INDIRECT("Indirect"),
    @XmlEnumValue("Primary")
    PRIMARY("Primary"),
    @XmlEnumValue("Resultant")
    RESULTANT("Resultant");
    private final String value;

    OrdinalityEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static OrdinalityEnumeration fromValue(String v) {
        for (OrdinalityEnumeration c: OrdinalityEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
