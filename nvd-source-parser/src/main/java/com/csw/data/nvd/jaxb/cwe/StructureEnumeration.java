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
 * <p>Java class for StructureEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="StructureEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Chain"/>
 *     &lt;enumeration value="Composite"/>
 *     &lt;enumeration value="Simple"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "StructureEnumeration")
@XmlEnum
public enum StructureEnumeration {

    @XmlEnumValue("Chain")
    CHAIN("Chain"),
    @XmlEnumValue("Composite")
    COMPOSITE("Composite"),
    @XmlEnumValue("Simple")
    SIMPLE("Simple");
    private final String value;

    StructureEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static StructureEnumeration fromValue(String v) {
        for (StructureEnumeration c: StructureEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
