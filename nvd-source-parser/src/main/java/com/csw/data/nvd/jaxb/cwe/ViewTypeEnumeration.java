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
 * <p>Java class for ViewTypeEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ViewTypeEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Implicit"/>
 *     &lt;enumeration value="Explicit"/>
 *     &lt;enumeration value="Graph"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ViewTypeEnumeration")
@XmlEnum
public enum ViewTypeEnumeration {

    @XmlEnumValue("Implicit")
    IMPLICIT("Implicit"),
    @XmlEnumValue("Explicit")
    EXPLICIT("Explicit"),
    @XmlEnumValue("Graph")
    GRAPH("Graph");
    private final String value;

    ViewTypeEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ViewTypeEnumeration fromValue(String v) {
        for (ViewTypeEnumeration c: ViewTypeEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
