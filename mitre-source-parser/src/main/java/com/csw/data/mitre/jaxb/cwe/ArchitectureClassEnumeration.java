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
 * <p>Java class for ArchitectureClassEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="ArchitectureClassEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Embedded"/>
 *     &lt;enumeration value="Microcomputer"/>
 *     &lt;enumeration value="Workstation"/>
 *     &lt;enumeration value="Architecture-Independent"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ArchitectureClassEnumeration")
@XmlEnum
public enum ArchitectureClassEnumeration {

    @XmlEnumValue("Embedded")
    EMBEDDED("Embedded"),
    @XmlEnumValue("Microcomputer")
    MICROCOMPUTER("Microcomputer"),
    @XmlEnumValue("Workstation")
    WORKSTATION("Workstation"),
    @XmlEnumValue("Architecture-Independent")
    ARCHITECTURE_INDEPENDENT("Architecture-Independent");
    private final String value;

    ArchitectureClassEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static ArchitectureClassEnumeration fromValue(String v) {
        for (ArchitectureClassEnumeration c: ArchitectureClassEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
