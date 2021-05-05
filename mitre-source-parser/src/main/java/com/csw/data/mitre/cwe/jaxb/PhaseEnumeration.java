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
 * <p>Java class for PhaseEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="PhaseEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Policy"/>
 *     &lt;enumeration value="Requirements"/>
 *     &lt;enumeration value="Architecture and Design"/>
 *     &lt;enumeration value="Implementation"/>
 *     &lt;enumeration value="Build and Compilation"/>
 *     &lt;enumeration value="Testing"/>
 *     &lt;enumeration value="Documentation"/>
 *     &lt;enumeration value="Bundling"/>
 *     &lt;enumeration value="Distribution"/>
 *     &lt;enumeration value="Installation"/>
 *     &lt;enumeration value="System Configuration"/>
 *     &lt;enumeration value="Operation"/>
 *     &lt;enumeration value="Patching and Maintenance"/>
 *     &lt;enumeration value="Porting"/>
 *     &lt;enumeration value="Integration"/>
 *     &lt;enumeration value="Manufacturing"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "PhaseEnumeration")
@XmlEnum
public enum PhaseEnumeration {

    @XmlEnumValue("Policy")
    POLICY("Policy"),
    @XmlEnumValue("Requirements")
    REQUIREMENTS("Requirements"),
    @XmlEnumValue("Architecture and Design")
    ARCHITECTURE_AND_DESIGN("Architecture and Design"),
    @XmlEnumValue("Implementation")
    IMPLEMENTATION("Implementation"),
    @XmlEnumValue("Build and Compilation")
    BUILD_AND_COMPILATION("Build and Compilation"),
    @XmlEnumValue("Testing")
    TESTING("Testing"),
    @XmlEnumValue("Documentation")
    DOCUMENTATION("Documentation"),
    @XmlEnumValue("Bundling")
    BUNDLING("Bundling"),
    @XmlEnumValue("Distribution")
    DISTRIBUTION("Distribution"),
    @XmlEnumValue("Installation")
    INSTALLATION("Installation"),
    @XmlEnumValue("System Configuration")
    SYSTEM_CONFIGURATION("System Configuration"),
    @XmlEnumValue("Operation")
    OPERATION("Operation"),
    @XmlEnumValue("Patching and Maintenance")
    PATCHING_AND_MAINTENANCE("Patching and Maintenance"),
    @XmlEnumValue("Porting")
    PORTING("Porting"),
    @XmlEnumValue("Integration")
    INTEGRATION("Integration"),
    @XmlEnumValue("Manufacturing")
    MANUFACTURING("Manufacturing");
    private final String value;

    PhaseEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static PhaseEnumeration fromValue(String v) {
        for (PhaseEnumeration c: PhaseEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
