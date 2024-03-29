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
 * <p>Java class for TechnologyClassEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="TechnologyClassEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Client Server"/>
 *     &lt;enumeration value="Cloud Computing"/>
 *     &lt;enumeration value="Mainframe"/>
 *     &lt;enumeration value="Mobile"/>
 *     &lt;enumeration value="N-Tier"/>
 *     &lt;enumeration value="SOA"/>
 *     &lt;enumeration value="System on Chip"/>
 *     &lt;enumeration value="Web Based"/>
 *     &lt;enumeration value="Technology-Independent"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "TechnologyClassEnumeration")
@XmlEnum
public enum TechnologyClassEnumeration {


    /**
     * Represents technology involving a distributed application but for the purposes of CWE does not leverage a web browser.
     * 
     */
    @XmlEnumValue("Client Server")
    CLIENT_SERVER("Client Server"),

    /**
     * Represents technology that involves data storage and computing power being made available to multiple users via the internet instead of using local systems, without the need for users to perform all system management themselves.
     * 
     */
    @XmlEnumValue("Cloud Computing")
    CLOUD_COMPUTING("Cloud Computing"),
    @XmlEnumValue("Mainframe")
    MAINFRAME("Mainframe"),
    @XmlEnumValue("Mobile")
    MOBILE("Mobile"),
    @XmlEnumValue("N-Tier")
    N_TIER("N-Tier"),
    SOA("SOA"),

    /**
     * Represents technology that integrates all components of a computer within a single integrated circuit, to include FPGA and ASIC.
     * 
     */
    @XmlEnumValue("System on Chip")
    SYSTEM_ON_CHIP("System on Chip"),

    /**
     * Represents technology that involves applications or single-page sites that leverage a web browser to support client interactions.
     * 
     */
    @XmlEnumValue("Web Based")
    WEB_BASED("Web Based"),

    /**
     * Used to associate with all classes of technologies.
     * 
     */
    @XmlEnumValue("Technology-Independent")
    TECHNOLOGY_INDEPENDENT("Technology-Independent");
    private final String value;

    TechnologyClassEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static TechnologyClassEnumeration fromValue(String v) {
        for (TechnologyClassEnumeration c: TechnologyClassEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
