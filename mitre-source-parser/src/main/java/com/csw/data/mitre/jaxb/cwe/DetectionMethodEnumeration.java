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
 * <p>Java class for DetectionMethodEnumeration.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="DetectionMethodEnumeration">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="Automated Analysis"/>
 *     &lt;enumeration value="Automated Dynamic Analysis"/>
 *     &lt;enumeration value="Automated Static Analysis"/>
 *     &lt;enumeration value="Automated Static Analysis - Source Code"/>
 *     &lt;enumeration value="Automated Static Analysis - Binary or Bytecode"/>
 *     &lt;enumeration value="Fuzzing"/>
 *     &lt;enumeration value="Manual Analysis"/>
 *     &lt;enumeration value="Manual Dynamic Analysis"/>
 *     &lt;enumeration value="Manual Static Analysis"/>
 *     &lt;enumeration value="Manual Static Analysis - Source Code"/>
 *     &lt;enumeration value="Manual Static Analysis - Binary or Bytecode"/>
 *     &lt;enumeration value="White Box"/>
 *     &lt;enumeration value="Black Box"/>
 *     &lt;enumeration value="Architecture or Design Review"/>
 *     &lt;enumeration value="Dynamic Analysis with Manual Results Interpretation"/>
 *     &lt;enumeration value="Dynamic Analysis with Automated Results Interpretation"/>
 *     &lt;enumeration value="Other"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "DetectionMethodEnumeration")
@XmlEnum
public enum DetectionMethodEnumeration {

    @XmlEnumValue("Automated Analysis")
    AUTOMATED_ANALYSIS("Automated Analysis"),
    @XmlEnumValue("Automated Dynamic Analysis")
    AUTOMATED_DYNAMIC_ANALYSIS("Automated Dynamic Analysis"),
    @XmlEnumValue("Automated Static Analysis")
    AUTOMATED_STATIC_ANALYSIS("Automated Static Analysis"),
    @XmlEnumValue("Automated Static Analysis - Source Code")
    AUTOMATED_STATIC_ANALYSIS_SOURCE_CODE("Automated Static Analysis - Source Code"),
    @XmlEnumValue("Automated Static Analysis - Binary or Bytecode")
    AUTOMATED_STATIC_ANALYSIS_BINARY_OR_BYTECODE("Automated Static Analysis - Binary or Bytecode"),
    @XmlEnumValue("Fuzzing")
    FUZZING("Fuzzing"),
    @XmlEnumValue("Manual Analysis")
    MANUAL_ANALYSIS("Manual Analysis"),
    @XmlEnumValue("Manual Dynamic Analysis")
    MANUAL_DYNAMIC_ANALYSIS("Manual Dynamic Analysis"),
    @XmlEnumValue("Manual Static Analysis")
    MANUAL_STATIC_ANALYSIS("Manual Static Analysis"),
    @XmlEnumValue("Manual Static Analysis - Source Code")
    MANUAL_STATIC_ANALYSIS_SOURCE_CODE("Manual Static Analysis - Source Code"),
    @XmlEnumValue("Manual Static Analysis - Binary or Bytecode")
    MANUAL_STATIC_ANALYSIS_BINARY_OR_BYTECODE("Manual Static Analysis - Binary or Bytecode"),
    @XmlEnumValue("White Box")
    WHITE_BOX("White Box"),
    @XmlEnumValue("Black Box")
    BLACK_BOX("Black Box"),
    @XmlEnumValue("Architecture or Design Review")
    ARCHITECTURE_OR_DESIGN_REVIEW("Architecture or Design Review"),
    @XmlEnumValue("Dynamic Analysis with Manual Results Interpretation")
    DYNAMIC_ANALYSIS_WITH_MANUAL_RESULTS_INTERPRETATION("Dynamic Analysis with Manual Results Interpretation"),
    @XmlEnumValue("Dynamic Analysis with Automated Results Interpretation")
    DYNAMIC_ANALYSIS_WITH_AUTOMATED_RESULTS_INTERPRETATION("Dynamic Analysis with Automated Results Interpretation"),
    @XmlEnumValue("Other")
    OTHER("Other");
    private final String value;

    DetectionMethodEnumeration(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static DetectionMethodEnumeration fromValue(String v) {
        for (DetectionMethodEnumeration c: DetectionMethodEnumeration.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

}
