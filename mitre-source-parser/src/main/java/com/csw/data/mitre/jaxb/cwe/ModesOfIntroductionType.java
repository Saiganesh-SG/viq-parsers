//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.mitre.jaxb.cwe;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The ModeOfIntroductionType complex type is used to provide information about how and when a given weakness may be introduced. If there are multiple possible introduction points, then a separate Introduction element should be included for each. The required Phase element identifies the point in the product life cycle at which the weakness may be introduced. The optional Note element identifies the typical scenarios under which the weakness may be introduced during the given phase.
 * 
 * <p>Java class for ModesOfIntroductionType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ModesOfIntroductionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Introduction" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Phase" type="{http://cwe.mitre.org/cwe-6}PhaseEnumeration"/>
 *                   &lt;element name="Note" type="{http://cwe.mitre.org/cwe-6}StructuredTextType" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ModesOfIntroductionType", propOrder = {
    "introduction"
})
public class ModesOfIntroductionType {

    @XmlElement(name = "Introduction", required = true)
    protected List<ModesOfIntroductionType.Introduction> introduction;

    /**
     * Gets the value of the introduction property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the introduction property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIntroduction().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ModesOfIntroductionType.Introduction }
     * 
     * 
     */
    public List<ModesOfIntroductionType.Introduction> getIntroduction() {
        if (introduction == null) {
            introduction = new ArrayList<ModesOfIntroductionType.Introduction>();
        }
        return this.introduction;
    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;complexContent>
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
     *       &lt;sequence>
     *         &lt;element name="Phase" type="{http://cwe.mitre.org/cwe-6}PhaseEnumeration"/>
     *         &lt;element name="Note" type="{http://cwe.mitre.org/cwe-6}StructuredTextType" minOccurs="0"/>
     *       &lt;/sequence>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "phase",
        "note"
    })
    public static class Introduction {

        @XmlElement(name = "Phase", required = true)
        @XmlSchemaType(name = "string")
        protected PhaseEnumeration phase;
        @XmlElement(name = "Note")
        protected StructuredTextType note;

        /**
         * Gets the value of the phase property.
         * 
         * @return
         *     possible object is
         *     {@link PhaseEnumeration }
         *     
         */
        public PhaseEnumeration getPhase() {
            return phase;
        }

        /**
         * Sets the value of the phase property.
         * 
         * @param value
         *     allowed object is
         *     {@link PhaseEnumeration }
         *     
         */
        public void setPhase(PhaseEnumeration value) {
            this.phase = value;
        }

        /**
         * Gets the value of the note property.
         * 
         * @return
         *     possible object is
         *     {@link StructuredTextType }
         *     
         */
        public StructuredTextType getNote() {
            return note;
        }

        /**
         * Sets the value of the note property.
         * 
         * @param value
         *     allowed object is
         *     {@link StructuredTextType }
         *     
         */
        public void setNote(StructuredTextType value) {
            this.note = value;
        }

    }

}
