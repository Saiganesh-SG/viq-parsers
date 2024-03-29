//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.mitre.cwe.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The WeaknessOrdinalitiesType complex type indicates potential ordering relationships with other weaknesses. The required Ordinality element identifies whether the weakness has a primary, resultant, or indirect relationship. The optional Description contains the context in which the relationship exists. It is important to note that it is possible for the same entry to be primary in some instances and resultant in others.
 * 
 * <p>Java class for WeaknessOrdinalitiesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="WeaknessOrdinalitiesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Weakness_Ordinality" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Ordinality" type="{http://cwe.mitre.org/cwe-6}OrdinalityEnumeration"/>
 *                   &lt;element name="Description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
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
@XmlType(name = "WeaknessOrdinalitiesType", propOrder = {
    "weaknessOrdinality"
})
public class WeaknessOrdinalitiesType {

    @XmlElement(name = "Weakness_Ordinality", required = true)
    protected List<WeaknessOrdinalitiesType.WeaknessOrdinality> weaknessOrdinality;

    /**
     * Gets the value of the weaknessOrdinality property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the weaknessOrdinality property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getWeaknessOrdinality().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link WeaknessOrdinalitiesType.WeaknessOrdinality }
     * 
     * 
     */
    public List<WeaknessOrdinalitiesType.WeaknessOrdinality> getWeaknessOrdinality() {
        if (weaknessOrdinality == null) {
            weaknessOrdinality = new ArrayList<WeaknessOrdinalitiesType.WeaknessOrdinality>();
        }
        return this.weaknessOrdinality;
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
     *         &lt;element name="Ordinality" type="{http://cwe.mitre.org/cwe-6}OrdinalityEnumeration"/>
     *         &lt;element name="Description" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
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
        "ordinality",
        "description"
    })
    public static class WeaknessOrdinality {

        @XmlElement(name = "Ordinality", required = true)
        @XmlSchemaType(name = "string")
        protected OrdinalityEnumeration ordinality;
        @XmlElement(name = "Description")
        protected String description;

        /**
         * Gets the value of the ordinality property.
         * 
         * @return
         *     possible object is
         *     {@link OrdinalityEnumeration }
         *     
         */
        public OrdinalityEnumeration getOrdinality() {
            return ordinality;
        }

        /**
         * Sets the value of the ordinality property.
         * 
         * @param value
         *     allowed object is
         *     {@link OrdinalityEnumeration }
         *     
         */
        public void setOrdinality(OrdinalityEnumeration value) {
            this.ordinality = value;
        }

        /**
         * Gets the value of the description property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getDescription() {
            return description;
        }

        /**
         * Sets the value of the description property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setDescription(String value) {
            this.description = value;
        }

    }

}
