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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The optional Consequence_ID attribute is used by the internal CWE team to uniquely identify examples that are repeated across any number of individual weaknesses. To help make sure that the details of these common examples stay synchronized, the Consequence_ID is used to quickly identify those examples across CWE that should be identical. The identifier is a string and should match the following format: CC-1.
 * 
 * <p>Java class for CommonConsequencesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CommonConsequencesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Consequence" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Scope" type="{http://cwe.mitre.org/cwe-6}ScopeEnumeration" maxOccurs="unbounded"/>
 *                   &lt;element name="Impact" type="{http://cwe.mitre.org/cwe-6}TechnicalImpactEnumeration" maxOccurs="unbounded" minOccurs="0"/>
 *                   &lt;element name="Likelihood" type="{http://cwe.mitre.org/cwe-6}LikelihoodEnumeration" minOccurs="0"/>
 *                   &lt;element name="Note" type="{http://cwe.mitre.org/cwe-6}StructuredTextType" minOccurs="0"/>
 *                 &lt;/sequence>
 *                 &lt;attribute name="Consequence_ID" type="{http://www.w3.org/2001/XMLSchema}string" />
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
@XmlType(name = "CommonConsequencesType", propOrder = {
    "consequence"
})
public class CommonConsequencesType {

    @XmlElement(name = "Consequence", required = true)
    protected List<CommonConsequencesType.Consequence> consequence;

    /**
     * Gets the value of the consequence property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the consequence property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getConsequence().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link CommonConsequencesType.Consequence }
     * 
     * 
     */
    public List<CommonConsequencesType.Consequence> getConsequence() {
        if (consequence == null) {
            consequence = new ArrayList<CommonConsequencesType.Consequence>();
        }
        return this.consequence;
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
     *         &lt;element name="Scope" type="{http://cwe.mitre.org/cwe-6}ScopeEnumeration" maxOccurs="unbounded"/>
     *         &lt;element name="Impact" type="{http://cwe.mitre.org/cwe-6}TechnicalImpactEnumeration" maxOccurs="unbounded" minOccurs="0"/>
     *         &lt;element name="Likelihood" type="{http://cwe.mitre.org/cwe-6}LikelihoodEnumeration" minOccurs="0"/>
     *         &lt;element name="Note" type="{http://cwe.mitre.org/cwe-6}StructuredTextType" minOccurs="0"/>
     *       &lt;/sequence>
     *       &lt;attribute name="Consequence_ID" type="{http://www.w3.org/2001/XMLSchema}string" />
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "scope",
        "impact",
        "likelihood",
        "note"
    })
    public static class Consequence {

        @XmlElement(name = "Scope", required = true)
        @XmlSchemaType(name = "string")
        protected List<ScopeEnumeration> scope;
        @XmlElement(name = "Impact")
        @XmlSchemaType(name = "string")
        protected List<TechnicalImpactEnumeration> impact;
        @XmlElement(name = "Likelihood")
        @XmlSchemaType(name = "string")
        protected LikelihoodEnumeration likelihood;
        @XmlElement(name = "Note")
        protected StructuredTextType note;
        @XmlAttribute(name = "Consequence_ID")
        protected String consequenceID;

        /**
         * Gets the value of the scope property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the scope property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getScope().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link ScopeEnumeration }
         * 
         * 
         */
        public List<ScopeEnumeration> getScope() {
            if (scope == null) {
                scope = new ArrayList<ScopeEnumeration>();
            }
            return this.scope;
        }

        /**
         * Gets the value of the impact property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the impact property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getImpact().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link TechnicalImpactEnumeration }
         * 
         * 
         */
        public List<TechnicalImpactEnumeration> getImpact() {
            if (impact == null) {
                impact = new ArrayList<TechnicalImpactEnumeration>();
            }
            return this.impact;
        }

        /**
         * Gets the value of the likelihood property.
         * 
         * @return
         *     possible object is
         *     {@link LikelihoodEnumeration }
         *     
         */
        public LikelihoodEnumeration getLikelihood() {
            return likelihood;
        }

        /**
         * Sets the value of the likelihood property.
         * 
         * @param value
         *     allowed object is
         *     {@link LikelihoodEnumeration }
         *     
         */
        public void setLikelihood(LikelihoodEnumeration value) {
            this.likelihood = value;
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

        /**
         * Gets the value of the consequenceID property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getConsequenceID() {
            return consequenceID;
        }

        /**
         * Sets the value of the consequenceID property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setConsequenceID(String value) {
            this.consequenceID = value;
        }

    }

}
