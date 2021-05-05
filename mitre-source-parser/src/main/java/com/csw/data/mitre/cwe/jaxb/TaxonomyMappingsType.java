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
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The TaxonomyMappingsType complex type is used to provide a mapping from an entry (Weakness or Category) in CWE to an equivalent entry in a different taxonomy. The required Taxonomy_Name attribute identifies the taxonomy to which the mapping is being made. The Entry_ID and Entry_Name elements identify the ID and name of the entry which is being mapped. The Mapping_Fit element identifies how close the CWE is to the entry in the taxonomy.
 * 
 * <p>Java class for TaxonomyMappingsType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TaxonomyMappingsType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Taxonomy_Mapping" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Entry_ID" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Entry_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Mapping_Fit" type="{http://cwe.mitre.org/cwe-6}TaxonomyMappingFitEnumeration" minOccurs="0"/>
 *                 &lt;/sequence>
 *                 &lt;attribute name="Taxonomy_Name" use="required" type="{http://cwe.mitre.org/cwe-6}TaxonomyNameEnumeration" />
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
@XmlType(name = "TaxonomyMappingsType", propOrder = {
    "taxonomyMapping"
})
public class TaxonomyMappingsType {

    @XmlElement(name = "Taxonomy_Mapping", required = true)
    protected List<TaxonomyMappingsType.TaxonomyMapping> taxonomyMapping;

    /**
     * Gets the value of the taxonomyMapping property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the taxonomyMapping property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getTaxonomyMapping().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link TaxonomyMappingsType.TaxonomyMapping }
     * 
     * 
     */
    public List<TaxonomyMappingsType.TaxonomyMapping> getTaxonomyMapping() {
        if (taxonomyMapping == null) {
            taxonomyMapping = new ArrayList<TaxonomyMappingsType.TaxonomyMapping>();
        }
        return this.taxonomyMapping;
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
     *         &lt;element name="Entry_ID" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Entry_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Mapping_Fit" type="{http://cwe.mitre.org/cwe-6}TaxonomyMappingFitEnumeration" minOccurs="0"/>
     *       &lt;/sequence>
     *       &lt;attribute name="Taxonomy_Name" use="required" type="{http://cwe.mitre.org/cwe-6}TaxonomyNameEnumeration" />
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "entryID",
        "entryName",
        "mappingFit"
    })
    public static class TaxonomyMapping {

        @XmlElement(name = "Entry_ID")
        protected String entryID;
        @XmlElement(name = "Entry_Name")
        protected String entryName;
        @XmlElement(name = "Mapping_Fit")
        @XmlSchemaType(name = "string")
        protected TaxonomyMappingFitEnumeration mappingFit;
        @XmlAttribute(name = "Taxonomy_Name", required = true)
        protected String taxonomyName;

        /**
         * Gets the value of the entryID property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getEntryID() {
            return entryID;
        }

        /**
         * Sets the value of the entryID property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setEntryID(String value) {
            this.entryID = value;
        }

        /**
         * Gets the value of the entryName property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getEntryName() {
            return entryName;
        }

        /**
         * Sets the value of the entryName property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setEntryName(String value) {
            this.entryName = value;
        }

        /**
         * Gets the value of the mappingFit property.
         * 
         * @return
         *     possible object is
         *     {@link TaxonomyMappingFitEnumeration }
         *     
         */
        public TaxonomyMappingFitEnumeration getMappingFit() {
            return mappingFit;
        }

        /**
         * Sets the value of the mappingFit property.
         * 
         * @param value
         *     allowed object is
         *     {@link TaxonomyMappingFitEnumeration }
         *     
         */
        public void setMappingFit(TaxonomyMappingFitEnumeration value) {
            this.mappingFit = value;
        }

        /**
         * Gets the value of the taxonomyName property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getTaxonomyName() {
            return taxonomyName;
        }

        /**
         * Sets the value of the taxonomyName property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setTaxonomyName(String value) {
            this.taxonomyName = value;
        }

    }

}
