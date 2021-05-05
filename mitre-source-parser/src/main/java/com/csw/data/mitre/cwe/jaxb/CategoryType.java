//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.mitre.cwe.jaxb;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The required ID attribute provides a unique identifier for the category. It is meant to be static for the lifetime of the category. If the category becomes deprecated, the ID should not be reused, and a placeholder for the deprecated category should be left in the catalog. The required Name attribute provides a descriptive title used to give the reader an idea of what characteristics this category represents. All words in the name should be capitalized except for articles and prepositions unless they begin or end the name. The required Status attribute defines the maturity of the information for this category. Please refer to the StatusEnumeration simple type for a list of valid values and their meanings.
 * 
 * <p>Java class for CategoryType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CategoryType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Summary" type="{http://cwe.mitre.org/cwe-6}StructuredTextType"/>
 *         &lt;element name="Relationships" type="{http://cwe.mitre.org/cwe-6}RelationshipsType" minOccurs="0"/>
 *         &lt;element name="Taxonomy_Mappings" type="{http://cwe.mitre.org/cwe-6}TaxonomyMappingsType" minOccurs="0"/>
 *         &lt;element name="References" type="{http://cwe.mitre.org/cwe-6}ReferencesType" minOccurs="0"/>
 *         &lt;element name="Notes" type="{http://cwe.mitre.org/cwe-6}NotesType" minOccurs="0"/>
 *         &lt;element name="Content_History" type="{http://cwe.mitre.org/cwe-6}ContentHistoryType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}integer" />
 *       &lt;attribute name="Name" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Status" use="required" type="{http://cwe.mitre.org/cwe-6}StatusEnumeration" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CategoryType", propOrder = {
    "summary",
    "relationships",
    "taxonomyMappings",
    "references",
    "notes",
    "contentHistory"
})
public class CategoryType {

    @XmlElement(name = "Summary", required = true)
    protected StructuredTextType summary;
    @XmlElement(name = "Relationships")
    protected RelationshipsType relationships;
    @XmlElement(name = "Taxonomy_Mappings")
    protected TaxonomyMappingsType taxonomyMappings;
    @XmlElement(name = "References")
    protected ReferencesType references;
    @XmlElement(name = "Notes")
    protected NotesType notes;
    @XmlElement(name = "Content_History")
    protected ContentHistoryType contentHistory;
    @XmlAttribute(name = "ID", required = true)
    protected BigInteger id;
    @XmlAttribute(name = "Name", required = true)
    protected String name;
    @XmlAttribute(name = "Status", required = true)
    protected StatusEnumeration status;

    /**
     * Gets the value of the summary property.
     * 
     * @return
     *     possible object is
     *     {@link StructuredTextType }
     *     
     */
    public StructuredTextType getSummary() {
        return summary;
    }

    /**
     * Sets the value of the summary property.
     * 
     * @param value
     *     allowed object is
     *     {@link StructuredTextType }
     *     
     */
    public void setSummary(StructuredTextType value) {
        this.summary = value;
    }

    /**
     * Gets the value of the relationships property.
     * 
     * @return
     *     possible object is
     *     {@link RelationshipsType }
     *     
     */
    public RelationshipsType getRelationships() {
        return relationships;
    }

    /**
     * Sets the value of the relationships property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelationshipsType }
     *     
     */
    public void setRelationships(RelationshipsType value) {
        this.relationships = value;
    }

    /**
     * Gets the value of the taxonomyMappings property.
     * 
     * @return
     *     possible object is
     *     {@link TaxonomyMappingsType }
     *     
     */
    public TaxonomyMappingsType getTaxonomyMappings() {
        return taxonomyMappings;
    }

    /**
     * Sets the value of the taxonomyMappings property.
     * 
     * @param value
     *     allowed object is
     *     {@link TaxonomyMappingsType }
     *     
     */
    public void setTaxonomyMappings(TaxonomyMappingsType value) {
        this.taxonomyMappings = value;
    }

    /**
     * Gets the value of the references property.
     * 
     * @return
     *     possible object is
     *     {@link ReferencesType }
     *     
     */
    public ReferencesType getReferences() {
        return references;
    }

    /**
     * Sets the value of the references property.
     * 
     * @param value
     *     allowed object is
     *     {@link ReferencesType }
     *     
     */
    public void setReferences(ReferencesType value) {
        this.references = value;
    }

    /**
     * Gets the value of the notes property.
     * 
     * @return
     *     possible object is
     *     {@link NotesType }
     *     
     */
    public NotesType getNotes() {
        return notes;
    }

    /**
     * Sets the value of the notes property.
     * 
     * @param value
     *     allowed object is
     *     {@link NotesType }
     *     
     */
    public void setNotes(NotesType value) {
        this.notes = value;
    }

    /**
     * Gets the value of the contentHistory property.
     * 
     * @return
     *     possible object is
     *     {@link ContentHistoryType }
     *     
     */
    public ContentHistoryType getContentHistory() {
        return contentHistory;
    }

    /**
     * Sets the value of the contentHistory property.
     * 
     * @param value
     *     allowed object is
     *     {@link ContentHistoryType }
     *     
     */
    public void setContentHistory(ContentHistoryType value) {
        this.contentHistory = value;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getID() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setID(BigInteger value) {
        this.id = value;
    }

    /**
     * Gets the value of the name property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setName(String value) {
        this.name = value;
    }

    /**
     * Gets the value of the status property.
     * 
     * @return
     *     possible object is
     *     {@link StatusEnumeration }
     *     
     */
    public StatusEnumeration getStatus() {
        return status;
    }

    /**
     * Sets the value of the status property.
     * 
     * @param value
     *     allowed object is
     *     {@link StatusEnumeration }
     *     
     */
    public void setStatus(StatusEnumeration value) {
        this.status = value;
    }

}
