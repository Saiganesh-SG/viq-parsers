//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.nvd.jaxb.cwe;

import java.math.BigInteger;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * The required ID attribute provides a unique identifier for the view. It is meant to be static for the lifetime of the view. If the view becomes deprecated, the ID should not be reused, and a placeholder for the deprecated view should be left in the catalog. The required Name attribute provides a descriptive title used to give the reader an idea of what perspective this view represents. All words in the name should be capitalized except for articles and prepositions, unless they begin or end the name. The required Type attribute describes how this view is being constructed. Please refer to the ViewTypeEnumeration simple type for a list of valid values and their meanings. The required Status attribute defines the maturity of the information for this view. Please refer to the StatusEnumeration simple type for a list of valid values and their meanings.
 * 
 * <p>Java class for ViewType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ViewType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Objective" type="{http://cwe.mitre.org/cwe-6}StructuredTextType"/>
 *         &lt;element name="Audience" type="{http://cwe.mitre.org/cwe-6}AudienceType" minOccurs="0"/>
 *         &lt;element name="Members" type="{http://cwe.mitre.org/cwe-6}RelationshipsType" minOccurs="0"/>
 *         &lt;element name="Filter" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="References" type="{http://cwe.mitre.org/cwe-6}ReferencesType" minOccurs="0"/>
 *         &lt;element name="Notes" type="{http://cwe.mitre.org/cwe-6}NotesType" minOccurs="0"/>
 *         &lt;element name="Content_History" type="{http://cwe.mitre.org/cwe-6}ContentHistoryType" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ID" use="required" type="{http://www.w3.org/2001/XMLSchema}integer" />
 *       &lt;attribute name="Name" use="required" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Type" use="required" type="{http://cwe.mitre.org/cwe-6}ViewTypeEnumeration" />
 *       &lt;attribute name="Status" use="required" type="{http://cwe.mitre.org/cwe-6}StatusEnumeration" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ViewType", propOrder = {
    "objective",
    "audience",
    "members",
    "filter",
    "references",
    "notes",
    "contentHistory"
})
public class ViewType {

    @XmlElement(name = "Objective", required = true)
    protected StructuredTextType objective;
    @XmlElement(name = "Audience")
    protected AudienceType audience;
    @XmlElement(name = "Members")
    protected RelationshipsType members;
    @XmlElement(name = "Filter")
    protected String filter;
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
    @XmlAttribute(name = "Type", required = true)
    protected ViewTypeEnumeration type;
    @XmlAttribute(name = "Status", required = true)
    protected StatusEnumeration status;

    /**
     * Gets the value of the objective property.
     * 
     * @return
     *     possible object is
     *     {@link StructuredTextType }
     *     
     */
    public StructuredTextType getObjective() {
        return objective;
    }

    /**
     * Sets the value of the objective property.
     * 
     * @param value
     *     allowed object is
     *     {@link StructuredTextType }
     *     
     */
    public void setObjective(StructuredTextType value) {
        this.objective = value;
    }

    /**
     * Gets the value of the audience property.
     * 
     * @return
     *     possible object is
     *     {@link AudienceType }
     *     
     */
    public AudienceType getAudience() {
        return audience;
    }

    /**
     * Sets the value of the audience property.
     * 
     * @param value
     *     allowed object is
     *     {@link AudienceType }
     *     
     */
    public void setAudience(AudienceType value) {
        this.audience = value;
    }

    /**
     * Gets the value of the members property.
     * 
     * @return
     *     possible object is
     *     {@link RelationshipsType }
     *     
     */
    public RelationshipsType getMembers() {
        return members;
    }

    /**
     * Sets the value of the members property.
     * 
     * @param value
     *     allowed object is
     *     {@link RelationshipsType }
     *     
     */
    public void setMembers(RelationshipsType value) {
        this.members = value;
    }

    /**
     * Gets the value of the filter property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getFilter() {
        return filter;
    }

    /**
     * Sets the value of the filter property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setFilter(String value) {
        this.filter = value;
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
     * Gets the value of the type property.
     * 
     * @return
     *     possible object is
     *     {@link ViewTypeEnumeration }
     *     
     */
    public ViewTypeEnumeration getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     * @param value
     *     allowed object is
     *     {@link ViewTypeEnumeration }
     *     
     */
    public void setType(ViewTypeEnumeration value) {
        this.type = value;
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
