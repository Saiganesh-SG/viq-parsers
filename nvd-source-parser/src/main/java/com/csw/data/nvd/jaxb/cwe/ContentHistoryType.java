//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.nvd.jaxb.cwe;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementRef;
import javax.xml.bind.annotation.XmlElementRefs;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.XmlValue;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * The ContentHistoryType complex type provides elements to keep track of the original author of an entry and any subsequent modifications to the content. The required Submission element is used to identify the submitter and/or their organization, the date, and any optional comments related to an entry. The optional Modification element is used to identify a modifier's name, organization, the date, and any related comments. A new Modification element should exist for each change made to the content. Modifications that change the meaning of the entry, or how it might be interpreted, should be marked with an importance of critical to bring it to the attention of anyone previously dependent on the weakness. The optional Contribution element is used to identify a contributor's name, organization, the date, and any related comments. This element has a single Type attribute, which indicates whether the contribution was part of general feedback given or actual content that was donated. The optional Previous_Entry_Name element is used to describe a previous name that was used for the entry. This should be filled out whenever a substantive name change occurs. The required Date attribute lists the date on which this name change was made. A Previous_Entry_Name element should align with a corresponding Modification element.
 * 
 * <p>Java class for ContentHistoryType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ContentHistoryType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Submission">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;choice>
 *                     &lt;sequence>
 *                       &lt;element name="Submission_Name" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *                       &lt;element name="Submission_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                     &lt;/sequence>
 *                     &lt;element name="Submission_Organization" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *                   &lt;/choice>
 *                   &lt;element name="Submission_Date" type="{http://www.w3.org/2001/XMLSchema}date"/>
 *                   &lt;element name="Submission_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Modification" maxOccurs="unbounded" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Modification_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Modification_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Modification_Date" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
 *                   &lt;element name="Modification_Importance" type="{http://cwe.mitre.org/cwe-6}ImportanceEnumeration" minOccurs="0"/>
 *                   &lt;element name="Modification_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                 &lt;/sequence>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Contribution" maxOccurs="unbounded" minOccurs="0">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Contribution_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Contribution_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                   &lt;element name="Contribution_Date" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
 *                   &lt;element name="Contribution_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *                 &lt;/sequence>
 *                 &lt;attribute name="Type" use="required">
 *                   &lt;simpleType>
 *                     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *                       &lt;enumeration value="Content"/>
 *                       &lt;enumeration value="Feedback"/>
 *                     &lt;/restriction>
 *                   &lt;/simpleType>
 *                 &lt;/attribute>
 *               &lt;/restriction>
 *             &lt;/complexContent>
 *           &lt;/complexType>
 *         &lt;/element>
 *         &lt;element name="Previous_Entry_Name" maxOccurs="unbounded" minOccurs="0">
 *           &lt;complexType>
 *             &lt;simpleContent>
 *               &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>string">
 *                 &lt;attribute name="Date" use="required" type="{http://www.w3.org/2001/XMLSchema}date" />
 *               &lt;/extension>
 *             &lt;/simpleContent>
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
@XmlType(name = "ContentHistoryType", propOrder = {
    "submission",
    "modification",
    "contribution",
    "previousEntryName"
})
public class ContentHistoryType {

    @XmlElement(name = "Submission", required = true)
    protected ContentHistoryType.Submission submission;
    @XmlElement(name = "Modification")
    protected List<ContentHistoryType.Modification> modification;
    @XmlElement(name = "Contribution")
    protected List<ContentHistoryType.Contribution> contribution;
    @XmlElement(name = "Previous_Entry_Name")
    protected List<ContentHistoryType.PreviousEntryName> previousEntryName;

    /**
     * Gets the value of the submission property.
     * 
     * @return
     *     possible object is
     *     {@link ContentHistoryType.Submission }
     *     
     */
    public ContentHistoryType.Submission getSubmission() {
        return submission;
    }

    /**
     * Sets the value of the submission property.
     * 
     * @param value
     *     allowed object is
     *     {@link ContentHistoryType.Submission }
     *     
     */
    public void setSubmission(ContentHistoryType.Submission value) {
        this.submission = value;
    }

    /**
     * Gets the value of the modification property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the modification property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getModification().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ContentHistoryType.Modification }
     * 
     * 
     */
    public List<ContentHistoryType.Modification> getModification() {
        if (modification == null) {
            modification = new ArrayList<ContentHistoryType.Modification>();
        }
        return this.modification;
    }

    /**
     * Gets the value of the contribution property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the contribution property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getContribution().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ContentHistoryType.Contribution }
     * 
     * 
     */
    public List<ContentHistoryType.Contribution> getContribution() {
        if (contribution == null) {
            contribution = new ArrayList<ContentHistoryType.Contribution>();
        }
        return this.contribution;
    }

    /**
     * Gets the value of the previousEntryName property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the previousEntryName property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPreviousEntryName().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ContentHistoryType.PreviousEntryName }
     * 
     * 
     */
    public List<ContentHistoryType.PreviousEntryName> getPreviousEntryName() {
        if (previousEntryName == null) {
            previousEntryName = new ArrayList<ContentHistoryType.PreviousEntryName>();
        }
        return this.previousEntryName;
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
     *         &lt;element name="Contribution_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Contribution_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Contribution_Date" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
     *         &lt;element name="Contribution_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *       &lt;/sequence>
     *       &lt;attribute name="Type" use="required">
     *         &lt;simpleType>
     *           &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
     *             &lt;enumeration value="Content"/>
     *             &lt;enumeration value="Feedback"/>
     *           &lt;/restriction>
     *         &lt;/simpleType>
     *       &lt;/attribute>
     *     &lt;/restriction>
     *   &lt;/complexContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "contributionName",
        "contributionOrganization",
        "contributionDate",
        "contributionComment"
    })
    public static class Contribution {

        @XmlElement(name = "Contribution_Name")
        protected String contributionName;
        @XmlElement(name = "Contribution_Organization")
        protected String contributionOrganization;
        @XmlElement(name = "Contribution_Date")
        @XmlSchemaType(name = "date")
        protected XMLGregorianCalendar contributionDate;
        @XmlElement(name = "Contribution_Comment")
        protected String contributionComment;
        @XmlAttribute(name = "Type", required = true)
        protected String type;

        /**
         * Gets the value of the contributionName property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getContributionName() {
            return contributionName;
        }

        /**
         * Sets the value of the contributionName property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setContributionName(String value) {
            this.contributionName = value;
        }

        /**
         * Gets the value of the contributionOrganization property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getContributionOrganization() {
            return contributionOrganization;
        }

        /**
         * Sets the value of the contributionOrganization property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setContributionOrganization(String value) {
            this.contributionOrganization = value;
        }

        /**
         * Gets the value of the contributionDate property.
         * 
         * @return
         *     possible object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public XMLGregorianCalendar getContributionDate() {
            return contributionDate;
        }

        /**
         * Sets the value of the contributionDate property.
         * 
         * @param value
         *     allowed object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public void setContributionDate(XMLGregorianCalendar value) {
            this.contributionDate = value;
        }

        /**
         * Gets the value of the contributionComment property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getContributionComment() {
            return contributionComment;
        }

        /**
         * Sets the value of the contributionComment property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setContributionComment(String value) {
            this.contributionComment = value;
        }

        /**
         * Gets the value of the type property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getType() {
            return type;
        }

        /**
         * Sets the value of the type property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setType(String value) {
            this.type = value;
        }

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
     *         &lt;element name="Modification_Name" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Modification_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *         &lt;element name="Modification_Date" type="{http://www.w3.org/2001/XMLSchema}date" minOccurs="0"/>
     *         &lt;element name="Modification_Importance" type="{http://cwe.mitre.org/cwe-6}ImportanceEnumeration" minOccurs="0"/>
     *         &lt;element name="Modification_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
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
        "modificationName",
        "modificationOrganization",
        "modificationDate",
        "modificationImportance",
        "modificationComment"
    })
    public static class Modification {

        @XmlElement(name = "Modification_Name")
        protected String modificationName;
        @XmlElement(name = "Modification_Organization")
        protected String modificationOrganization;
        @XmlElement(name = "Modification_Date")
        @XmlSchemaType(name = "date")
        protected XMLGregorianCalendar modificationDate;
        @XmlElement(name = "Modification_Importance")
        @XmlSchemaType(name = "string")
        protected ImportanceEnumeration modificationImportance;
        @XmlElement(name = "Modification_Comment")
        protected String modificationComment;

        /**
         * Gets the value of the modificationName property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getModificationName() {
            return modificationName;
        }

        /**
         * Sets the value of the modificationName property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setModificationName(String value) {
            this.modificationName = value;
        }

        /**
         * Gets the value of the modificationOrganization property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getModificationOrganization() {
            return modificationOrganization;
        }

        /**
         * Sets the value of the modificationOrganization property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setModificationOrganization(String value) {
            this.modificationOrganization = value;
        }

        /**
         * Gets the value of the modificationDate property.
         * 
         * @return
         *     possible object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public XMLGregorianCalendar getModificationDate() {
            return modificationDate;
        }

        /**
         * Sets the value of the modificationDate property.
         * 
         * @param value
         *     allowed object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public void setModificationDate(XMLGregorianCalendar value) {
            this.modificationDate = value;
        }

        /**
         * Gets the value of the modificationImportance property.
         * 
         * @return
         *     possible object is
         *     {@link ImportanceEnumeration }
         *     
         */
        public ImportanceEnumeration getModificationImportance() {
            return modificationImportance;
        }

        /**
         * Sets the value of the modificationImportance property.
         * 
         * @param value
         *     allowed object is
         *     {@link ImportanceEnumeration }
         *     
         */
        public void setModificationImportance(ImportanceEnumeration value) {
            this.modificationImportance = value;
        }

        /**
         * Gets the value of the modificationComment property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getModificationComment() {
            return modificationComment;
        }

        /**
         * Sets the value of the modificationComment property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setModificationComment(String value) {
            this.modificationComment = value;
        }

    }


    /**
     * <p>Java class for anonymous complex type.
     * 
     * <p>The following schema fragment specifies the expected content contained within this class.
     * 
     * <pre>
     * &lt;complexType>
     *   &lt;simpleContent>
     *     &lt;extension base="&lt;http://www.w3.org/2001/XMLSchema>string">
     *       &lt;attribute name="Date" use="required" type="{http://www.w3.org/2001/XMLSchema}date" />
     *     &lt;/extension>
     *   &lt;/simpleContent>
     * &lt;/complexType>
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "", propOrder = {
        "value"
    })
    public static class PreviousEntryName {

        @XmlValue
        protected String value;
        @XmlAttribute(name = "Date", required = true)
        @XmlSchemaType(name = "date")
        protected XMLGregorianCalendar date;

        /**
         * Gets the value of the value property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getValue() {
            return value;
        }

        /**
         * Sets the value of the value property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setValue(String value) {
            this.value = value;
        }

        /**
         * Gets the value of the date property.
         * 
         * @return
         *     possible object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public XMLGregorianCalendar getDate() {
            return date;
        }

        /**
         * Sets the value of the date property.
         * 
         * @param value
         *     allowed object is
         *     {@link XMLGregorianCalendar }
         *     
         */
        public void setDate(XMLGregorianCalendar value) {
            this.date = value;
        }

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
     *         &lt;choice>
     *           &lt;sequence>
     *             &lt;element name="Submission_Name" type="{http://www.w3.org/2001/XMLSchema}string"/>
     *             &lt;element name="Submission_Organization" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
     *           &lt;/sequence>
     *           &lt;element name="Submission_Organization" type="{http://www.w3.org/2001/XMLSchema}string"/>
     *         &lt;/choice>
     *         &lt;element name="Submission_Date" type="{http://www.w3.org/2001/XMLSchema}date"/>
     *         &lt;element name="Submission_Comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
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
        "content"
    })
    public static class Submission {

        @XmlElementRefs({
            @XmlElementRef(name = "Submission_Date", namespace = "http://cwe.mitre.org/cwe-6", type = JAXBElement.class, required = false),
            @XmlElementRef(name = "Submission_Name", namespace = "http://cwe.mitre.org/cwe-6", type = JAXBElement.class, required = false),
            @XmlElementRef(name = "Submission_Comment", namespace = "http://cwe.mitre.org/cwe-6", type = JAXBElement.class, required = false),
            @XmlElementRef(name = "Submission_Organization", namespace = "http://cwe.mitre.org/cwe-6", type = JAXBElement.class, required = false)
        })
        protected List<JAXBElement<?>> content;

        /**
         * Gets the rest of the content model. 
         * 
         * <p>
         * You are getting this "catch-all" property because of the following reason: 
         * The field name "SubmissionOrganization" is used by two different parts of a schema. See: 
         * line 295 of file:/D:/Workspace/beam-example/word-count-beam/target/cwe_schema_latest_mitre.xsd
         * line 293 of file:/D:/Workspace/beam-example/word-count-beam/target/cwe_schema_latest_mitre.xsd
         * <p>
         * To get rid of this property, apply a property customization to one 
         * of both of the following declarations to change their names: 
         * Gets the value of the content property.
         * 
         * <p>
         * This accessor method returns a reference to the live list,
         * not a snapshot. Therefore any modification you make to the
         * returned list will be present inside the JAXB object.
         * This is why there is not a <CODE>set</CODE> method for the content property.
         * 
         * <p>
         * For example, to add a new item, do as follows:
         * <pre>
         *    getContent().add(newItem);
         * </pre>
         * 
         * 
         * <p>
         * Objects of the following type(s) are allowed in the list
         * {@link JAXBElement }{@code <}{@link XMLGregorianCalendar }{@code >}
         * {@link JAXBElement }{@code <}{@link String }{@code >}
         * {@link JAXBElement }{@code <}{@link String }{@code >}
         * {@link JAXBElement }{@code <}{@link String }{@code >}
         * 
         * 
         */
        public List<JAXBElement<?>> getContent() {
            if (content == null) {
                content = new ArrayList<JAXBElement<?>>();
            }
            return this.content;
        }

    }

}
