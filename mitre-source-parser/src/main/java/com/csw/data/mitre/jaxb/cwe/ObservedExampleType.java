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
import javax.xml.bind.annotation.XmlType;


/**
 * The ObservedExampleType complex type specifies references to a specific observed instance of a weakness in real-world products. Typically this will be a CVE reference. Each Observed_Example element represents a single example. The optional Reference element should contain the identifier for the example being cited. For example, if a CVE is being cited, it should be of the standard CVE identifier format, such as CVE-2005-1951 or CVE-1999-0046. The required Description element should contain a product-independent description of the example being cited. The description should present an unambiguous correlation between the example being described and the weakness that it is meant to exemplify. It should also be short and easy to understand. The Link element should provide a valid URL where more information regarding this example can be obtained.
 * 
 * <p>Java class for ObservedExampleType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ObservedExampleType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Observed_Example" maxOccurs="unbounded">
 *           &lt;complexType>
 *             &lt;complexContent>
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *                 &lt;sequence>
 *                   &lt;element name="Reference" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *                   &lt;element name="Description" type="{http://cwe.mitre.org/cwe-6}StructuredTextType"/>
 *                   &lt;element name="Link" type="{http://www.w3.org/2001/XMLSchema}string"/>
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
@XmlType(name = "ObservedExampleType", propOrder = {
    "observedExample"
})
public class ObservedExampleType {

    @XmlElement(name = "Observed_Example", required = true)
    protected List<ObservedExampleType.ObservedExample> observedExample;

    /**
     * Gets the value of the observedExample property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the observedExample property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getObservedExample().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ObservedExampleType.ObservedExample }
     * 
     * 
     */
    public List<ObservedExampleType.ObservedExample> getObservedExample() {
        if (observedExample == null) {
            observedExample = new ArrayList<ObservedExampleType.ObservedExample>();
        }
        return this.observedExample;
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
     *         &lt;element name="Reference" type="{http://www.w3.org/2001/XMLSchema}string"/>
     *         &lt;element name="Description" type="{http://cwe.mitre.org/cwe-6}StructuredTextType"/>
     *         &lt;element name="Link" type="{http://www.w3.org/2001/XMLSchema}string"/>
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
        "reference",
        "description",
        "link"
    })
    public static class ObservedExample {

        @XmlElement(name = "Reference", required = true)
        protected String reference;
        @XmlElement(name = "Description", required = true)
        protected StructuredTextType description;
        @XmlElement(name = "Link", required = true)
        protected String link;

        /**
         * Gets the value of the reference property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getReference() {
            return reference;
        }

        /**
         * Sets the value of the reference property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setReference(String value) {
            this.reference = value;
        }

        /**
         * Gets the value of the description property.
         * 
         * @return
         *     possible object is
         *     {@link StructuredTextType }
         *     
         */
        public StructuredTextType getDescription() {
            return description;
        }

        /**
         * Sets the value of the description property.
         * 
         * @param value
         *     allowed object is
         *     {@link StructuredTextType }
         *     
         */
        public void setDescription(StructuredTextType value) {
            this.description = value;
        }

        /**
         * Gets the value of the link property.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getLink() {
            return link;
        }

        /**
         * Sets the value of the link property.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setLink(String value) {
            this.link = value;
        }

    }

}
