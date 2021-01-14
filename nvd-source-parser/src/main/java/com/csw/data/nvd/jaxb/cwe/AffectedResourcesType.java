//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2021.01.13 at 11:40:26 PM IST 
//


package com.csw.data.nvd.jaxb.cwe;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;


/**
 * The AffectedResourcesType complex type is used to identify system resources that can be affected by an exploit of this weakness. If multiple resources could be affected, then each should be defined by its own Affected_Resource element.
 * 
 * <p>Java class for AffectedResourcesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AffectedResourcesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Affected_Resource" type="{http://cwe.mitre.org/cwe-6}ResourceEnumeration" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AffectedResourcesType", propOrder = {
    "affectedResource"
})
public class AffectedResourcesType {

    @XmlElement(name = "Affected_Resource", required = true)
    @XmlSchemaType(name = "string")
    protected List<ResourceEnumeration> affectedResource;

    /**
     * Gets the value of the affectedResource property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the affectedResource property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAffectedResource().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link ResourceEnumeration }
     * 
     * 
     */
    public List<ResourceEnumeration> getAffectedResource() {
        if (affectedResource == null) {
            affectedResource = new ArrayList<ResourceEnumeration>();
        }
        return this.affectedResource;
    }

}
