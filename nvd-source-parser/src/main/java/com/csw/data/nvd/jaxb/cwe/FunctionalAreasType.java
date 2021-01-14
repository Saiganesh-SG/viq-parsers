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
 * The FunctionalAreasType complex type contains one or more functional_area elements, each of which identifies the functional area in which the weakness is most likely to occur. For example, CWE-23: Relative Path Traversal may occur in functional areas of software related to file processing. Each applicable functional area should have a new Functional_Area element, and standard title capitalization should be applied to each area.
 * 
 * <p>Java class for FunctionalAreasType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="FunctionalAreasType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Functional_Area" type="{http://cwe.mitre.org/cwe-6}FunctionalAreaEnumeration" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "FunctionalAreasType", propOrder = {
    "functionalArea"
})
public class FunctionalAreasType {

    @XmlElement(name = "Functional_Area", required = true)
    @XmlSchemaType(name = "string")
    protected List<FunctionalAreaEnumeration> functionalArea;

    /**
     * Gets the value of the functionalArea property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the functionalArea property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getFunctionalArea().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link FunctionalAreaEnumeration }
     * 
     * 
     */
    public List<FunctionalAreaEnumeration> getFunctionalArea() {
        if (functionalArea == null) {
            functionalArea = new ArrayList<FunctionalAreaEnumeration>();
        }
        return this.functionalArea;
    }

}
