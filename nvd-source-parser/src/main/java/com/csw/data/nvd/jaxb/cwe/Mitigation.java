package com.csw.data.nvd.jaxb.cwe;

import lombok.Getter;
import lombok.Setter;

import javax.xml.bind.annotation.*;
import java.util.Set;

@Getter
@Setter
@XmlRootElement(name = "Mitigation")
@XmlAccessorType(XmlAccessType.FIELD)
public class Mitigation {

    @XmlAttribute(name = "Mitigation_ID")
    private String mitigationId;

    @XmlElement(name = "Phase")
    private Set<String> phases;

    @XmlElement(name = "Strategy")
    private String strategy;

    @XmlElement(name = "Description")
   // @XmlAnyElement
    private String description;

    @XmlElement(name = "Effectiveness")
    private String effectiveness;

    @XmlElement(name = "Effectiveness_Notes")
    private String effectivenessNotes;

}
