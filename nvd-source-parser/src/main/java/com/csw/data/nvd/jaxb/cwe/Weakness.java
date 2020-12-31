package com.csw.data.nvd.jaxb.cwe;

import lombok.Getter;
import lombok.Setter;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@XmlRootElement(name = "Weakness")
@XmlAccessorType(XmlAccessType.FIELD)
public class Weakness {

    @XmlAttribute(name = "ID")
    private String id;

    @XmlAttribute(name = "Name")
    private String name;

    @XmlAttribute(name = "Status")
    private String status;

    @XmlElement(name = "Description")
    private String description;

    @XmlElement(name = "Likelihood_Of_Exploit")
    private String likelihoodOfExploit;

    @XmlElementWrapper(name = "Potential_Mitigations")
    @XmlElement(name = "Mitigation")
    List<Mitigation> mitigations = new ArrayList<>();

}
