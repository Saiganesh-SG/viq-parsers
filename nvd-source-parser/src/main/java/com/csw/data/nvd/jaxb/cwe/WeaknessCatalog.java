package com.csw.data.nvd.jaxb.cwe;

import lombok.Getter;
import lombok.Setter;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@XmlAccessorType(XmlAccessType.FIELD)
@XmlRootElement(name = "Weakness_Catalog")
public class WeaknessCatalog {

    @XmlElementWrapper(name = "Weaknesses")
    @XmlElement(name = "Weakness")
    private List<Weakness> weaknesses = new ArrayList<>();
}
