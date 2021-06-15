
package com.csw.data.mitre.cwe.pojo;

import com.fasterxml.jackson.annotation.*;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * The Common Weakness Enumeration JSON Schema is created and maintained by The Cyber Security Works. The original data is sourced from Mitre Corporation(https://cwe.mitre.org).
 * 
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "id",
    "weaknessType",
    "sources",
    "title",
    "abstraction",
    "status",
    "structure",
    "viewType",
    "description",
    "extendedDescription",
    "relatedWeaknesses",
    "weaknessOrdinalities",
    "applicablePlatforms",
    "alternateTerms",
    "modesOfIntroduction",
    "likelihoodOfExploit",
    "commonConsequences",
    "detectionMethods",
    "potentialMitigations",
    "relatedAttackPattern",
    "functionalAreas",
    "affectedResources",
    "summary",
    "objective",
    "audience",
    "taxonomyMappings",
    "notes",
    "filter",
    "references",
    "contentHistory"
})
@Getter
@Setter
public class WeaknessRoot {

    @JsonProperty("id")
    @JsonPropertyDescription("The required ID attribute provides a unique identifier for the Common Weakness Enumeration")
    private String id;
    
    @JsonProperty("type")
    private String weaknessType;

    @JsonProperty("sources")
    private List<Source> sources = new ArrayList<Source>();
    /**
     * The CWE title attribute
     * <p>
     * The title attribute provides a unique title for the Common Weakness Enumeration
     * (Required)
     * 
     */
    @JsonProperty("title")
    @JsonPropertyDescription("The title attribute provides a unique title for the Common Weakness Enumeration")
    private String title;
    /**
     * The CWE Abstraction attribute
     * <p>
     * The Abstraction defines the different abstraction levels that apply to a weakness. A "Pillar" is the most abstract type of weakness and represents a theme for all class/base/variant weaknesses related to it. A Pillar is different from a Category as a Pillar is still technically a type of weakness that describes a mistake, while a Category represents a common characteristic used to group related things. A "Class" is a weakness also described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource. A "Base" is a more specific type of weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource. A "Variant" is a weakness  that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource. A "Compound" weakness is a meaningful aggregation of several weaknesses, currently known as either a Chain or Composite.
     * 
     */
    @JsonProperty("abstraction")
    @JsonPropertyDescription("The Abstraction defines the different abstraction levels that apply to a weakness. A \"Pillar\" is the most abstract type of weakness and represents a theme for all class/base/variant weaknesses related to it. A Pillar is different from a Category as a Pillar is still technically a type of weakness that describes a mistake, while a Category represents a common characteristic used to group related things. A \"Class\" is a weakness also described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource. A \"Base\" is a more specific type of weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource. A \"Variant\" is a weakness  that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource. A \"Compound\" weakness is a meaningful aggregation of several weaknesses, currently known as either a Chain or Composite.")
    private WeaknessRoot.Abstraction abstraction;
    /**
     * The CWE Status attribute
     * <p>
     * The Status defines the different status values that an entity (view, category, weakness) can have. A value of Deprecated refers to an entity that has been removed from CWE, likely because it was a duplicate or was created in error. A value of Obsolete is used when an entity is still valid but no longer is relevant, likely because it has been superceded by a more recent entity.  A value of Incomplete means that the entity does not have all important elements filled, and there is no guarantee of quality.  A value of Draft refers to an entity that has all important elements filled, and critical elements such as Name and Description are reasonably well-written; the entity may still have important problems or gaps.  A value of Usable refers to an entity that has received close, extensive review, with critical elements verified.  A value of Stable indicates that all important elements have been verified, and the entry is unlikely to change significantly in the future. Note that the quality requirements for Draft and Usable status are very resource-intensive to accomplish, while some Incomplete and Draft entries are actively used by the general public; so, this status enumeration might change in the future.
     * (Required)
     * 
     */
    @JsonProperty("status")
    @JsonPropertyDescription("The Status defines the different status values that an entity (view, category, weakness) can have. A value of Deprecated refers to an entity that has been removed from CWE, likely because it was a duplicate or was created in error. A value of Obsolete is used when an entity is still valid but no longer is relevant, likely because it has been superceded by a more recent entity.  A value of Incomplete means that the entity does not have all important elements filled, and there is no guarantee of quality.  A value of Draft refers to an entity that has all important elements filled, and critical elements such as Name and Description are reasonably well-written; the entity may still have important problems or gaps.  A value of Usable refers to an entity that has received close, extensive review, with critical elements verified.  A value of Stable indicates that all important elements have been verified, and the entry is unlikely to change significantly in the future. Note that the quality requirements for Draft and Usable status are very resource-intensive to accomplish, while some Incomplete and Draft entries are actively used by the general public; so, this status enumeration might change in the future.")
    private WeaknessRoot.Status status;
    /**
     * The CWE Status attribute
     * <p>
     * The Structure lists the different structural natures of a weakness. A Simple structure represents a single weakness whose exploitation is not dependent on the presence of another weakness. A Composite is a set of weaknesses that must all be present simultaneously in order to produce an exploitable vulnerability, while a Chain is a set of weaknesses that must be reachable consecutively in order to produce an exploitable vulnerability.
     * 
     */
    @JsonProperty("structure")
    @JsonPropertyDescription("The Structure lists the different structural natures of a weakness. A Simple structure represents a single weakness whose exploitation is not dependent on the presence of another weakness. A Composite is a set of weaknesses that must all be present simultaneously in order to produce an exploitable vulnerability, while a Chain is a set of weaknesses that must be reachable consecutively in order to produce an exploitable vulnerability.")
    private WeaknessRoot.Structure structure;
    @JsonProperty("viewType")
    private WeaknessRoot.ViewType viewType;
    @JsonProperty("description")
    private String description;
    @JsonProperty("extendedDescription")
    private String extendedDescription;
    @JsonProperty("relatedWeaknesses")
    private List<RelatedWeakness> relatedWeaknesses = new ArrayList<>();
    @JsonProperty("weaknessOrdinalities")
    private List<WeaknessOrdinality> weaknessOrdinalities = new ArrayList<>();
    @JsonProperty("applicablePlatforms")
    private ApplicablePlatformsRoot applicablePlatforms;
    @JsonProperty("alternateTerms")
    private List<AlternateTermType> alternateTerms = new ArrayList<>();
    @JsonProperty("modesOfIntroduction")
    private List<ModesOfIntroduction> modesOfIntroduction = new ArrayList<>();
    @JsonProperty("likelihoodOfExploit")
    private String likelihoodOfExploit;
    @JsonProperty("commonConsequences")
    private List<CommonConsequence> commonConsequences = new ArrayList<>();
    @JsonProperty("detectionMethods")
    private List<DetectionMethod> detectionMethods = new ArrayList<>();
    @JsonProperty("potentialMitigations")
    private List<PotentialMitigation> potentialMitigations = new ArrayList<>();
    @JsonProperty("relatedAttackPattern")
    private List<RelatedAttackPatternType> relatedAttackPattern = new ArrayList<>();
    @JsonProperty("functionalAreas")
    private List<String> functionalAreas = new ArrayList<>();
    @JsonProperty("affectedResources")
    private List<String> affectedResources = new ArrayList<>();
    @JsonProperty("summary")
    private String summary;
    @JsonProperty("objective")
    private String objective;
    @JsonProperty("audience")
    private List<AudienceType> audience = new ArrayList<>();
    @JsonProperty("taxonomyMappings")
    private List<TaxonomyMapping> taxonomyMappings = new ArrayList<>();
    @JsonProperty("notes")
    private List<NoteType> notes = new ArrayList<>();
    @JsonProperty("filter")
    private String filter;
    @JsonProperty("references")
    private List<Reference> references = new ArrayList<>();
    @JsonProperty("contentHistory")
    private ContentHistoryRoot contentHistory;
    private String lastUpdatedDate;
    private String submissionDate;

    /**
     * The CWE Abstraction attribute
     * <p>
     * The Abstraction defines the different abstraction levels that apply to a weakness. A "Pillar" is the most abstract type of weakness and represents a theme for all class/base/variant weaknesses related to it. A Pillar is different from a Category as a Pillar is still technically a type of weakness that describes a mistake, while a Category represents a common characteristic used to group related things. A "Class" is a weakness also described in a very abstract fashion, typically independent of any specific language or technology. More specific than a Pillar Weakness, but more general than a Base Weakness. Class level weaknesses typically describe issues in terms of 1 or 2 of the following dimensions: behavior, property, and resource. A "Base" is a more specific type of weakness that is still mostly independent of a resource or technology, but with sufficient details to provide specific methods for detection and prevention. Base level weaknesses typically describe issues in terms of 2 or 3 of the following dimensions: behavior, property, technology, language, and resource. A "Variant" is a weakness  that is linked to a certain type of product, typically involving a specific language or technology. More specific than a Base weakness. Variant level weaknesses typically describe issues in terms of 3 to 5 of the following dimensions: behavior, property, technology, language, and resource. A "Compound" weakness is a meaningful aggregation of several weaknesses, currently known as either a Chain or Composite.
     * 
     */
    public enum Abstraction {

        PILLAR("Pillar"),
        CLASS("Class"),
        BASE("Base"),
        VARIANT("Variant"),
        COMPOUND("Compound");
        private final String value;
        private final static Map<String, WeaknessRoot.Abstraction> CONSTANTS = new HashMap<String, WeaknessRoot.Abstraction>();

        static {
            for (WeaknessRoot.Abstraction c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private Abstraction(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static WeaknessRoot.Abstraction fromValue(String value) {
            WeaknessRoot.Abstraction constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }


    /**
     * The CWE Status attribute
     * <p>
     * The Status defines the different status values that an entity (view, category, weakness) can have. A value of Deprecated refers to an entity that has been removed from CWE, likely because it was a duplicate or was created in error. A value of Obsolete is used when an entity is still valid but no longer is relevant, likely because it has been superceded by a more recent entity.  A value of Incomplete means that the entity does not have all important elements filled, and there is no guarantee of quality.  A value of Draft refers to an entity that has all important elements filled, and critical elements such as Name and Description are reasonably well-written; the entity may still have important problems or gaps.  A value of Usable refers to an entity that has received close, extensive review, with critical elements verified.  A value of Stable indicates that all important elements have been verified, and the entry is unlikely to change significantly in the future. Note that the quality requirements for Draft and Usable status are very resource-intensive to accomplish, while some Incomplete and Draft entries are actively used by the general public; so, this status enumeration might change in the future.
     * 
     */
    public enum Status {

        DEPRECATED("Deprecated"),
        DRAFT("Draft"),
        INCOMPLETE("Incomplete"),
        OBSOLETE("Obsolete"),
        STABLE("Stable"),
        USABLE("Usable");
        private final String value;
        private final static Map<String, WeaknessRoot.Status> CONSTANTS = new HashMap<String, WeaknessRoot.Status>();

        static {
            for (WeaknessRoot.Status c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private Status(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static WeaknessRoot.Status fromValue(String value) {
            WeaknessRoot.Status constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }


    /**
     * The CWE Status attribute
     * <p>
     * The Structure lists the different structural natures of a weakness. A Simple structure represents a single weakness whose exploitation is not dependent on the presence of another weakness. A Composite is a set of weaknesses that must all be present simultaneously in order to produce an exploitable vulnerability, while a Chain is a set of weaknesses that must be reachable consecutively in order to produce an exploitable vulnerability.
     * 
     */
    public enum Structure {

        CHAIN("Chain"),
        COMPOSITE("Composite"),
        SIMPLE("Simple");
        private final String value;
        private final static Map<String, WeaknessRoot.Structure> CONSTANTS = new HashMap<String, WeaknessRoot.Structure>();

        static {
            for (WeaknessRoot.Structure c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private Structure(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static WeaknessRoot.Structure fromValue(String value) {
            WeaknessRoot.Structure constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

    public enum ViewType {

        IMPLICIT("Implicit"),
        EXPLICIT("Explicit"),
        GRAPH("Graph");
        private final String value;
        private final static Map<String, WeaknessRoot.ViewType> CONSTANTS = new HashMap<String, WeaknessRoot.ViewType>();

        static {
            for (WeaknessRoot.ViewType c: values()) {
                CONSTANTS.put(c.value, c);
            }
        }

        private ViewType(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }

        @JsonValue
        public String value() {
            return this.value;
        }

        @JsonCreator
        public static WeaknessRoot.ViewType fromValue(String value) {
            WeaknessRoot.ViewType constant = CONSTANTS.get(value);
            if (constant == null) {
                throw new IllegalArgumentException(value);
            } else {
                return constant;
            }
        }

    }

}
