
package com.csw.data.mitre.pojo.cwe;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.annotation.JsonValue;

import lombok.Getter;
import lombok.Setter;


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
    "relationships",
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
    @JsonProperty("relationships")
    private List<Relationship> relationships = new ArrayList<>();
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
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(WeaknessRoot.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("id");
        sb.append('=');
        sb.append(((this.id == null)?"<null>":this.id));
        sb.append(',');
        sb.append("weaknessType");
        sb.append('=');
        sb.append(((this.weaknessType == null)?"<null>":this.weaknessType));
        sb.append(',');
        sb.append("sources");
        sb.append('=');
        sb.append(((this.sources == null)?"<null>":this.sources));
        sb.append(',');
        sb.append("title");
        sb.append('=');
        sb.append(((this.title == null)?"<null>":this.title));
        sb.append(',');
        sb.append("abstraction");
        sb.append('=');
        sb.append(((this.abstraction == null)?"<null>":this.abstraction));
        sb.append(',');
        sb.append("status");
        sb.append('=');
        sb.append(((this.status == null)?"<null>":this.status));
        sb.append(',');
        sb.append("structure");
        sb.append('=');
        sb.append(((this.structure == null)?"<null>":this.structure));
        sb.append(',');
        sb.append("viewType");
        sb.append('=');
        sb.append(((this.viewType == null)?"<null>":this.viewType));
        sb.append(',');
        sb.append("description");
        sb.append('=');
        sb.append(((this.description == null)?"<null>":this.description));
        sb.append(',');
        sb.append("extendedDescription");
        sb.append('=');
        sb.append(((this.extendedDescription == null)?"<null>":this.extendedDescription));
        sb.append(',');
        sb.append("relatedWeaknesses");
        sb.append('=');
        sb.append(((this.relatedWeaknesses == null)?"<null>":this.relatedWeaknesses));
        sb.append(',');
        sb.append("weaknessOrdinalities");
        sb.append('=');
        sb.append(((this.weaknessOrdinalities == null)?"<null>":this.weaknessOrdinalities));
        sb.append(',');
        sb.append("applicablePlatforms");
        sb.append('=');
        sb.append(((this.applicablePlatforms == null)?"<null>":this.applicablePlatforms));
        sb.append(',');
        sb.append("alternateTerms");
        sb.append('=');
        sb.append(((this.alternateTerms == null)?"<null>":this.alternateTerms));
        sb.append(',');
        sb.append("modesOfIntroduction");
        sb.append('=');
        sb.append(((this.modesOfIntroduction == null)?"<null>":this.modesOfIntroduction));
        sb.append(',');
        sb.append("likelihoodOfExploit");
        sb.append('=');
        sb.append(((this.likelihoodOfExploit == null)?"<null>":this.likelihoodOfExploit));
        sb.append(',');
        sb.append("commonConsequences");
        sb.append('=');
        sb.append(((this.commonConsequences == null)?"<null>":this.commonConsequences));
        sb.append(',');
        sb.append("detectionMethods");
        sb.append('=');
        sb.append(((this.detectionMethods == null)?"<null>":this.detectionMethods));
        sb.append(',');
        sb.append("potentialMitigations");
        sb.append('=');
        sb.append(((this.potentialMitigations == null)?"<null>":this.potentialMitigations));
        sb.append(',');
        sb.append("relatedAttackPattern");
        sb.append('=');
        sb.append(((this.relatedAttackPattern == null)?"<null>":this.relatedAttackPattern));
        sb.append(',');
        sb.append("functionalAreas");
        sb.append('=');
        sb.append(((this.functionalAreas == null)?"<null>":this.functionalAreas));
        sb.append(',');
        sb.append("affectedResources");
        sb.append('=');
        sb.append(((this.affectedResources == null)?"<null>":this.affectedResources));
        sb.append(',');
        sb.append("summary");
        sb.append('=');
        sb.append(((this.summary == null)?"<null>":this.summary));
        sb.append(',');
        sb.append("objective");
        sb.append('=');
        sb.append(((this.objective == null)?"<null>":this.objective));
        sb.append(',');
        sb.append("audience");
        sb.append('=');
        sb.append(((this.audience == null)?"<null>":this.audience));
        sb.append(',');
        sb.append("relationships");
        sb.append('=');
        sb.append(((this.relationships == null)?"<null>":this.relationships));
        sb.append(',');
        sb.append("taxonomyMappings");
        sb.append('=');
        sb.append(((this.taxonomyMappings == null)?"<null>":this.taxonomyMappings));
        sb.append(',');
        sb.append("notes");
        sb.append('=');
        sb.append(((this.notes == null)?"<null>":this.notes));
        sb.append(',');
        sb.append("filter");
        sb.append('=');
        sb.append(((this.filter == null)?"<null>":this.filter));
        sb.append(',');
        sb.append("references");
        sb.append('=');
        sb.append(((this.references == null)?"<null>":this.references));
        sb.append(',');
        sb.append("contentHistory");
        sb.append('=');
        sb.append(((this.contentHistory == null)?"<null>":this.contentHistory));
        sb.append(',');
        sb.append("additionalProperties");
        sb.append('=');
        sb.append(((this.additionalProperties == null)?"<null>":this.additionalProperties));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.notes == null)? 0 :this.notes.hashCode()));
        result = ((result* 31)+((this.sources == null)? 0 :this.sources.hashCode()));
        result = ((result* 31)+((this.references == null)? 0 :this.references.hashCode()));
        result = ((result* 31)+((this.description == null)? 0 :this.description.hashCode()));
        result = ((result* 31)+((this.likelihoodOfExploit == null)? 0 :this.likelihoodOfExploit.hashCode()));
        result = ((result* 31)+((this.functionalAreas == null)? 0 :this.functionalAreas.hashCode()));
        result = ((result* 31)+((this.title == null)? 0 :this.title.hashCode()));
        result = ((result* 31)+((this.weaknessOrdinalities == null)? 0 :this.weaknessOrdinalities.hashCode()));
        result = ((result* 31)+((this.objective == null)? 0 :this.objective.hashCode()));
        result = ((result* 31)+((this.relationships == null)? 0 :this.relationships.hashCode()));
        result = ((result* 31)+((this.taxonomyMappings == null)? 0 :this.taxonomyMappings.hashCode()));
        result = ((result* 31)+((this.id == null)? 0 :this.id.hashCode()));
        result = ((result* 31)+((this.relatedWeaknesses == null)? 0 :this.relatedWeaknesses.hashCode()));
        result = ((result* 31)+((this.modesOfIntroduction == null)? 0 :this.modesOfIntroduction.hashCode()));
        result = ((result* 31)+((this.alternateTerms == null)? 0 :this.alternateTerms.hashCode()));
        result = ((result* 31)+((this.relatedAttackPattern == null)? 0 :this.relatedAttackPattern.hashCode()));
        result = ((result* 31)+((this.summary == null)? 0 :this.summary.hashCode()));
        result = ((result* 31)+((this.audience == null)? 0 :this.audience.hashCode()));
        result = ((result* 31)+((this.weaknessType == null)? 0 :this.weaknessType.hashCode()));
        result = ((result* 31)+((this.abstraction == null)? 0 :this.abstraction.hashCode()));
        result = ((result* 31)+((this.detectionMethods == null)? 0 :this.detectionMethods.hashCode()));
        result = ((result* 31)+((this.affectedResources == null)? 0 :this.affectedResources.hashCode()));
        result = ((result* 31)+((this.structure == null)? 0 :this.structure.hashCode()));
        result = ((result* 31)+((this.potentialMitigations == null)? 0 :this.potentialMitigations.hashCode()));
        result = ((result* 31)+((this.filter == null)? 0 :this.filter.hashCode()));
        result = ((result* 31)+((this.contentHistory == null)? 0 :this.contentHistory.hashCode()));
        result = ((result* 31)+((this.viewType == null)? 0 :this.viewType.hashCode()));
        result = ((result* 31)+((this.additionalProperties == null)? 0 :this.additionalProperties.hashCode()));
        result = ((result* 31)+((this.extendedDescription == null)? 0 :this.extendedDescription.hashCode()));
        result = ((result* 31)+((this.applicablePlatforms == null)? 0 :this.applicablePlatforms.hashCode()));
        result = ((result* 31)+((this.commonConsequences == null)? 0 :this.commonConsequences.hashCode()));
        result = ((result* 31)+((this.status == null)? 0 :this.status.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof WeaknessRoot) == false) {
            return false;
        }
        WeaknessRoot rhs = ((WeaknessRoot) other);
        return (((((((((((((((((((((((((((((((((this.notes == rhs.notes)||((this.notes!= null)&&this.notes.equals(rhs.notes)))&&((this.sources == rhs.sources)||((this.sources!= null)&&this.sources.equals(rhs.sources))))&&((this.references == rhs.references)||((this.references!= null)&&this.references.equals(rhs.references))))&&((this.description == rhs.description)||((this.description!= null)&&this.description.equals(rhs.description))))&&((this.likelihoodOfExploit == rhs.likelihoodOfExploit)||((this.likelihoodOfExploit!= null)&&this.likelihoodOfExploit.equals(rhs.likelihoodOfExploit))))&&((this.functionalAreas == rhs.functionalAreas)||((this.functionalAreas!= null)&&this.functionalAreas.equals(rhs.functionalAreas))))&&((this.title == rhs.title)||((this.title!= null)&&this.title.equals(rhs.title))))&&((this.weaknessOrdinalities == rhs.weaknessOrdinalities)||((this.weaknessOrdinalities!= null)&&this.weaknessOrdinalities.equals(rhs.weaknessOrdinalities))))&&((this.objective == rhs.objective)||((this.objective!= null)&&this.objective.equals(rhs.objective))))&&((this.relationships == rhs.relationships)||((this.relationships!= null)&&this.relationships.equals(rhs.relationships))))&&((this.taxonomyMappings == rhs.taxonomyMappings)||((this.taxonomyMappings!= null)&&this.taxonomyMappings.equals(rhs.taxonomyMappings))))&&((this.id == rhs.id)||((this.id!= null)&&this.id.equals(rhs.id))))&&((this.relatedWeaknesses == rhs.relatedWeaknesses)||((this.relatedWeaknesses!= null)&&this.relatedWeaknesses.equals(rhs.relatedWeaknesses))))&&((this.modesOfIntroduction == rhs.modesOfIntroduction)||((this.modesOfIntroduction!= null)&&this.modesOfIntroduction.equals(rhs.modesOfIntroduction))))&&((this.alternateTerms == rhs.alternateTerms)||((this.alternateTerms!= null)&&this.alternateTerms.equals(rhs.alternateTerms))))&&((this.relatedAttackPattern == rhs.relatedAttackPattern)||((this.relatedAttackPattern!= null)&&this.relatedAttackPattern.equals(rhs.relatedAttackPattern))))&&((this.summary == rhs.summary)||((this.summary!= null)&&this.summary.equals(rhs.summary))))&&((this.audience == rhs.audience)||((this.audience!= null)&&this.audience.equals(rhs.audience))))&&((this.weaknessType == rhs.weaknessType)||((this.weaknessType!= null)&&this.weaknessType.equals(rhs.weaknessType))))&&((this.abstraction == rhs.abstraction)||((this.abstraction!= null)&&this.abstraction.equals(rhs.abstraction))))&&((this.detectionMethods == rhs.detectionMethods)||((this.detectionMethods!= null)&&this.detectionMethods.equals(rhs.detectionMethods))))&&((this.affectedResources == rhs.affectedResources)||((this.affectedResources!= null)&&this.affectedResources.equals(rhs.affectedResources))))&&((this.structure == rhs.structure)||((this.structure!= null)&&this.structure.equals(rhs.structure))))&&((this.potentialMitigations == rhs.potentialMitigations)||((this.potentialMitigations!= null)&&this.potentialMitigations.equals(rhs.potentialMitigations))))&&((this.filter == rhs.filter)||((this.filter!= null)&&this.filter.equals(rhs.filter))))&&((this.contentHistory == rhs.contentHistory)||((this.contentHistory!= null)&&this.contentHistory.equals(rhs.contentHistory))))&&((this.viewType == rhs.viewType)||((this.viewType!= null)&&this.viewType.equals(rhs.viewType))))&&((this.additionalProperties == rhs.additionalProperties)||((this.additionalProperties!= null)&&this.additionalProperties.equals(rhs.additionalProperties))))&&((this.extendedDescription == rhs.extendedDescription)||((this.extendedDescription!= null)&&this.extendedDescription.equals(rhs.extendedDescription))))&&((this.applicablePlatforms == rhs.applicablePlatforms)||((this.applicablePlatforms!= null)&&this.applicablePlatforms.equals(rhs.applicablePlatforms))))&&((this.commonConsequences == rhs.commonConsequences)||((this.commonConsequences!= null)&&this.commonConsequences.equals(rhs.commonConsequences))))&&((this.status == rhs.status)||((this.status!= null)&&this.status.equals(rhs.status))));
    }


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
