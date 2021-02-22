
package com.csw.data.nvd.json.cwe;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "id",
    "weaknessType",
    "sources",
    "title",
    "abstraction",
    "status",
    "structure",
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
    "taxonomyMappings",
    "notes",
    "references",
    "contentHistory",
    "summary",
    "relationships",
    "name",
    "viewType",
    "objective",
    "audience",
    "members",
    "filter"
})
public class Weakness {

    @JsonProperty("id")
    private String id;
    @JsonProperty("weaknessType")
    private String weaknessType;
    @JsonProperty("sources")
    private List<Source> sources = null;
    @JsonProperty("title")
    private String title;
    @JsonProperty("abstraction")
    private String abstraction;
    @JsonProperty("status")
    private String status;
    @JsonProperty("structure")
    private String structure;
    @JsonProperty("description")
    private String description;
    @JsonProperty("extendedDescription")
    private String extendedDescription;
    @JsonProperty("relatedWeaknesses")
    private List<RelatedWeakness> relatedWeaknesses = null;
    @JsonProperty("weaknessOrdinalities")
    private List<WeaknessOrdinality> weaknessOrdinalities = null;
    @JsonProperty("applicablePlatforms")
    private ApplicablePlatforms applicablePlatforms;
    @JsonProperty("alternateTerms")
    private List<AlternateTerm> alternateTerms = null;
    @JsonProperty("modesOfIntroduction")
    private List<ModesOfIntroduction> modesOfIntroduction = null;
    @JsonProperty("likelihoodOfExploit")
    private String likelihoodOfExploit;
    @JsonProperty("commonConsequences")
    private List<CommonConsequence> commonConsequences = null;
    @JsonProperty("detectionMethods")
    private List<DetectionMethod> detectionMethods = null;
    @JsonProperty("potentialMitigations")
    private List<PotentialMitigation> potentialMitigations = null;
    @JsonProperty("relatedAttackPattern")
    private List<RelatedAttackPattern> relatedAttackPattern = null;
    @JsonProperty("functionalAreas")
    private List<String> functionalAreas = null;
    @JsonProperty("affectedResources")
    private List<String> affectedResources = null;
    @JsonProperty("taxonomyMappings")
    private List<TaxonomyMapping> taxonomyMappings = null;
    @JsonProperty("notes")
    private Notes notes;
    @JsonProperty("references")
    private List<Reference> references = null;
    @JsonProperty("contentHistory")
    private ContentHistory contentHistory;
    @JsonProperty("summary")
    private String summary;
    @JsonProperty("relationships")
    private List<Relationship> relationships = null;
    @JsonProperty("name")
    private String name;
    @JsonProperty("viewType")
    private String viewType;
    @JsonProperty("objective")
    private String objective;
    @JsonProperty("audience")
    private List<Audience> audience = null;
    @JsonProperty("members")
    private List<Member> members = null;
    @JsonProperty("filter")
    private String filter;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new HashMap<String, Object>();

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("weaknessType")
    public String getWeaknessType() {
        return weaknessType;
    }

    @JsonProperty("weaknessType")
    public void setWeaknessType(String weaknessType) {
        this.weaknessType = weaknessType;
    }

    @JsonProperty("sources")
    public List<Source> getSources() {
        return sources;
    }

    @JsonProperty("sources")
    public void setSources(List<Source> sources) {
        this.sources = sources;
    }

    @JsonProperty("title")
    public String getTitle() {
        return title;
    }

    @JsonProperty("title")
    public void setTitle(String title) {
        this.title = title;
    }

    @JsonProperty("abstraction")
    public String getAbstraction() {
        return abstraction;
    }

    @JsonProperty("abstraction")
    public void setAbstraction(String abstraction) {
        this.abstraction = abstraction;
    }

    @JsonProperty("status")
    public String getStatus() {
        return status;
    }

    @JsonProperty("status")
    public void setStatus(String status) {
        this.status = status;
    }

    @JsonProperty("structure")
    public String getStructure() {
        return structure;
    }

    @JsonProperty("structure")
    public void setStructure(String structure) {
        this.structure = structure;
    }

    @JsonProperty("description")
    public String getDescription() {
        return description;
    }

    @JsonProperty("description")
    public void setDescription(String description) {
        this.description = description;
    }

    @JsonProperty("extendedDescription")
    public String getExtendedDescription() {
        return extendedDescription;
    }

    @JsonProperty("extendedDescription")
    public void setExtendedDescription(String extendedDescription) {
        this.extendedDescription = extendedDescription;
    }

    @JsonProperty("relatedWeaknesses")
    public List<RelatedWeakness> getRelatedWeaknesses() {
        return relatedWeaknesses;
    }

    @JsonProperty("relatedWeaknesses")
    public void setRelatedWeaknesses(List<RelatedWeakness> relatedWeaknesses) {
        this.relatedWeaknesses = relatedWeaknesses;
    }

    @JsonProperty("weaknessOrdinalities")
    public List<WeaknessOrdinality> getWeaknessOrdinalities() {
        return weaknessOrdinalities;
    }

    @JsonProperty("weaknessOrdinalities")
    public void setWeaknessOrdinalities(List<WeaknessOrdinality> weaknessOrdinalities) {
        this.weaknessOrdinalities = weaknessOrdinalities;
    }

    @JsonProperty("applicablePlatforms")
    public ApplicablePlatforms getApplicablePlatforms() {
        return applicablePlatforms;
    }

    @JsonProperty("applicablePlatforms")
    public void setApplicablePlatforms(ApplicablePlatforms applicablePlatforms) {
        this.applicablePlatforms = applicablePlatforms;
    }

    @JsonProperty("alternateTerms")
    public List<AlternateTerm> getAlternateTerms() {
        return alternateTerms;
    }

    @JsonProperty("alternateTerms")
    public void setAlternateTerms(List<AlternateTerm> alternateTerms) {
        this.alternateTerms = alternateTerms;
    }

    @JsonProperty("modesOfIntroduction")
    public List<ModesOfIntroduction> getModesOfIntroduction() {
        return modesOfIntroduction;
    }

    @JsonProperty("modesOfIntroduction")
    public void setModesOfIntroduction(List<ModesOfIntroduction> modesOfIntroduction) {
        this.modesOfIntroduction = modesOfIntroduction;
    }

    @JsonProperty("likelihoodOfExploit")
    public String getLikelihoodOfExploit() {
        return likelihoodOfExploit;
    }

    @JsonProperty("likelihoodOfExploit")
    public void setLikelihoodOfExploit(String likelihoodOfExploit) {
        this.likelihoodOfExploit = likelihoodOfExploit;
    }

    @JsonProperty("commonConsequences")
    public List<CommonConsequence> getCommonConsequences() {
        return commonConsequences;
    }

    @JsonProperty("commonConsequences")
    public void setCommonConsequences(List<CommonConsequence> commonConsequences) {
        this.commonConsequences = commonConsequences;
    }

    @JsonProperty("detectionMethods")
    public List<DetectionMethod> getDetectionMethods() {
        return detectionMethods;
    }

    @JsonProperty("detectionMethods")
    public void setDetectionMethods(List<DetectionMethod> detectionMethods) {
        this.detectionMethods = detectionMethods;
    }

    @JsonProperty("potentialMitigations")
    public List<PotentialMitigation> getPotentialMitigations() {
        return potentialMitigations;
    }

    @JsonProperty("potentialMitigations")
    public void setPotentialMitigations(List<PotentialMitigation> potentialMitigations) {
        this.potentialMitigations = potentialMitigations;
    }

    @JsonProperty("relatedAttackPattern")
    public List<RelatedAttackPattern> getRelatedAttackPattern() {
        return relatedAttackPattern;
    }

    @JsonProperty("relatedAttackPattern")
    public void setRelatedAttackPattern(List<RelatedAttackPattern> relatedAttackPattern) {
        this.relatedAttackPattern = relatedAttackPattern;
    }

    @JsonProperty("functionalAreas")
    public List<String> getFunctionalAreas() {
        return functionalAreas;
    }

    @JsonProperty("functionalAreas")
    public void setFunctionalAreas(List<String> functionalAreas) {
        this.functionalAreas = functionalAreas;
    }

    @JsonProperty("affectedResources")
    public List<String> getAffectedResources() {
        return affectedResources;
    }

    @JsonProperty("affectedResources")
    public void setAffectedResources(List<String> affectedResources) {
        this.affectedResources = affectedResources;
    }

    @JsonProperty("taxonomyMappings")
    public List<TaxonomyMapping> getTaxonomyMappings() {
        return taxonomyMappings;
    }

    @JsonProperty("taxonomyMappings")
    public void setTaxonomyMappings(List<TaxonomyMapping> taxonomyMappings) {
        this.taxonomyMappings = taxonomyMappings;
    }

    @JsonProperty("notes")
    public Notes getNotes() {
        return notes;
    }

    @JsonProperty("notes")
    public void setNotes(Notes notes) {
        this.notes = notes;
    }

    @JsonProperty("references")
    public List<Reference> getReferences() {
        return references;
    }

    @JsonProperty("references")
    public void setReferences(List<Reference> references) {
        this.references = references;
    }

    @JsonProperty("contentHistory")
    public ContentHistory getContentHistory() {
        return contentHistory;
    }

    @JsonProperty("contentHistory")
    public void setContentHistory(ContentHistory contentHistory) {
        this.contentHistory = contentHistory;
    }

    @JsonProperty("summary")
    public String getSummary() {
        return summary;
    }

    @JsonProperty("summary")
    public void setSummary(String summary) {
        this.summary = summary;
    }

    @JsonProperty("relationships")
    public List<Relationship> getRelationships() {
        return relationships;
    }

    @JsonProperty("relationships")
    public void setRelationships(List<Relationship> relationships) {
        this.relationships = relationships;
    }

    @JsonProperty("name")
    public String getName() {
        return name;
    }

    @JsonProperty("name")
    public void setName(String name) {
        this.name = name;
    }

    @JsonProperty("viewType")
    public String getViewType() {
        return viewType;
    }

    @JsonProperty("viewType")
    public void setViewType(String viewType) {
        this.viewType = viewType;
    }

    @JsonProperty("objective")
    public String getObjective() {
        return objective;
    }

    @JsonProperty("objective")
    public void setObjective(String objective) {
        this.objective = objective;
    }

    @JsonProperty("audience")
    public List<Audience> getAudience() {
        return audience;
    }

    @JsonProperty("audience")
    public void setAudience(List<Audience> audience) {
        this.audience = audience;
    }

    @JsonProperty("members")
    public List<Member> getMembers() {
        return members;
    }

    @JsonProperty("members")
    public void setMembers(List<Member> members) {
        this.members = members;
    }

    @JsonProperty("filter")
    public String getFilter() {
        return filter;
    }

    @JsonProperty("filter")
    public void setFilter(String filter) {
        this.filter = filter;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

}
