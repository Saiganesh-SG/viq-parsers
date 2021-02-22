package com.csw.data.nvd.parser.helper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.csw.data.nvd.aws.config.AmazonS3Client;
import com.csw.data.nvd.jaxb.cwe.AlternateTermsType.AlternateTerm;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Architecture;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Language;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.OperatingSystem;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Technology;
import com.csw.data.nvd.jaxb.cwe.AudienceType.Stakeholder;
import com.csw.data.nvd.jaxb.cwe.CategoryType;
import com.csw.data.nvd.jaxb.cwe.CommonConsequencesType.Consequence;
import com.csw.data.nvd.jaxb.cwe.ContentHistoryType;
import com.csw.data.nvd.jaxb.cwe.ContentHistoryType.Contribution;
import com.csw.data.nvd.jaxb.cwe.ContentHistoryType.Modification;
import com.csw.data.nvd.jaxb.cwe.ContentHistoryType.PreviousEntryName;
import com.csw.data.nvd.jaxb.cwe.ContentHistoryType.Submission;
import com.csw.data.nvd.jaxb.cwe.ExternalReferenceType;
import com.csw.data.nvd.jaxb.cwe.FunctionalAreaEnumeration;
import com.csw.data.nvd.jaxb.cwe.MemberType;
import com.csw.data.nvd.jaxb.cwe.ModesOfIntroductionType.Introduction;
import com.csw.data.nvd.jaxb.cwe.NotesType.Note;
import com.csw.data.nvd.jaxb.cwe.PhaseEnumeration;
import com.csw.data.nvd.jaxb.cwe.PotentialMitigationsType.Mitigation;
import com.csw.data.nvd.jaxb.cwe.ReferencesType;
import com.csw.data.nvd.jaxb.cwe.RelatedAttackPatternsType.RelatedAttackPattern;
import com.csw.data.nvd.jaxb.cwe.RelatedWeaknessesType.RelatedWeakness;
import com.csw.data.nvd.jaxb.cwe.ResourceEnumeration;
import com.csw.data.nvd.jaxb.cwe.ScopeEnumeration;
import com.csw.data.nvd.jaxb.cwe.StructuredTextType;
import com.csw.data.nvd.jaxb.cwe.TechnicalImpactEnumeration;
import com.csw.data.nvd.jaxb.cwe.ViewType;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog.Categories;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog.ExternalReferences;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog.Views;
import com.csw.data.nvd.jaxb.cwe.WeaknessOrdinalitiesType.WeaknessOrdinality;
import com.csw.data.nvd.jaxb.cwe.WeaknessType;
import com.csw.data.nvd.pojo.cwe.AlternateTermType;
import com.csw.data.nvd.pojo.cwe.ApplicablePlatformsRoot;
import com.csw.data.nvd.pojo.cwe.AudienceType;
import com.csw.data.nvd.pojo.cwe.CommonConsequence;
import com.csw.data.nvd.pojo.cwe.ContentHistoryRoot;
import com.csw.data.nvd.pojo.cwe.ContributionType;
import com.csw.data.nvd.pojo.cwe.DetectionMethod;
import com.csw.data.nvd.pojo.cwe.ModesOfIntroduction;
import com.csw.data.nvd.pojo.cwe.ModificationType;
import com.csw.data.nvd.pojo.cwe.NoteType;
import com.csw.data.nvd.pojo.cwe.PlatformType;
import com.csw.data.nvd.pojo.cwe.PotentialMitigation;
import com.csw.data.nvd.pojo.cwe.PreviousEntryNameType;
import com.csw.data.nvd.pojo.cwe.Reference;
import com.csw.data.nvd.pojo.cwe.RelatedAttackPatternType;
import com.csw.data.nvd.pojo.cwe.Relationship;
import com.csw.data.nvd.pojo.cwe.Source;
import com.csw.data.nvd.pojo.cwe.SubmissionRoot;
import com.csw.data.nvd.pojo.cwe.TaxonomyMapping;
import com.csw.data.nvd.pojo.cwe.WeaknessRoot;
import com.csw.data.nvd.pojo.cwe.WeaknessRoot.Abstraction;
import com.csw.data.nvd.pojo.cwe.WeaknessRoot.Status;
import com.csw.data.nvd.pojo.cwe.WeaknessRoot.Structure;
import com.csw.data.util.HashingUtil;
import com.csw.data.util.ParserConstants;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

@Component
public class CweDataHelper {
	
	private static final Logger logger = LoggerFactory.getLogger(CweDataHelper.class);
	
	@Value("${data.local.flag}")
	private boolean localFlag;

	@Value("${livekeep.base.path}")
	private String liveKeepBasePath;

	@Value("${cwe.path}")
	private String cwePath;
	
	@Value("${data.livekeep.bucketName}")
	private String s3BucketName;
	
	@Value("${parse.cwe.mitre.url.prefix}")
	private String mitreUrlPrefix;
	
	@Autowired
	private AmazonS3Client amazonS3Client;
	
	public Map<String, Reference> extractExternalReferences(ExternalReferences externalReferences) {
		Map<String, Reference> externalReferenceListTemp = new HashMap<>();
		
		if(null != externalReferences && CollectionUtils.isEmpty(externalReferences.getExternalReference())) {
			return externalReferenceListTemp;
		}
		
		for(ExternalReferenceType externalReferenceType: externalReferences.getExternalReference()) {
			Reference reference = new Reference();
			Date urlDate = xmlGregorianCalendarToDate(externalReferenceType.getURLDate());
			SimpleDateFormat urlDateFormat = new SimpleDateFormat(ParserConstants.DEFAULT_DATE_FORMAT);
			reference.setId(externalReferenceType.getReferenceID());
			reference.setTitle(externalReferenceType.getTitle());
			reference.setEdition(externalReferenceType.getEdition());
			reference.setPublication(externalReferenceType.getPublication());
			reference.setPublisher(externalReferenceType.getPublisher());
			reference.setUrl(externalReferenceType.getURL());
			reference.setUrlDate(null != urlDate ? urlDateFormat.format(urlDate) : null);
			reference.setPublicationYear(null != externalReferenceType.getPublicationYear() ? String.valueOf(externalReferenceType.getPublicationYear().getYear()) : null);
			reference.setPublicationDay(null != externalReferenceType.getPublicationDay() ? String.valueOf(externalReferenceType.getPublicationDay().getDay()) : null);
			reference.setPublicationMonth(null != externalReferenceType.getPublicationMonth() ? String.valueOf(externalReferenceType.getPublicationMonth().getMonth()) : null);
			reference.setAuthor(addReferenceAuthors(externalReferenceType.getAuthor()));
			externalReferenceListTemp.put(externalReferenceType.getReferenceID(), reference);
		}
		return externalReferenceListTemp;
	}
	
	public void extractWeakness(List<WeaknessType> weaknesses, Map<String, Reference> externalReferenceList, String sourceFilePath) {
		for (WeaknessType weakness : weaknesses) {
			WeaknessRoot cwe = createCwe(weakness, externalReferenceList);
			writeToLiveKeep(cwe, sourceFilePath);
		}
	}

	public void extractViews(Views viewsType, Map<String, Reference> externalReferenceList, String sourceFilePath) {
		if(!CollectionUtils.isEmpty(viewsType.getView())) {
			for(ViewType viewType: viewsType.getView()) {
				WeaknessRoot view = createView(viewType, externalReferenceList);
				writeToLiveKeep(view, sourceFilePath);
			}
		}
	}
	
	public void extractCategories(Categories categories, Map<String, Reference> externalReferenceList, String sourceFilePath) {
		if(!CollectionUtils.isEmpty(categories.getCategory())) {
			for(CategoryType categoryType: categories.getCategory()) {
				WeaknessRoot category = createCategory(categoryType, externalReferenceList);
				writeToLiveKeep(category, sourceFilePath);
			}
		}
	}

	private WeaknessRoot createCwe(WeaknessType weaknessType, Map<String, Reference> externalReferenceList) {
		com.csw.data.nvd.pojo.cwe.WeaknessRoot weakness = new com.csw.data.nvd.pojo.cwe.WeaknessRoot();
		weakness.setId("CWE-" + weaknessType.getID());
		weakness.setWeaknessType("Weakness");
		weakness.setSources(addWeaknessSources(String.valueOf(weaknessType.getID()), ParserConstants.MITRE));
		weakness.setTitle(weaknessType.getName());
		weakness.setAbstraction(Abstraction.fromValue(weaknessType.getAbstraction().value()));
		weakness.setStatus(Status.fromValue(weaknessType.getStatus().value()));
		weakness.setStructure(Structure.fromValue(weaknessType.getStructure().value()));
		weakness.setDescription(weaknessType.getDescription());
		weakness.setExtendedDescription(null != weaknessType.getExtendedDescription() ? String.valueOf(weaknessType.getExtendedDescription().getContent().get(0)) : null);
		weakness.setLikelihoodOfExploit(null != weaknessType.getLikelihoodOfExploit() ? weaknessType.getLikelihoodOfExploit().value() : null);
		
		if(null != weaknessType.getRelatedWeaknesses()) {
			List<com.csw.data.nvd.pojo.cwe.RelatedWeakness> relatedWeaknesses = new ArrayList<>();
			for (RelatedWeakness relatedWeaknessType : weaknessType.getRelatedWeaknesses().getRelatedWeakness()) {
				com.csw.data.nvd.pojo.cwe.RelatedWeakness relatedWeakness = new com.csw.data.nvd.pojo.cwe.RelatedWeakness();
				relatedWeakness.setId(String.valueOf(relatedWeaknessType.getCWEID()));
				relatedWeakness.setNature(null != relatedWeaknessType.getNature() ? relatedWeaknessType.getNature().value() : null);
				relatedWeakness.setChainId(String.valueOf(relatedWeaknessType.getChainID()));
				relatedWeakness.setViewId(String.valueOf(relatedWeaknessType.getViewID()));
				relatedWeakness.setOrdinal(null != relatedWeaknessType.getOrdinal() ? relatedWeaknessType.getOrdinal().value() : null);
				relatedWeaknesses.add(relatedWeakness);
			}
			weakness.setRelatedWeaknesses(relatedWeaknesses);
		}
		
		if(null != weaknessType.getWeaknessOrdinalities()) {
			List<com.csw.data.nvd.pojo.cwe.WeaknessOrdinality> weaknessOrdinalities = new ArrayList<>();
			for (WeaknessOrdinality weaknessOrdinalityType : weaknessType.getWeaknessOrdinalities().getWeaknessOrdinality()) {
				com.csw.data.nvd.pojo.cwe.WeaknessOrdinality weaknessOrdinality = new com.csw.data.nvd.pojo.cwe.WeaknessOrdinality();
				weaknessOrdinality.setOrdinality(weaknessOrdinalityType.getOrdinality().value());
				weaknessOrdinality.setDescription(weaknessOrdinalityType.getDescription());
				weaknessOrdinalities.add(weaknessOrdinality);
			}
			weakness.setWeaknessOrdinalities(weaknessOrdinalities);
		}
		
		if(null != weaknessType.getApplicablePlatforms()) {
			ApplicablePlatformsRoot applicablePlatforms = new ApplicablePlatformsRoot();
			if(null != weaknessType.getApplicablePlatforms().getLanguage()) {
				List<PlatformType> languageList = new ArrayList<>();
				for(Language languageType: weaknessType.getApplicablePlatforms().getLanguage()) {
					PlatformType language = new PlatformType();
					language.setName(null != languageType.getName() ? languageType.getName() : null);
					language.setClazz(null != languageType.getClazz() ? languageType.getClazz().value() : null);
					language.setPrevalence(null != languageType.getPrevalence() ? languageType.getPrevalence().value() : null);
					languageList.add(language);
				}
				applicablePlatforms.setLanguage(languageList);
			}
			if(null != weaknessType.getApplicablePlatforms().getOperatingSystem()) {
				List<PlatformType> operatingSystemList = new ArrayList<>();
				for(OperatingSystem operatingSystemType: weaknessType.getApplicablePlatforms().getOperatingSystem()) {
					PlatformType operatingSystem = new PlatformType();
					operatingSystem.setName(null != operatingSystemType.getName() ? operatingSystemType.getName().value() : null);
					operatingSystem.setClazz(null != operatingSystemType.getClazz() ? operatingSystemType.getClazz().value() : null);
					operatingSystem.setPrevalence(null != operatingSystemType.getPrevalence() ? operatingSystemType.getPrevalence().value() : null);
					operatingSystemList.add(operatingSystem);
				}
				applicablePlatforms.setOperatingSystem(operatingSystemList);
			}
			if(null != weaknessType.getApplicablePlatforms().getArchitecture()) {
				List<PlatformType> architectureList = new ArrayList<>();
				for(Architecture architectureType: weaknessType.getApplicablePlatforms().getArchitecture()) {
					PlatformType architecture = new PlatformType();
					architecture.setName(null != architectureType.getName() ? architectureType.getName().value() : null);
					architecture.setClazz(null != architectureType.getClazz() ? architectureType.getClazz().value() : null);
					architecture.setPrevalence(null != architectureType.getPrevalence() ? architectureType.getPrevalence().value() : null);
					architectureList.add(architecture);
				}
				applicablePlatforms.setArchitecture(architectureList);
			}
			if(null != weaknessType.getApplicablePlatforms().getTechnology()) {
				List<PlatformType> technologyList = new ArrayList<>();
				for(Technology technologyType: weaknessType.getApplicablePlatforms().getTechnology()) {
					PlatformType technology = new PlatformType();
					technology.setName(null != technologyType.getName() ? technologyType.getName().value() : null);
					technology.setClazz(null != technologyType.getClazz() ? technologyType.getClazz().value() : null);
					technology.setPrevalence(null != technologyType.getPrevalence() ? technologyType.getPrevalence().value() : null);
					technologyList.add(technology);
				}
				applicablePlatforms.setTechnology(technologyList);
			}
			weakness.setApplicablePlatforms(applicablePlatforms);
		}
		
		if(null != weaknessType.getAlternateTerms()) {
			List<AlternateTermType> alternateTerms = new ArrayList<>();
			for(AlternateTerm alternateTermsType: weaknessType.getAlternateTerms().getAlternateTerm()) {
				AlternateTermType alternateTerm = new AlternateTermType();
				alternateTerm.setTerm(alternateTermsType.getTerm());
				alternateTerm.setDescription(null != alternateTermsType.getDescription() ? String.valueOf(alternateTermsType.getDescription().getContent().get(0)) : null);
				alternateTerms.add(alternateTerm);
			}
			weakness.setAlternateTerms(alternateTerms);
		}
		
		if(null != weaknessType.getModesOfIntroduction()) {
			List<ModesOfIntroduction> modesOfIntroductions = new ArrayList<>();
			for(Introduction introductionType: weaknessType.getModesOfIntroduction().getIntroduction()) {
				ModesOfIntroduction modesOfIntroduction = new ModesOfIntroduction();
				modesOfIntroduction.setNote(null != introductionType.getNote() ? String.valueOf(introductionType.getNote().getContent().get(0)) : null);
				modesOfIntroduction.setPhase(introductionType.getPhase().value());
				modesOfIntroductions.add(modesOfIntroduction);
			}
			weakness.setModesOfIntroduction(modesOfIntroductions);
		}
		
		if(null != weaknessType.getCommonConsequences()) {
			List<CommonConsequence> commonConsequences = new ArrayList<>();
			for(Consequence consequenceType :weaknessType.getCommonConsequences().getConsequence()) {
				CommonConsequence commonConsequence = new CommonConsequence();
				commonConsequence.setLikelihood(null != consequenceType.getLikelihood() ? consequenceType.getLikelihood().value() : null);
				commonConsequence.setNote(null != consequenceType.getNote() ? String.valueOf(consequenceType.getNote().getContent().get(0)) : null);
				commonConsequence.setImpact(setCommonConsequenceImpact(consequenceType.getImpact()));
				commonConsequence.setScope(setCommonConsequenceScope(consequenceType.getScope()));
				commonConsequences.add(commonConsequence);
			}
			weakness.setCommonConsequences(commonConsequences);
		}
		
		if(null != weaknessType.getDetectionMethods()) {
			List<DetectionMethod> detectionMethods = new ArrayList<>();
			for(com.csw.data.nvd.jaxb.cwe.DetectionMethodsType.DetectionMethod detectionMethodType: weaknessType.getDetectionMethods().getDetectionMethod()) {
				DetectionMethod detectionMethod = new DetectionMethod();
				detectionMethod.setDetectionMethodID(detectionMethodType.getDetectionMethodID());
				detectionMethod.setMethod(null != detectionMethodType.getMethod() ? detectionMethodType.getMethod().value() : null);
				detectionMethod.setDescription(addStructuredTypes(detectionMethodType.getDescription()));
				detectionMethod.setEffectiveness(null != detectionMethodType.getEffectiveness() ? detectionMethodType.getEffectiveness().value() : null);
				detectionMethod.setEffectivenessNotes(addStructuredTypes(detectionMethodType.getEffectivenessNotes()));
				detectionMethods.add(detectionMethod);
			}
			weakness.setDetectionMethods(detectionMethods);
		}
		
		if(null != weaknessType.getPotentialMitigations()) {
			List<PotentialMitigation> potentialMitigations = new ArrayList<>();
			for(Mitigation potentialMitigationType: weaknessType.getPotentialMitigations().getMitigation()) {
				PotentialMitigation potentialMitigation = new PotentialMitigation();
				potentialMitigation.setMitigationId(null != potentialMitigationType.getMitigationID() ? potentialMitigationType.getMitigationID() : null);
				potentialMitigation.setStrategy(null != potentialMitigationType.getStrategy() ? potentialMitigationType.getStrategy().value() : null);
				potentialMitigation.setEffectiveness(null != potentialMitigationType.getEffectiveness() ? potentialMitigationType.getEffectiveness().value() : null);
				potentialMitigation.setPhases(addMitigationPhases(potentialMitigationType.getPhase()));
				potentialMitigation.setDescription(addStructuredTypes(potentialMitigationType.getDescription()));
				potentialMitigation.setEffectivenessNotes(addStructuredTypes(potentialMitigationType.getEffectivenessNotes()));
				potentialMitigations.add(potentialMitigation);
			}
			weakness.setPotentialMitigations(potentialMitigations);
		}
		
		if(null != weaknessType.getRelatedAttackPatterns()) {
			List<RelatedAttackPatternType> relatedAttackPatterns = new ArrayList<>();
			for(RelatedAttackPattern relatedAttackPattern: weaknessType.getRelatedAttackPatterns().getRelatedAttackPattern()) {
				RelatedAttackPatternType relatedAttackPatternType = new RelatedAttackPatternType();
				relatedAttackPatternType.setId(relatedAttackPattern.getCAPECID().toString());
				relatedAttackPatterns.add(relatedAttackPatternType);
			}
			weakness.setRelatedAttackPattern(relatedAttackPatterns);
		}
		
		if(null != weaknessType.getFunctionalAreas()) {
			List<String> functionalAreas = new ArrayList<>();
			for(FunctionalAreaEnumeration functionalAreaEnumeration: weaknessType.getFunctionalAreas().getFunctionalArea()) {
				functionalAreas.add(functionalAreaEnumeration.value());
			}
			weakness.setFunctionalAreas(functionalAreas);
		}
		
		if(null != weaknessType.getAffectedResources()) {
			List<String> affectedResources = new ArrayList<>();
			for (ResourceEnumeration resourceEnumeration : weaknessType.getAffectedResources().getAffectedResource()) {
				affectedResources.add(resourceEnumeration.value());
			}
			weakness.setAffectedResources(affectedResources);
		}
		
		if(null != weaknessType.getTaxonomyMappings()) {
			List<TaxonomyMapping> taxonomyMappings = new ArrayList<>();
			for(com.csw.data.nvd.jaxb.cwe.TaxonomyMappingsType.TaxonomyMapping taxonomyMappingType: weaknessType.getTaxonomyMappings().getTaxonomyMapping()) {
				TaxonomyMapping taxonomyMapping = new TaxonomyMapping();
				taxonomyMapping.setEntryName(taxonomyMappingType.getEntryName());
				taxonomyMapping.setEntryId(taxonomyMappingType.getEntryID());
				taxonomyMapping.setTaxonomyName(taxonomyMappingType.getTaxonomyName());
				taxonomyMapping.setMappingFit(null != taxonomyMappingType.getMappingFit() ? taxonomyMappingType.getMappingFit().value() : null);
				taxonomyMappings.add(taxonomyMapping);
			}
			weakness.setTaxonomyMappings(taxonomyMappings);
		}
		
		if(null != weaknessType.getNotes()) {
			List<NoteType> notes = new ArrayList<>();
			for(Note noteType: weaknessType.getNotes().getNote()) {
				NoteType note = new NoteType();
				note.setNote(String.valueOf(noteType.getContent().get(0)));
				note.setType(noteType.getType().value());
				notes.add(note);
			}
			weakness.setNotes(notes);
		}
		weakness.setReferences(addReferences(weaknessType.getReferences(), externalReferenceList));
		weakness.setContentHistory(addContentHistory(weaknessType.getContentHistory()));		
		return weakness;
	}
	
	private WeaknessRoot createView(ViewType viewType, Map<String, Reference> externalReferenceList) {
		com.csw.data.nvd.pojo.cwe.WeaknessRoot weakness = new com.csw.data.nvd.pojo.cwe.WeaknessRoot();
		weakness.setId("CWE-" + viewType.getID());
		weakness.setWeaknessType("View");
		weakness.setSources(addWeaknessSources(String.valueOf(viewType.getID()), ParserConstants.MITRE));
		weakness.setTitle(viewType.getName());
		weakness.setViewType(com.csw.data.nvd.pojo.cwe.WeaknessRoot.ViewType.fromValue(viewType.getType().value()));
		weakness.setStatus(Status.fromValue(viewType.getStatus().value()));
		weakness.setObjective(null != viewType.getObjective() ? String.valueOf(viewType.getObjective().getContent().get(0)) : null);
		weakness.setFilter(viewType.getFilter());
		
		if(null != viewType.getAudience()) {
			List<AudienceType> audiences = new ArrayList<>();
			for(Stakeholder stakeholder: viewType.getAudience().getStakeholder()) {
				AudienceType audienceType = new AudienceType();
				audienceType.setType(stakeholder.getType().value());
				audienceType.setDescription(stakeholder.getDescription());
				audiences.add(audienceType);
			}
			weakness.setAudience(audiences);
		}
		
		if(null != viewType.getMembers()) {
			List<Relationship> relationships = new ArrayList<>();
			for(JAXBElement<MemberType> memberTypeJaxb: viewType.getMembers().getContent()) {
				MemberType memberType = memberTypeJaxb.getValue();
				Relationship relationship = new Relationship();
				relationship.setId(String.valueOf(memberType.getCWEID()));
				relationship.setType(memberTypeJaxb.getName().getLocalPart());
				relationship.setViewId(String.valueOf(memberType.getViewID()));
				relationships.add(relationship);
			}
			weakness.setRelationships(relationships);
		}
		
		if(null != viewType.getNotes()) {
			List<NoteType> notes = new ArrayList<>();
			for(Note noteType: viewType.getNotes().getNote()) {
				NoteType note = new NoteType();
				note.setNote(String.valueOf(noteType.getContent().get(0)));
				note.setType(noteType.getType().value());
				notes.add(note);
			}
			weakness.setNotes(notes);
		}
		weakness.setReferences(addReferences(viewType.getReferences(), externalReferenceList));
		weakness.setContentHistory(addContentHistory(viewType.getContentHistory()));
		return weakness;
	}
	
	private WeaknessRoot createCategory(CategoryType categoryType, Map<String, Reference> externalReferenceList) {
		com.csw.data.nvd.pojo.cwe.WeaknessRoot weakness = new com.csw.data.nvd.pojo.cwe.WeaknessRoot();
		weakness.setId("CWE-" + categoryType.getID());
		weakness.setWeaknessType("Category");
		weakness.setSources(addWeaknessSources(String.valueOf(categoryType.getID()), ParserConstants.MITRE));
		weakness.setTitle(categoryType.getName());
		weakness.setSummary(null != categoryType.getSummary() ? String.valueOf(categoryType.getSummary().getContent().get(0)) : null);
		weakness.setStatus(Status.fromValue(categoryType.getStatus().value()));
		
		if(null != categoryType.getRelationships()) {
			List<Relationship> relationships = new ArrayList<>();
			for(JAXBElement<MemberType> memberTypeJaxb: categoryType.getRelationships().getContent()) {
				MemberType memberType = memberTypeJaxb.getValue();
				Relationship relationship = new Relationship();
				relationship.setId(String.valueOf(memberType.getCWEID()));
				relationship.setType(memberTypeJaxb.getName().getLocalPart());
				relationship.setViewId(String.valueOf(memberType.getViewID()));
				relationships.add(relationship);
			}
			weakness.setRelationships(relationships);
		}
		
		if(null != categoryType.getTaxonomyMappings()) {
			List<TaxonomyMapping> taxonomyMappings = new ArrayList<>();
			for(com.csw.data.nvd.jaxb.cwe.TaxonomyMappingsType.TaxonomyMapping taxonomyMappingType: categoryType.getTaxonomyMappings().getTaxonomyMapping()) {
				TaxonomyMapping taxonomyMapping = new TaxonomyMapping();
				taxonomyMapping.setEntryName(taxonomyMappingType.getEntryName());
				taxonomyMapping.setEntryId(taxonomyMappingType.getEntryID());
				taxonomyMapping.setTaxonomyName(taxonomyMappingType.getTaxonomyName());
				taxonomyMapping.setMappingFit(null != taxonomyMappingType.getMappingFit() ? taxonomyMappingType.getMappingFit().value() : null);
				taxonomyMappings.add(taxonomyMapping);
			}
			weakness.setTaxonomyMappings(taxonomyMappings);
		}
		
		if(null != categoryType.getNotes()) {
			List<NoteType> notes = new ArrayList<>();
			for(Note noteType: categoryType.getNotes().getNote()) {
				NoteType note = new NoteType();
				note.setNote(String.valueOf(noteType.getContent().get(0)));
				note.setType(noteType.getType().value());
				notes.add(note);
			}
			weakness.setNotes(notes);
		}
		weakness.setReferences(addReferences(categoryType.getReferences(), externalReferenceList));
		weakness.setContentHistory(addContentHistory(categoryType.getContentHistory()));
		return weakness;
	}
	
	private void writeToLiveKeep(WeaknessRoot weakness, String sourceFilePath) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			//writing the weakness to a local filesystem
			if(localFlag) {
				String cweLiveKeepDirectory = liveKeepBasePath + cwePath + "/" + ParserConstants.MITRE + "/";
				String cweFile = cweLiveKeepDirectory + weakness.getId() + ParserConstants.JSON_FILE_EXTENSION;
				mapper.writeValue(new File(cweFile), weakness);
				generateMetaFile(new File(cweFile), sourceFilePath, cweLiveKeepDirectory);
			}
			//pushing the file to s3 bucket
			else {
				S3Client s3Client = amazonS3Client.buildAmazonS3Client();
				String objectKey = cwePath + "/mitre/" + weakness.getId() + ParserConstants.JSON_FILE_EXTENSION;
				PutObjectRequest request = PutObjectRequest.builder().bucket(s3BucketName).key(objectKey).build();
				s3Client.putObject(request, RequestBody.fromBytes(mapper.writeValueAsBytes(weakness)));
			}
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private List<Source> addWeaknessSources(String weaknessId, String sourceName) {
		List<Source> sources = new ArrayList<>();
		Source source = new Source();
		StringBuilder sourceUrlBuilder = new StringBuilder().append(mitreUrlPrefix).append(weaknessId).append(ParserConstants.HTML_FILE_EXTENSION);
		source.setSourceName(sourceName);
		source.setSourceUrl(sourceUrlBuilder.toString());
		sources.add(source);
		return sources;
	}
	
	private List<Reference> addReferences(ReferencesType referencesType, Map<String, Reference> externalReferenceList) {
		List<Reference> referenceList = new ArrayList<>();
		if(null == referencesType || CollectionUtils.isEmpty(referencesType.getReference())) {
			return referenceList;
		}
		for(com.csw.data.nvd.jaxb.cwe.ReferencesType.Reference referenceType: referencesType.getReference()) {
			Reference reference = externalReferenceList.get(referenceType.getExternalReferenceID());
			reference.setSection(referenceType.getSection());
			referenceList.add(reference);
		}
		return referenceList;
	}
	
	private ContentHistoryRoot addContentHistory(ContentHistoryType contentHistoryType) {
		ContentHistoryRoot contentHistory = new ContentHistoryRoot();
		contentHistory.setSubmission(addContentHistorySubmission(contentHistoryType.getSubmission()));
		contentHistory.setModification(addContentHistoryModification(contentHistoryType.getModification()));
		contentHistory.setContribution(addContentHistoryContribution(contentHistoryType.getContribution()));
		contentHistory.setPreviousEntryName(addContentHistoryPreviousEntryDetails(contentHistoryType.getPreviousEntryName()));
		return contentHistory;
	}
	
	private List<PreviousEntryNameType> addContentHistoryPreviousEntryDetails(List<PreviousEntryName> previousEntryNameList) {
		List<PreviousEntryNameType> previousEntryNames = new ArrayList<>();
		if(CollectionUtils.isEmpty(previousEntryNameList)) {
			return previousEntryNames;
		}
		for(PreviousEntryName previousEntryName: previousEntryNameList) {
			PreviousEntryNameType previousEntryNameType = new PreviousEntryNameType();
			Date submissionDate = xmlGregorianCalendarToDate(previousEntryName.getDate());
			SimpleDateFormat dateFormat = new SimpleDateFormat(ParserConstants.DEFAULT_DATE_FORMAT);
			
			previousEntryNameType.setName(previousEntryName.getValue());
			previousEntryNameType.setSubmissionDate(dateFormat.format(submissionDate));
			previousEntryNames.add(previousEntryNameType);
		}
		return previousEntryNames;
	}

	private List<ContributionType> addContentHistoryContribution(List<Contribution> contributions) {
		List<ContributionType> contributionTypes = new ArrayList<>();
		if(CollectionUtils.isEmpty(contributions)) {
			return contributionTypes;
		}
		for(Contribution contribution: contributions) {
			ContributionType contributionType = new ContributionType();
			Date modificationDate = xmlGregorianCalendarToDate(contribution.getContributionDate());
			SimpleDateFormat dateFormat = new SimpleDateFormat(ParserConstants.DEFAULT_DATE_FORMAT);
			
			contributionType.setType(contribution.getType());
			contributionType.setContributionName(contribution.getContributionName());
			contributionType.setContributionOrganization(contribution.getContributionOrganization());
			contributionType.setContributionDate(dateFormat.format(modificationDate));
			contributionType.setContributionComment(contribution.getContributionComment());
			contributionTypes.add(contributionType);
		}
		return contributionTypes;
	}

	private List<ModificationType> addContentHistoryModification(List<Modification> modifications) {
		List<ModificationType> modificationTypes = new ArrayList<>();
		if(CollectionUtils.isEmpty(modifications)) {
			return modificationTypes;
		}
		for(Modification modification: modifications) {
			ModificationType modificationType = new ModificationType();
			Date modificationDate = xmlGregorianCalendarToDate(modification.getModificationDate());
			SimpleDateFormat dateFormat = new SimpleDateFormat(ParserConstants.DEFAULT_DATE_FORMAT);
			
			modificationType.setModificationName(modification.getModificationName());
			modificationType.setModificationOrganization(modification.getModificationOrganization());
			modificationType.setModificationDate(dateFormat.format(modificationDate));
			modificationType.setModificationImportance(null != modification.getModificationImportance() ? modification.getModificationImportance().value() : null);
			modificationType.setModificationComment(modification.getModificationComment());
			modificationTypes.add(modificationType);
		}
		return modificationTypes;
	}

	private SubmissionRoot addContentHistorySubmission(Submission submission) {
		if(null == submission) {
			return null;
		}
		SubmissionRoot submissionRoot = new SubmissionRoot();
		Date submissionDate = xmlGregorianCalendarToDate(submission.getSubmissionDate());
		SimpleDateFormat dateFormat = new SimpleDateFormat(ParserConstants.DEFAULT_DATE_FORMAT);
		
		submissionRoot.setSubmissionName(submission.getSubmissionName());
		submissionRoot.setSubmissionOrganization(submission.getSubmissionOrganization());
		submissionRoot.setSubmissionDate(dateFormat.format(submissionDate));
		submissionRoot.setSubmissionComment(submission.getSubmissionComment());
		return submissionRoot;
	}

	private List<String> addReferenceAuthors(List<String> authors) {
		List<String> authorList = new ArrayList<>();
		if(!CollectionUtils.isEmpty(authors)) {
			authorList.addAll(authors);
		}
		return authorList;
	}

	private List<String> addMitigationPhases(List<PhaseEnumeration> phaseEnumerations) {
		List<String> phases = new ArrayList<>();
		for (PhaseEnumeration phaseEnumeration : phaseEnumerations) {
			phases.add(phaseEnumeration.value());
		}
		return phases;
	}

	private List<String> addStructuredTypes(StructuredTextType structuredTextType) {
		List<String> structuredNotes = new ArrayList<>();
		if (null != structuredTextType) {
			Object contentsObject = structuredTextType.getContent();
			List<Object> contents = (List<Object>) contentsObject;
			for (Object content : contents) {
				structuredNotes.add((String.valueOf(content)));
			}
		}
		return structuredNotes;
	}

	private List<String> setCommonConsequenceScope(List<ScopeEnumeration> scopeEnumerations) {
		List<String> scopes = new ArrayList<>();
		for (ScopeEnumeration scopeEnumeration : scopeEnumerations) {
			scopes.add(scopeEnumeration.value());
		}
		return scopes;
	}

	private List<String> setCommonConsequenceImpact(List<TechnicalImpactEnumeration> impactEnumerations) {
		List<String> technicalImpacts = new ArrayList<>();
		for (TechnicalImpactEnumeration technicalImpactEnumeration : impactEnumerations) {
			technicalImpacts.add(technicalImpactEnumeration.value());
		}
		return technicalImpacts;
	}

	private void generateMetaFile(File file, String sourceFilePath, String cweLiveKeepDirectory) {
		try {
			String shaChecksum = HashingUtil.getShaChecksum(file);
			ObjectMapper mapper = new ObjectMapper();
			Map<String, Object> map = new HashMap<>();
			map.put("sha256", shaChecksum);
			List<String> sourceFileLocation = new ArrayList<>();
			sourceFileLocation.add(sourceFilePath);
			map.put("sourceFiles", sourceFileLocation);
			String[] fileNameSplitArray = file.getName().split("\\.");
			Arrays.deepToString(fileNameSplitArray);
			mapper.writeValue(Paths.get(cweLiveKeepDirectory + fileNameSplitArray[0] + ".meta.json").toFile(), map);
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage());
		} catch (IOException e) {
			logger.error("IOException while reading the Json file");
		}
	}
	
	private Date xmlGregorianCalendarToDate(XMLGregorianCalendar urlDate) {
		if(null == urlDate) {
			return null;
		}
		return urlDate.toGregorianCalendar().getTime();
	}

}
