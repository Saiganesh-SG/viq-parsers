package com.csw.data.mitre.parser.helper;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.csw.data.mitre.cwe.jaxb.AlternateTermsType.AlternateTerm;
import com.csw.data.mitre.cwe.jaxb.ApplicablePlatformsType.Architecture;
import com.csw.data.mitre.cwe.jaxb.ApplicablePlatformsType.Language;
import com.csw.data.mitre.cwe.jaxb.ApplicablePlatformsType.OperatingSystem;
import com.csw.data.mitre.cwe.jaxb.ApplicablePlatformsType.Technology;
import com.csw.data.mitre.cwe.jaxb.AudienceType.Stakeholder;
import com.csw.data.mitre.cwe.jaxb.CategoryType;
import com.csw.data.mitre.cwe.jaxb.CommonConsequencesType.Consequence;
import com.csw.data.mitre.cwe.jaxb.ContentHistoryType;
import com.csw.data.mitre.cwe.jaxb.ContentHistoryType.Contribution;
import com.csw.data.mitre.cwe.jaxb.ContentHistoryType.Modification;
import com.csw.data.mitre.cwe.jaxb.ContentHistoryType.PreviousEntryName;
import com.csw.data.mitre.cwe.jaxb.ContentHistoryType.Submission;
import com.csw.data.mitre.cwe.jaxb.ExternalReferenceType;
import com.csw.data.mitre.cwe.jaxb.FunctionalAreaEnumeration;
import com.csw.data.mitre.cwe.jaxb.MemberType;
import com.csw.data.mitre.cwe.jaxb.ModesOfIntroductionType.Introduction;
import com.csw.data.mitre.cwe.jaxb.NotesType.Note;
import com.csw.data.mitre.cwe.jaxb.PhaseEnumeration;
import com.csw.data.mitre.cwe.jaxb.PotentialMitigationsType.Mitigation;
import com.csw.data.mitre.cwe.jaxb.ReferencesType;
import com.csw.data.mitre.cwe.jaxb.RelatedAttackPatternsType.RelatedAttackPattern;
import com.csw.data.mitre.cwe.jaxb.RelatedWeaknessesType.RelatedWeakness;
import com.csw.data.mitre.cwe.jaxb.ResourceEnumeration;
import com.csw.data.mitre.cwe.jaxb.ScopeEnumeration;
import com.csw.data.mitre.cwe.jaxb.StructuredTextType;
import com.csw.data.mitre.cwe.jaxb.TechnicalImpactEnumeration;
import com.csw.data.mitre.cwe.jaxb.ViewType;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog.Categories;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog.ExternalReferences;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog.Views;
import com.csw.data.mitre.cwe.jaxb.WeaknessOrdinalitiesType.WeaknessOrdinality;
import com.csw.data.mitre.cwe.jaxb.WeaknessType;
import com.csw.data.mitre.cwe.pojo.AlternateTermType;
import com.csw.data.mitre.cwe.pojo.ApplicablePlatformsRoot;
import com.csw.data.mitre.cwe.pojo.AudienceType;
import com.csw.data.mitre.cwe.pojo.CommonConsequence;
import com.csw.data.mitre.cwe.pojo.ContentHistoryRoot;
import com.csw.data.mitre.cwe.pojo.ContributionType;
import com.csw.data.mitre.cwe.pojo.DetectionMethod;
import com.csw.data.mitre.cwe.pojo.ModesOfIntroduction;
import com.csw.data.mitre.cwe.pojo.ModificationType;
import com.csw.data.mitre.cwe.pojo.NoteType;
import com.csw.data.mitre.cwe.pojo.PlatformType;
import com.csw.data.mitre.cwe.pojo.PotentialMitigation;
import com.csw.data.mitre.cwe.pojo.PreviousEntryNameType;
import com.csw.data.mitre.cwe.pojo.Reference;
import com.csw.data.mitre.cwe.pojo.RelatedAttackPatternType;
import com.csw.data.mitre.cwe.pojo.Source;
import com.csw.data.mitre.cwe.pojo.SubmissionRoot;
import com.csw.data.mitre.cwe.pojo.TaxonomyMapping;
import com.csw.data.mitre.cwe.pojo.WeaknessMetaData;
import com.csw.data.mitre.cwe.pojo.WeaknessRoot;
import com.csw.data.mitre.cwe.pojo.WeaknessRoot.Abstraction;
import com.csw.data.mitre.cwe.pojo.WeaknessRoot.Status;
import com.csw.data.mitre.cwe.pojo.WeaknessRoot.Structure;
import com.csw.data.mitre.parser.LivekeepService;
import com.csw.data.util.ParserConstants;

/**
 * The Class CweDataHelper.
 */
@Component
public class CweDataHelper {

	/** The Constant LOGGER. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CweDataHelper.class);

	/** The Constant CWE_PRFIX. */
	public static final String CWE_PREFIX = "CWE-";

	/** The Constant CATEGORY. */
	public static final String CATEGORY = "Category";

	/** The mitre url prefix. */
	@Value("${parse.cwe.mitre.url.prefix}")
	private String mitreUrlPrefix;

	/** The livekeep service. */
	@Autowired
	@Qualifier("LivekeepService")
	private LivekeepService livekeepService;

	/**
	 * Extract external references.
	 *
	 * @param externalReferences the external references
	 * @return the map
	 */
	public Map<String, Reference> extractExternalReferences(ExternalReferences externalReferences) {
		Map<String, Reference> externalReferenceList = new HashMap<>();

		if(null != externalReferences && CollectionUtils.isEmpty(externalReferences.getExternalReference())) {
			return externalReferenceList;
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
			externalReferenceList.put(externalReferenceType.getReferenceID(), reference);
		}
		return externalReferenceList;
	}

	/**
	 * Extract weakness.
	 *
	 * @param weaknesses the weaknesses
	 * @param externalReferenceList the external reference list
	 * @param weaknessMetaDataList the weakness meta data list
	 * @return the list
	 */
	public List<WeaknessRoot> extractWeakness(List<WeaknessType> weaknesses, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		List<WeaknessRoot> weaknessList = new ArrayList<>();
		for (WeaknessType weakness : weaknesses) {
			WeaknessRoot cwe = createCwe(weakness, externalReferenceList, weaknessMetaDataList);
			weaknessList.add(cwe);
		}
		return weaknessList;
	}

	/**
	 * Extract views.
	 *
	 * @param viewsType the views type
	 * @param externalReferenceList the external reference list
	 * @param weaknessMetaDataList the weakness meta data list
	 * @return the list
	 */
	public List<WeaknessRoot> extractViews(Views viewsType, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		List<WeaknessRoot> weaknessList = new ArrayList<>();
		if(!CollectionUtils.isEmpty(viewsType.getView())) {
			for(ViewType viewType: viewsType.getView()) {
				WeaknessRoot view = createView(viewType, externalReferenceList, weaknessMetaDataList);
				weaknessList.add(view);
			}
		}
		return weaknessList;
	}

	/**
	 * Extract categories.
	 *
	 * @param categories the categories
	 * @param externalReferenceList the external reference list
	 * @param weaknessMetaDataList the weakness meta data list
	 * @return the list
	 */
	public List<WeaknessRoot> extractCategories(Categories categories, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		List<WeaknessRoot> weaknessList = new ArrayList<>();
		if(!CollectionUtils.isEmpty(categories.getCategory())) {
			for(CategoryType categoryType: categories.getCategory()) {
				WeaknessRoot category = createCategory(categoryType, externalReferenceList, weaknessMetaDataList);
				weaknessList.add(category);
			}
		}
		return weaknessList;
	}

	/**
	 * Extract weakness meta data.
	 *
	 * @param weaknessCatalog the weakness catalog
	 * @return the map
	 */
	public Map<String, WeaknessMetaData> extractWeaknessMetaData(WeaknessCatalog weaknessCatalog) {
		Map<String, WeaknessMetaData> metaDataList = new HashMap<>();
		metaDataList.putAll(extractMetadataFromWeakness(weaknessCatalog.getWeaknesses()));
		metaDataList.putAll(extractMetadataFromCategories(weaknessCatalog.getCategories()));
		metaDataList.putAll(extractMetadataFromViews(weaknessCatalog.getViews()));
		LOGGER.info("metaDataList size : {}", metaDataList.size());
		return metaDataList;
	}

	/**
	 * Creates the cwe.
	 *
	 * @param weaknessType the weakness type
	 * @param externalReferenceList the external reference list
	 * @param weaknessMetaDataList the weakness meta data list
	 * @return the weakness root
	 */
	private WeaknessRoot createCwe(WeaknessType weaknessType, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		com.csw.data.mitre.cwe.pojo.WeaknessRoot weakness = new com.csw.data.mitre.cwe.pojo.WeaknessRoot();
		String id = String.valueOf(weaknessType.getID());
		weakness.setId(CWE_PREFIX + id);
		weakness.setWeaknessType("Weakness");
		weakness.setSources(addWeaknessSources(id, ParserConstants.MITRE));
		weakness.setTitle(weaknessType.getName());
		weakness.setAbstraction(Abstraction.fromValue(weaknessType.getAbstraction().value()));
		weakness.setStatus(Status.fromValue(weaknessType.getStatus().value()));
		weakness.setStructure(Structure.fromValue(weaknessType.getStructure().value()));
		weakness.setDescription(weaknessType.getDescription());
		weakness.setExtendedDescription(null != weaknessType.getExtendedDescription() ? String.valueOf(weaknessType.getExtendedDescription()) : null);
		weakness.setLikelihoodOfExploit(null != weaknessType.getLikelihoodOfExploit() ? weaknessType.getLikelihoodOfExploit().value() : null);

		if(null != weaknessType.getRelatedWeaknesses()) {
			List<com.csw.data.mitre.cwe.pojo.RelatedWeakness> relatedWeaknesses = new ArrayList<>();
			for (RelatedWeakness relatedWeaknessType : weaknessType.getRelatedWeaknesses().getRelatedWeakness()) {
				com.csw.data.mitre.cwe.pojo.RelatedWeakness relatedWeakness = new com.csw.data.mitre.cwe.pojo.RelatedWeakness();
				WeaknessMetaData metaData = weaknessMetaDataList.get(String.valueOf(relatedWeaknessType.getCWEID()));
				relatedWeakness.setId(null != relatedWeaknessType.getCWEID() ? CWE_PREFIX + relatedWeaknessType.getCWEID() : null );
				relatedWeakness.setNature(null != relatedWeaknessType.getNature() ? relatedWeaknessType.getNature().value() : null);
				relatedWeakness.setChainId(null != relatedWeaknessType.getChainID() ? CWE_PREFIX + relatedWeaknessType.getChainID() : null);
				relatedWeakness.setViewId(null != relatedWeaknessType.getViewID() ?  CWE_PREFIX + relatedWeaknessType.getViewID() : null );
				relatedWeakness.setOrdinal(null != relatedWeaknessType.getOrdinal() ? relatedWeaknessType.getOrdinal().value() : null);
				if (null != metaData) {
					relatedWeakness.setTitle(metaData.getTitle());
					relatedWeakness.setType(metaData.getType());
					relatedWeakness.setAbstraction(metaData.getAbstraction());
				}
				relatedWeaknesses.add(relatedWeakness);
			}
			weakness.setRelatedWeaknesses(relatedWeaknesses);
		}

		if(null != weaknessType.getWeaknessOrdinalities()) {
			List<com.csw.data.mitre.cwe.pojo.WeaknessOrdinality> weaknessOrdinalities = new ArrayList<>();
			for (WeaknessOrdinality weaknessOrdinalityType : weaknessType.getWeaknessOrdinalities().getWeaknessOrdinality()) {
				com.csw.data.mitre.cwe.pojo.WeaknessOrdinality weaknessOrdinality = new com.csw.data.mitre.cwe.pojo.WeaknessOrdinality();
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
			for(com.csw.data.mitre.cwe.jaxb.DetectionMethodsType.DetectionMethod detectionMethodType: weaknessType.getDetectionMethods().getDetectionMethod()) {
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
				if(null != functionalAreaEnumeration)
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
			for(com.csw.data.mitre.cwe.jaxb.TaxonomyMappingsType.TaxonomyMapping taxonomyMappingType: weaknessType.getTaxonomyMappings().getTaxonomyMapping()) {
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
		if(null != weaknessType.getContentHistory()) {
			ContentHistoryRoot contentHistory = addContentHistory(weaknessType.getContentHistory(), weakness);
			weakness.setContentHistory(contentHistory);
		}
		return weakness;
	}


	/**
	 * Creates the view.
	 *
	 * @param viewType the view type
	 * @param externalReferenceList the external reference list
	 * @return the weakness root
	 */
	private WeaknessRoot createView(ViewType viewType, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		com.csw.data.mitre.cwe.pojo.WeaknessRoot weakness = new com.csw.data.mitre.cwe.pojo.WeaknessRoot();
		weakness.setId(CWE_PREFIX + viewType.getID());
		weakness.setWeaknessType("View");
		weakness.setSources(addWeaknessSources(String.valueOf(viewType.getID()), ParserConstants.MITRE));
		weakness.setTitle(viewType.getName());
		weakness.setViewType(com.csw.data.mitre.cwe.pojo.WeaknessRoot.ViewType.fromValue(viewType.getType().value()));
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
			List<com.csw.data.mitre.cwe.pojo.RelatedWeakness> relatedWeaknesses = new ArrayList<>();
			for(JAXBElement<MemberType> memberTypeJaxb: viewType.getMembers().getContent()) {
				com.csw.data.mitre.cwe.pojo.RelatedWeakness relatedWeakness = createRelatedWeakness(memberTypeJaxb, weaknessMetaDataList);
				relatedWeaknesses.add(relatedWeakness);
			}
			weakness.setRelatedWeaknesses(relatedWeaknesses);
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
		weakness.setContentHistory(addContentHistory(viewType.getContentHistory(), weakness));
		return weakness;
	}

    /**
	 * Creates the category.
	 *
	 * @param categoryType the category type
	 * @param externalReferenceList the external reference list
	 * @return the weakness root
	 */
	private WeaknessRoot createCategory(CategoryType categoryType, Map<String, Reference> externalReferenceList, Map<String, WeaknessMetaData> weaknessMetaDataList) {
		com.csw.data.mitre.cwe.pojo.WeaknessRoot weakness = new com.csw.data.mitre.cwe.pojo.WeaknessRoot();
		weakness.setId(CWE_PREFIX + categoryType.getID());
		weakness.setWeaknessType(CATEGORY);
		weakness.setSources(addWeaknessSources(String.valueOf(categoryType.getID()), ParserConstants.MITRE));
		weakness.setTitle(categoryType.getName());
		weakness.setDescription(null != categoryType.getSummary() ? String.valueOf(categoryType.getSummary().getContent().get(0)) : null);
		weakness.setStatus(Status.fromValue(categoryType.getStatus().value()));


		if(null != categoryType.getRelationships()) {
			List<com.csw.data.mitre.cwe.pojo.RelatedWeakness> relatedWeaknesses = new ArrayList<>();
			for(JAXBElement<MemberType> memberTypeJaxb: categoryType.getRelationships().getContent()) {
				com.csw.data.mitre.cwe.pojo.RelatedWeakness relatedWeakness = createRelatedWeakness(memberTypeJaxb, weaknessMetaDataList);
				relatedWeaknesses.add(relatedWeakness);
			}
			weakness.setRelatedWeaknesses(relatedWeaknesses);
		}

		if(null != categoryType.getTaxonomyMappings()) {
			List<TaxonomyMapping> taxonomyMappings = new ArrayList<>();
			for(com.csw.data.mitre.cwe.jaxb.TaxonomyMappingsType.TaxonomyMapping taxonomyMappingType: categoryType.getTaxonomyMappings().getTaxonomyMapping()) {
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
		weakness.setContentHistory(addContentHistory(categoryType.getContentHistory(), weakness));
		return weakness;
	}
	
	/**
	 * Creates the related weakness.
	 *
	 * @param memberTypeJaxb the member type jaxb
	 * @param weaknessMetaDataList the weakness meta data list
	 * @return the com.csw.data.mitre.cwe.pojo. related weakness
	 */
	private com.csw.data.mitre.cwe.pojo.RelatedWeakness createRelatedWeakness(JAXBElement<MemberType> memberTypeJaxb, Map<String, WeaknessMetaData> weaknessMetaDataList) {
        MemberType memberType = memberTypeJaxb.getValue();
        com.csw.data.mitre.cwe.pojo.RelatedWeakness relatedWeakness = new com.csw.data.mitre.cwe.pojo.RelatedWeakness();
        String cweId = String.valueOf(memberType.getCWEID());
        String viewId = String.valueOf(memberType.getViewID());
        WeaknessMetaData metaData = weaknessMetaDataList.get(cweId);
        String type = metaData.getType();
        String abstraction = metaData.getAbstraction();
        String title = metaData.getTitle();
        relatedWeakness.setId((null != cweId) ? CWE_PREFIX + cweId : null);
        relatedWeakness.setNature(memberTypeJaxb.getName().getLocalPart());
        relatedWeakness.setViewId((null != viewId) ? CWE_PREFIX + viewId : null);
        relatedWeakness.setType(type);
        relatedWeakness.setAbstraction(abstraction);
        relatedWeakness.setTitle(title);
        return relatedWeakness;
    }

	/**
	 * Adds the weakness sources.
	 *
	 * @param weaknessId the weakness id
	 * @param sourceName the source name
	 * @return the list
	 */
	private List<Source> addWeaknessSources(String weaknessId, String sourceName) {
		List<Source> sources = new ArrayList<>();
		Source source = new Source();
		StringBuilder sourceUrlBuilder = new StringBuilder().append(mitreUrlPrefix).append(weaknessId).append(ParserConstants.HTML_FILE_EXTENSION);
		source.setSourceName(sourceName);
		source.setSourceUrl(sourceUrlBuilder.toString());
		sources.add(source);
		return sources;
	}

	/**
	 * Adds the references.
	 *
	 * @param referencesType the references type
	 * @param externalReferenceList the external reference list
	 * @return the list
	 */
	private List<Reference> addReferences(ReferencesType referencesType, Map<String, Reference> externalReferenceList) {
		List<Reference> referenceList = new ArrayList<>();
		if(null == referencesType || CollectionUtils.isEmpty(referencesType.getReference())) {
			return referenceList;
		}
		for(com.csw.data.mitre.cwe.jaxb.ReferencesType.Reference referenceType: referencesType.getReference()) {
			Reference reference = externalReferenceList.get(referenceType.getExternalReferenceID());
			reference.setSection(referenceType.getSection());
			referenceList.add(reference);
		}
		return referenceList;
	}

	/**
	 * Adds the content history.
	 *
	 * @param contentHistoryType the content history type
	 * @param weakness the weakness
	 * @return the content history root
	 */
	private ContentHistoryRoot addContentHistory(ContentHistoryType contentHistoryType, WeaknessRoot weakness) {
		ContentHistoryRoot contentHistory = new ContentHistoryRoot();
		contentHistory.setSubmission(addContentHistorySubmission(contentHistoryType.getSubmission(), weakness));
		contentHistory.setModification(addContentHistoryModification(contentHistoryType.getModification(), weakness));
		contentHistory.setContribution(addContentHistoryContribution(contentHistoryType.getContribution()));
		contentHistory.setPreviousEntryName(addContentHistoryPreviousEntryDetails(contentHistoryType.getPreviousEntryName()));
		return contentHistory;
	}

	/**
	 * Adds the content history previous entry details.
	 *
	 * @param previousEntryNameList the previous entry name list
	 * @return the list
	 */
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

	/**
	 * Adds the content history contribution.
	 *
	 * @param contributions the contributions
	 * @return the list
	 */
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

	/**
	 * Adds the content history modification.
	 *
	 * @param modifications the modifications
	 * @param weakness the weakness
	 * @return the list
	 */
	private List<ModificationType> addContentHistoryModification(List<Modification> modifications, WeaknessRoot weakness) {
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
			weakness.setLastUpdatedDate(dateFormat.format(modificationDate));
			modificationTypes.add(modificationType);
		}
		return modificationTypes;
	}

	/**
	 * Adds the content history submission.
	 *
	 * @param submission the submission
	 * @param weakness the weakness
	 * @return the submission root
	 */
	private SubmissionRoot addContentHistorySubmission(Submission submission, WeaknessRoot weakness) {
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
		weakness.setSubmissionDate(dateFormat.format(submissionDate));
		return submissionRoot;
	}

	/**
	 * Adds the reference authors.
	 *
	 * @param authors the authors
	 * @return the list
	 */
	private List<String> addReferenceAuthors(List<String> authors) {
		List<String> authorList = new ArrayList<>();
		if(!CollectionUtils.isEmpty(authors)) {
			authorList.addAll(authors);
		}
		return authorList;
	}

	/**
	 * Adds the mitigation phases.
	 *
	 * @param phaseEnumerations the phase enumerations
	 * @return the list
	 */
	private List<String> addMitigationPhases(List<PhaseEnumeration> phaseEnumerations) {
		List<String> phases = new ArrayList<>();
		for (PhaseEnumeration phaseEnumeration : phaseEnumerations) {
			phases.add(phaseEnumeration.value());
		}
		return phases;
	}

	/**
	 * Adds the structured types.
	 *
	 * @param structuredTextType the structured text type
	 * @return the list
	 */
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

	/**
	 * Sets the common consequence scope.
	 *
	 * @param scopeEnumerations the scope enumerations
	 * @return the list
	 */
	private List<String> setCommonConsequenceScope(List<ScopeEnumeration> scopeEnumerations) {
		List<String> scopes = new ArrayList<>();
		for (ScopeEnumeration scopeEnumeration : scopeEnumerations) {
			scopes.add(scopeEnumeration.value());
		}
		return scopes;
	}

	/**
	 * Sets the common consequence impact.
	 *
	 * @param impactEnumerations the impact enumerations
	 * @return the list
	 */
	private List<String> setCommonConsequenceImpact(List<TechnicalImpactEnumeration> impactEnumerations) {
		List<String> technicalImpacts = new ArrayList<>();
		for (TechnicalImpactEnumeration technicalImpactEnumeration : impactEnumerations) {
			technicalImpacts.add(technicalImpactEnumeration.value());
		}
		return technicalImpacts;
	}

	/**
	 * Xml gregorian calendar to date.
	 *
	 * @param urlDate the url date
	 * @return the date
	 */
	private Date xmlGregorianCalendarToDate(XMLGregorianCalendar urlDate) {
		if(null == urlDate) {
			return null;
		}
		return urlDate.toGregorianCalendar().getTime();
	}

	/**
	 * Extract metadata from weakness.
	 *
	 * @param weaknesses the weaknesses
	 * @return the map
	 */
	private Map<String, WeaknessMetaData> extractMetadataFromWeakness(List<WeaknessType> weaknesses) {
		Map<String, WeaknessMetaData> metaDataList = new HashMap<>();
		for (WeaknessType weaknessType : weaknesses) {
			WeaknessMetaData metaData = createMetaData(String.valueOf(weaknessType.getID()), weaknessType.getName(), "Weakness", weaknessType.getAbstraction().value());
			metaDataList.put(String.valueOf(weaknessType.getID()), metaData);
		}
		return metaDataList;
	}

	/**
	 * Extract metadata from categories.
	 *
	 * @param categories the categories
	 * @return the map
	 */
	private Map<String, WeaknessMetaData> extractMetadataFromCategories(Categories categories) {
		Map<String, WeaknessMetaData> metaDataList = new HashMap<>();
		if(!CollectionUtils.isEmpty(categories.getCategory())) {
			for (CategoryType category : categories.getCategory()) {
				WeaknessMetaData metaData = createMetaData(String.valueOf(category.getID()), category.getName(), CATEGORY, null);
				metaDataList.put(String.valueOf(category.getID()), metaData);
			}
		}
		return metaDataList;
	}

	/**
	 * Extract metadata from views.
	 *
	 * @param views the views
	 * @return the map
	 */
	private Map<String, WeaknessMetaData> extractMetadataFromViews(Views views) {
		Map<String, WeaknessMetaData> metaDataList = new HashMap<>();
		if(!CollectionUtils.isEmpty(views.getView())) {
			for (ViewType view : views.getView()) {
				WeaknessMetaData metaData = createMetaData(String.valueOf(view.getID()), view.getName(), CATEGORY, null);
				metaDataList.put(String.valueOf(view.getID()), metaData);
			}
		}
		return metaDataList;
	}

	/**
	 * Creates the meta data.
	 *
	 * @param id the id
	 * @param title the title
	 * @param type the type
	 * @return the weakness meta data
	 */
	private WeaknessMetaData createMetaData(String id, String title, String type, String abstraction) {
		WeaknessMetaData data = new WeaknessMetaData();
		data.setId(id);
		data.setTitle(title);
		data.setType(type);
		data.setAbstraction(abstraction);
		return data;
	}
}
