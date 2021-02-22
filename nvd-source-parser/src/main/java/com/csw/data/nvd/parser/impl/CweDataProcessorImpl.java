package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.collections.CollectionUtils;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.aws.config.AmazonS3Client;
import com.csw.data.nvd.jaxb.cwe.AlternateTermsType.AlternateTerm;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Architecture;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Language;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.OperatingSystem;
import com.csw.data.nvd.jaxb.cwe.ApplicablePlatformsType.Technology;
import com.csw.data.nvd.jaxb.cwe.AudienceType.Stakeholder;
import com.csw.data.nvd.jaxb.cwe.CommonConsequencesType.Consequence;
import com.csw.data.nvd.jaxb.cwe.FunctionalAreaEnumeration;
import com.csw.data.nvd.jaxb.cwe.MemberType;
import com.csw.data.nvd.jaxb.cwe.ModesOfIntroductionType.Introduction;
import com.csw.data.nvd.jaxb.cwe.NotesType.Note;
import com.csw.data.nvd.jaxb.cwe.PhaseEnumeration;
import com.csw.data.nvd.jaxb.cwe.PotentialMitigationsType.Mitigation;
import com.csw.data.nvd.jaxb.cwe.RelatedAttackPatternsType.RelatedAttackPattern;
import com.csw.data.nvd.jaxb.cwe.RelatedWeaknessesType.RelatedWeakness;
import com.csw.data.nvd.jaxb.cwe.ResourceEnumeration;
import com.csw.data.nvd.jaxb.cwe.ScopeEnumeration;
import com.csw.data.nvd.jaxb.cwe.StructuredTextType;
import com.csw.data.nvd.jaxb.cwe.TechnicalImpactEnumeration;
import com.csw.data.nvd.jaxb.cwe.ViewType;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog;
import com.csw.data.nvd.jaxb.cwe.WeaknessCatalog.Views;
import com.csw.data.nvd.jaxb.cwe.WeaknessOrdinalitiesType.WeaknessOrdinality;
import com.csw.data.nvd.jaxb.cwe.WeaknessType;
import com.csw.data.nvd.parser.DataProcessor;
import com.csw.data.nvd.pojo.cwe.AlternateTermType;
import com.csw.data.nvd.pojo.cwe.ApplicablePlatformsRoot;
import com.csw.data.nvd.pojo.cwe.AudienceType;
import com.csw.data.nvd.pojo.cwe.CommonConsequence;
import com.csw.data.nvd.pojo.cwe.DetectionMethod;
import com.csw.data.nvd.pojo.cwe.ModesOfIntroduction;
import com.csw.data.nvd.pojo.cwe.NoteType;
import com.csw.data.nvd.pojo.cwe.PlatformType;
import com.csw.data.nvd.pojo.cwe.PotentialMitigation;
import com.csw.data.nvd.pojo.cwe.RelatedAttackPatternType;
import com.csw.data.nvd.pojo.cwe.Relationship;
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

@Service
@Qualifier("CweDataProcessor")
public class CweDataProcessorImpl implements DataProcessor {

	private static final Logger logger = LoggerFactory.getLogger(CweDataProcessorImpl.class);

	@Value("${livekeep.base.path}")
	private String liveKeepBasePath;

	@Value("${cwe.path}")
	private String cwePath;
	
	@Value("${data.local.flag}")
	private boolean localFlag;
	
	@Value("${data.livekeep.bucketName}")
	private String s3BucketName;
	
	@Autowired
	private AmazonS3Client amazonS3Client;
	
	public void process(String sourceFilePath) throws Exception {
		JAXBContext context = JAXBContext.newInstance(WeaknessCatalog.class);
        Unmarshaller un = context.createUnmarshaller();
        Object obj = un.unmarshal(new File(sourceFilePath));
        WeaknessCatalog weaknessCatalog = (WeaknessCatalog) obj;
		extractWeakness(weaknessCatalog.getWeaknesses(), sourceFilePath);
		extractViews(weaknessCatalog.getViews(), sourceFilePath);
	}
	
	private void extractViews(Views viewsType, String sourceFilePath) {
		if(!CollectionUtils.isEmpty(viewsType.getView())) {
			for(ViewType viewType: viewsType.getView()) {
				WeaknessRoot view = createView(viewType);
				writeToLiveKeep(view, sourceFilePath);
			}
		}
	}

	private void extractWeakness(List<WeaknessType> weaknesses, String sourceFilePath) {
		for (WeaknessType weakness : weaknesses) {
			WeaknessRoot cwe = createCwe(weakness);
			writeToLiveKeep(cwe, sourceFilePath);
		}
	}

	private WeaknessRoot createCwe(WeaknessType weaknessType) {
		com.csw.data.nvd.pojo.cwe.WeaknessRoot weakness = new com.csw.data.nvd.pojo.cwe.WeaknessRoot();
		weakness.setId("CWE-" + weaknessType.getID());
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
			List<Object> weaknessOrdinalities = new ArrayList<>();
			for (WeaknessOrdinality weaknessOrdinalityType : weaknessType.getWeaknessOrdinalities().getWeaknessOrdinality()) {
				JSONObject weaknessOrdinality = new JSONObject();
				weaknessOrdinality.put("ordinality", weaknessOrdinalityType.getOrdinality().value());
				weaknessOrdinality.put("weaknessOrdinality", weaknessOrdinalityType.getDescription());
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
		//TODO add content history, external reference and source
		return weakness;
	}
	
	private WeaknessRoot createView(ViewType viewType) {
		com.csw.data.nvd.pojo.cwe.WeaknessRoot weakness = new com.csw.data.nvd.pojo.cwe.WeaknessRoot();
		weakness.setId("CWE-" + viewType.getID());
		weakness.setWeaknessType("View");
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
		//TODO add content history, external reference and source
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
}
