package com.csw.data.nvd.parser.helper;

import java.io.File;
import java.io.IOException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.csw.data.nvd.jaxb.vendorstatement.StatementType;
import com.csw.data.nvd.jaxb.vendorstatement.VendorstatementsType;
import com.csw.data.nvd.json.source.BaseMetricV2;
import com.csw.data.nvd.json.source.BaseMetricV3;
import com.csw.data.nvd.json.source.CVEJSON40Min11;
import com.csw.data.nvd.json.source.DefCpeMatch;
import com.csw.data.nvd.json.source.DefCveItem;
import com.csw.data.nvd.json.source.DefNode;
import com.csw.data.nvd.json.source.LangString;
import com.csw.data.nvd.json.source.NvdCveFeedJson11;
import com.csw.data.nvd.json.source.ProblemtypeDatum;
import com.csw.data.nvd.json.targets.AffectedSoftwareConfiguration;
import com.csw.data.nvd.json.targets.AffectedSoftwareConfigurationType;
import com.csw.data.nvd.json.targets.Cvssv2;
import com.csw.data.nvd.json.targets.Cvssv3;
import com.csw.data.nvd.json.targets.CweList;
import com.csw.data.nvd.json.targets.Reference;
import com.csw.data.nvd.json.targets.VendorComment;
import com.csw.data.nvd.json.targets.Vulnerability;
import com.csw.data.nvd.json.targets.VulnerabilityRiskScore;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component
public class CveConstructor {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CveConstructor.class);
	
	public Map<String, List<VendorComment>> constructVendorCommentsFromSource(String sourceFile) {
		VendorstatementsType vendorstatementsType = unmarshallVendorStatement(sourceFile);
		return extractVendorCommentJson(vendorstatementsType);
	}

	public List<Vulnerability> constructVulnerabilititesFromSource(String sourceFile, Map<String, List<VendorComment>> vendorComments) {
		//Extract the CVE feed files and convert CVE to JSON Object. Add the sourcekeep directory for each CVE. Add the Vendor statement accoringly
		NvdCveFeedJson11 vulnerability = unmarshalVulnerability(sourceFile);
		return extractVulnerabilityJson(vulnerability, vendorComments);
	}
	
    private List<Vulnerability> extractVulnerabilityJson(NvdCveFeedJson11 nvdCveFeedJson11, Map<String, List<VendorComment>> vendorComments) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        List<DefCveItem> cveItems = nvdCveFeedJson11.getCVEItems();
        for (DefCveItem cveItem : cveItems) {
            vulnerabilities.add(constructVulnerabilityJson(cveItem, vendorComments));
        }
        return vulnerabilities;
    }
	
	private Vulnerability constructVulnerabilityJson(DefCveItem cveItem, Map<String, List<VendorComment>> vendorComments) {
		Vulnerability vulnerability = new Vulnerability();
		CVEJSON40Min11 cve = cveItem.getCve();
		vulnerability.setId(cve.getCVEDataMeta().getId());
		vulnerability.setAssigner(cve.getCVEDataMeta().getAssigner());
		vulnerability.setPublishedDate(cveItem.getPublishedDate());
		vulnerability.setLastModifiedDate(cveItem.getLastModifiedDate());
		
		if(null != cve.getDescription() && !CollectionUtils.isEmpty(cve.getDescription().getDescriptionData())) {
		    List<String> desciptions = new ArrayList<>();
		    for (LangString langString : cve.getDescription().getDescriptionData()) {
		        desciptions.add(langString.getValue());
            }
		    vulnerability.setDescription(desciptions);
		}
		
		BaseMetricV2 baseMetricV2 = cveItem.getImpact().getBaseMetricV2();
		if(null != baseMetricV2) {
			Cvssv2 cvssv2 = new Cvssv2();
			cvssv2.setCvssV2version(baseMetricV2.getCvssV2().getVersion());
			cvssv2.setCvssV2vectorString(baseMetricV2.getCvssV2().getVectorString());
			cvssv2.setCvssV2accessVector(baseMetricV2.getCvssV2().getAccessVector().value());
			cvssv2.setCvssV2accessComplexity(baseMetricV2.getCvssV2().getAccessComplexity().value());
			cvssv2.setCvssV2authentication(baseMetricV2.getCvssV2().getAuthentication().value());
			cvssv2.setCvssV2confidentialityImpact(baseMetricV2.getCvssV2().getConfidentialityImpact().value());
			cvssv2.setCvssv2integrityImpact(baseMetricV2.getCvssV2().getIntegrityImpact().value());
			cvssv2.setCvssV2availabilityImpact(baseMetricV2.getCvssV2().getAvailabilityImpact().value());
			cvssv2.setCvssV2baseScore(String.valueOf(baseMetricV2.getCvssV2().getBaseScore()));
			cvssv2.setBaseMetricV2severity(baseMetricV2.getSeverity());
			cvssv2.setBaseMetricAcInsufInfo(String.valueOf(baseMetricV2.getAcInsufInfo()));
			cvssv2.setBaseMetricV2exploitabilityScore(String.valueOf(baseMetricV2.getExploitabilityScore()));
			cvssv2.setBaseMetricV2impactScore(String.valueOf(baseMetricV2.getImpactScore()));
			vulnerability.setCvssv2(cvssv2);
		}
		
		BaseMetricV3 baseMetricV3 = cveItem.getImpact().getBaseMetricV3();
		if(null != baseMetricV3) {
			Cvssv3 cvssv3 = new Cvssv3();
			cvssv3.setCvssV3version(baseMetricV3.getCvssV3().getVersion());
			cvssv3.setCvssV3vectorString(baseMetricV3.getCvssV3().getVectorString());
			cvssv3.setCvssV3attackVector(baseMetricV3.getCvssV3().getAttackVector().value());
			cvssv3.setCvssV3attackComplexity(baseMetricV3.getCvssV3().getAttackComplexity().value());
			cvssv3.setCvssV3privilegesRequired(baseMetricV3.getCvssV3().getPrivilegesRequired().value());
			cvssv3.setCvssV3userInteraction(baseMetricV3.getCvssV3().getUserInteraction().value());
			cvssv3.setCvssV3scope(baseMetricV3.getCvssV3().getScope().value());
			cvssv3.setCvssV3confidentialityImpact(baseMetricV3.getCvssV3().getConfidentialityImpact().value());
			cvssv3.setCvssV3integrityImpact(baseMetricV3.getCvssV3().getIntegrityImpact().value());
			cvssv3.setCvssV3availabilityImpact(baseMetricV3.getCvssV3().getAvailabilityImpact().value());
			cvssv3.setCvssV3baseScore(String.valueOf(baseMetricV3.getCvssV3().getBaseScore()));
			cvssv3.setCvssV3baseSeverity(baseMetricV3.getCvssV3().getBaseSeverity().value());
			cvssv3.setBaseMetricV3exploitabilityScore(String.valueOf(baseMetricV3.getExploitabilityScore()));
			cvssv3.setBaseMetricV3impactScore(String.valueOf(baseMetricV3.getImpactScore()));
			vulnerability.setCvssv3(cvssv3);
		}
		
		List<CweList> cweLists = new ArrayList<>();
		List<ProblemtypeDatum> problemtypeDatums = cveItem.getCve().getProblemtype().getProblemtypeData();
		for (ProblemtypeDatum problemtypeDatum : problemtypeDatums) {
			List<LangString> langStrings = problemtypeDatum.getDescription();
			for (LangString langString : langStrings) {
				if(null == langString.getValue() || !langString.getValue().startsWith("CWE-")) {
					continue;
				}
				CweList cweList = new CweList();
				cweList.setId(langString.getValue());
				cweLists.add(cweList);
			}
		}
		vulnerability.setCweList(cweLists);
		
		List<VendorComment> comments = extractVendorCommentByCve(vendorComments, cve.getCVEDataMeta().getId());
		vulnerability.setVendorComments(comments);
		
        if (null != cve.getReferences() && !CollectionUtils.isEmpty(cve.getReferences().getReferenceData())) {
            List<Reference> references = new ArrayList<>(cve.getReferences().getReferenceData().size());
            List<com.csw.data.nvd.json.source.Reference> sourceReferences = cve.getReferences().getReferenceData();
            for (com.csw.data.nvd.json.source.Reference sourceReference : sourceReferences) {
                Reference reference = new Reference();
                reference.setName(sourceReference.getName());
                reference.setUrl(sourceReference.getUrl());
                reference.setRefsource(sourceReference.getRefsource());
                if(!CollectionUtils.isEmpty(sourceReference.getTags())) {
                    reference.setTags(sourceReference.getTags());
                }
                references.add(reference);
            }
            vulnerability.setReferences(references);
        }
        
        VulnerabilityRiskScore riskScore = constructVulnerabilityScore();
        vulnerability.setVulnerabilityRiskScore(riskScore);
		
		List<DefNode> defNodes = cveItem.getConfigurations().getNodes();
		List<AffectedSoftwareConfiguration> affectedSoftwareConfigurations = new ArrayList<>();
		for (int i = 0; i < defNodes.size(); i++) {
			if(!CollectionUtils.isEmpty(defNodes.get(i).getCpeMatch())) {
				affectedSoftwareConfigurations.addAll(getSoftwareConfiguration(defNodes.get(i).getCpeMatch(), i));
			}
			else {
				List<DefNode> nodes = defNodes.get(i).getChildren();
				for (DefNode defNode : nodes) {
					affectedSoftwareConfigurations.addAll(getSoftwareConfiguration(defNode.getCpeMatch(), i));
				}
			}
		}
		AffectedSoftwareConfigurationType affectedSoftwareConfigurationType = new AffectedSoftwareConfigurationType();
		affectedSoftwareConfigurationType.setAffectedProductCount(String.valueOf(affectedSoftwareConfigurations.size()));
		affectedSoftwareConfigurationType.setSoftwareConfigurations(affectedSoftwareConfigurations);
		vulnerability.setAffectedSoftwareConfigurations(affectedSoftwareConfigurationType);
		return vulnerability;
	}

	private VulnerabilityRiskScore constructVulnerabilityScore() {
	    VulnerabilityRiskScore riskScore = new VulnerabilityRiskScore();
	    riskScore.setScore("null");
	    riskScore.setSeverity("null");
	    riskScore.setVersion("null");
	    riskScore.setLastUpdatedDate("null");
	    riskScore.setReasonForChange(new ArrayList<String>(1));
        return riskScore;
    }

    private List<AffectedSoftwareConfiguration> getSoftwareConfiguration(List<DefCpeMatch> cpeMatchs, int configurationNumber) {
		List<AffectedSoftwareConfiguration> affectedSoftwareConfigurations = new ArrayList<>();
		configurationNumber = configurationNumber+1;
			for (DefCpeMatch defCpeMatch : cpeMatchs) {
				AffectedSoftwareConfiguration configuration = new AffectedSoftwareConfiguration();
				configuration.setVulnerable(String.valueOf(defCpeMatch.getVulnerable()));
				configuration.setRunningOnOrWith(String.valueOf(!defCpeMatch.getVulnerable()));
				configuration.setCpe23Uri(defCpeMatch.getCpe23Uri());
				configuration.setTitle(defCpeMatch.getCpe23Uri());
				configuration.setVendor(getDetailsFromUri(defCpeMatch.getCpe23Uri(), 3));
				configuration.setProduct(getDetailsFromUri(defCpeMatch.getCpe23Uri(), 4));
				configuration.setSoftwareConfigurationGroup("Configuration " + configurationNumber);
				configuration.setVersionStart(null != defCpeMatch.getVersionStartIncluding() ? defCpeMatch.getVersionStartIncluding() : defCpeMatch.getVersionStartExcluding());
				configuration.setVersionStartIncluding(defCpeMatch.getVersionStartIncluding());
				configuration.setVersionStartExcluding(defCpeMatch.getVersionStartExcluding());
				configuration.setVersionEnd(null != defCpeMatch.getVersionStartIncluding() ? defCpeMatch.getVersionEndIncluding() : defCpeMatch.getVersionEndExcluding());
				configuration.setVersionEndIncluding(defCpeMatch.getVersionEndIncluding());
				configuration.setVersionEndExcluding(defCpeMatch.getVersionEndExcluding());
				affectedSoftwareConfigurations.add(configuration);
			}
		return affectedSoftwareConfigurations;
	}

	private String getDetailsFromUri(String cpe23Uri, int index) {
		String[] tokens = cpe23Uri.split(":");
		return tokens[index].replace("_", " ");
	}

	private List<VendorComment> extractVendorCommentByCve(Map<String, List<VendorComment>> vendorComments, String cveId) {
		for (Entry<String, List<VendorComment>> entrySet : vendorComments.entrySet()) {
			if (cveId.equalsIgnoreCase(entrySet.getKey())) {
				return entrySet.getValue();
			}
		}
		return new ArrayList<>();
	}
	
	private NvdCveFeedJson11 unmarshalVulnerability(String sourceFilePath) {
		ObjectMapper mapper = new ObjectMapper();
		NvdCveFeedJson11 nvdCveFeedJson11 = null;
		try {
			nvdCveFeedJson11 = mapper.readValue(new File(sourceFilePath), NvdCveFeedJson11.class);
		} catch (IOException e1) {
			LOGGER.error("Error while unmarshalling the cve source file : {}", sourceFilePath);
		}
		return nvdCveFeedJson11;
	}
	
	private Map<String, List<VendorComment>> extractVendorCommentJson(VendorstatementsType vendorstatementsType) {
		Map<String, List<VendorComment>> vendorComments = new HashMap<>();
		List<StatementType> statementTypes = vendorstatementsType.getStatement();
		for (StatementType statementType : statementTypes) {
			String cveId = statementType.getCvename();
			List<VendorComment> commentList = vendorComments.get(cveId);
			if(CollectionUtils.isNotEmpty(commentList)) {
				VendorComment vendorComment = new VendorComment();
				vendorComment.setVendorName(statementType.getOrganization());
				vendorComment.setDateIssued(xmlGregorianCalendarToDate(statementType.getLastmodified()));
				vendorComment.setContributor(statementType.getContributor());
				vendorComment.setCommentary(statementType.getValue());
				commentList.add(vendorComment);
				vendorComments.put(cveId, commentList);
			}else {
				VendorComment vendorComment = new VendorComment();
				vendorComment.setVendorName(statementType.getOrganization());
				vendorComment.setDateIssued(xmlGregorianCalendarToDate(statementType.getLastmodified()));
				vendorComment.setContributor(statementType.getContributor());
				vendorComment.setCommentary(statementType.getValue());
				commentList = new ArrayList<>();
				commentList.add(vendorComment);
				vendorComments.put(cveId, commentList);
			}
		}
		return vendorComments;
	}
	
	private VendorstatementsType unmarshallVendorStatement(String sourceFilePath) {
		JAXBContext context;
		Object object = new Object();
		try {
			context = JAXBContext.newInstance(VendorstatementsType.class);
			Unmarshaller un = context.createUnmarshaller();
			object = un.unmarshal(new File(sourceFilePath));
		} catch (JAXBException e) {
			LOGGER.error("Error while unmarshalling the vendor statement source file : {}", sourceFilePath);
		}
		return (VendorstatementsType) object;
	}
	
	private String xmlGregorianCalendarToDate(XMLGregorianCalendar urlDate) {
		DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
		if(null == urlDate) {
			return null;
		}
		Date date =  urlDate.toGregorianCalendar().getTime();
		return df.format(date);
	}

}
