package com.csw.data.mitre.parser.helper;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.csw.data.mitre.cve.pojo.Bm;
import com.csw.data.mitre.cve.pojo.Cvss;
import com.csw.data.mitre.cve.pojo.CvssArray;
import com.csw.data.mitre.cve.pojo.CvssArray1;
import com.csw.data.mitre.cve.pojo.Cvssv2;
import com.csw.data.mitre.cve.pojo.Cvssv3;
import com.csw.data.mitre.cve.pojo.Cvssv3Source;
import com.csw.data.mitre.cve.pojo.Description1;
import com.csw.data.mitre.cve.pojo.DescriptionData;
import com.csw.data.mitre.cve.pojo.Impact;
import com.csw.data.mitre.cve.pojo.ProblemType;
import com.csw.data.mitre.cve.pojo.ProblemTypeData;
import com.csw.data.mitre.cve.pojo.ReferenceData;
import com.csw.data.mitre.cve.pojo.References;
import com.csw.data.mitre.cve.pojo.ReferencesSource;
import com.csw.data.mitre.cve.pojo.TemporalMetrics;
import com.csw.data.mitre.cve.pojo.Tm;
import com.csw.data.mitre.cve.pojo.VulnerabilityRoot;
import com.csw.data.mitre.cve.pojo.VulnerabilitySourceRoot;
import com.csw.data.mitre.cve.pojo.Weaknesses;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

@Component
public class CveDataHelper {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CveDataHelper.class);
	
	private static final String BASESCORE = "baseScore";
	private static final String BASESCORESTRING = "baseScoreString";
	private static final String IMPACT = "impact";
	private static final String IMPACTARRAY = "impactArray";
	private static final String CVSS = "cvss";
	private static final String CVSSARRAY = "cvssArray";
	private static final String ENGLISH = "eng";
	private static final String PARTIAL = "PARTIAL";
	private static final String COMPLETE = "COMPLETE";
	private static final String LOCAL = "LOCAL";
	private static final String NETWORK = "NETWORK";
	private static final String CVSS30 = "CVSS:3.0";
	private static final String CVSS31 = "CVSS:3.1";
	private static final String CRITICAL = "CRITICAL";
	private static final String MEDIUM = "MEDIUM";
	private static final String UNDEFINED = "UNDEFINED";
	private static final String NONE = "NONE";
	private static final String LOW = "LOW";
	private static final String HIGH = "HIGH";
	private static final String ADJACENT_NETWORK = "ADJACENT_NETWORK";
	private static final String PHYSICAL = "PHYSICAL";
	private static final String REQUIRED = "REQUIRED";
	private static final String CHANGED = "CHANGED";
	private static final String UNCHANGED = "UNCHANGED";
	
	//Method to download the file from a provided url
	public void downloadSourceFile(String url, String sourceZipFile, String path) throws IOException {
		
		File directory = new File(path);
		if(!directory.exists()) {
			directory.mkdirs();
		}

		try (ReadableByteChannel readChannel = Channels.newChannel(
				new URL(url).openStream());
				FileOutputStream fileOS = new FileOutputStream(sourceZipFile);) {
			FileChannel writeChannel = fileOS.getChannel();
			writeChannel.transferFrom(readChannel, 0, Long.MAX_VALUE);
		}
	}
	
	//Method to extract a zip file
	public void extractSourceFile(String sourceZipFile, String destinationPath) throws IOException {

		File destDir = new File(destinationPath);

		try (ZipFile file = new ZipFile(sourceZipFile)) {
			Enumeration zipEntries = file.entries();
			while (zipEntries.hasMoreElements()) {
				ZipEntry zipEntry = (ZipEntry) zipEntries.nextElement();
				if (zipEntry.isDirectory()) {
					String subDir = destDir + "\\" + zipEntry.getName();
					File as = new File(subDir);
					as.mkdirs();
				} else {
					File newFile = new File(destDir, zipEntry.getName());
					String extractedDirectoryPath = destDir.getCanonicalPath();
					String extractedFilePath = newFile.getCanonicalPath();
					if (!extractedFilePath.startsWith(extractedDirectoryPath + File.separator)) {
						throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
					}
					BufferedInputStream inputStream = new BufferedInputStream(file.getInputStream(zipEntry));
					try (FileOutputStream outputStream = new FileOutputStream(newFile)) {
						while (inputStream.available() > 0) {
							outputStream.write(inputStream.read());
						}
					}
				}
			}
		}
	}
	
	//Method to read all the files from a directory and add it to a list
	public void getSourceFiles(String directoryName, List<File> files) {
		File directory = new File(directoryName);
		
		File[] fileList = directory.listFiles();
				
		if (fileList != null) {
			for (File file : fileList) {
				if (file.isFile() && file.getName().endsWith(".json")) {
					files.add(file);
				} else if (file.isDirectory()) {
					getSourceFiles(file.getAbsolutePath(), files);
				}
			}
		}
	}

	/*Method to modify the Source fields with same name and different data format. Fields are renamed as given below
	 * Field Name   |   Data Type   |   Modified Name
	 *   Impact         JSONArray        impactArray
	 *  BaseScore        String        baseScoreString
	 *    CVSS          JSONArray         cvssArray
	 *    CVSS       Nested JSONArray     cvssArray1
	*/
	public void sourceModifier(List<File> cveFiles, ObjectMapper mapper) throws Exception {

		for (File file : cveFiles) {

			String sourceJsonString = new String(Files.readAllBytes(Paths.get(file.getAbsolutePath())));

			JsonObject sourceJsonObject = new Gson().fromJson(sourceJsonString, JsonObject.class);
			String sourceJsonObjectString = sourceJsonObject.toString();

			sourceJsonObjectString = updateImpactArray(sourceJsonObject, sourceJsonObjectString);
			sourceJsonObjectString = updateCVSSAndBaseScore(sourceJsonObject, sourceJsonObjectString);
			try {
				VulnerabilitySourceRoot source = mapper.readValue(sourceJsonObjectString,
						VulnerabilitySourceRoot.class);

				FileOutputStream outputStream = new FileOutputStream(file.getAbsolutePath(), false);
				try (OutputStreamWriter outputWriter = new OutputStreamWriter(outputStream, StandardCharsets.UTF_8)) {

					outputWriter.flush();
					outputWriter.write(mapper.writerWithDefaultPrettyPrinter().writeValueAsString(source));
				}
				outputStream.close();
				
			} catch (Exception e) {
				LOGGER.info("Parsing exception occured while modifying source at file {}", file.getName());
			}
		}

	}

	//This method is used to rename the Impact JSONArray field to impactArray
	public String updateImpactArray(JsonObject jsonObject, String sourceJsonObjectString) {
		try {
			if (jsonObject.get(IMPACT) instanceof JsonArray) 
				sourceJsonObjectString = sourceJsonObjectString.replace(IMPACT, IMPACTARRAY);
			
		} catch (Exception e) {
			//
		}
		return sourceJsonObjectString;
	}

	//This method is used to rename a CVSS JSONArray to cvssArray
	public String updateCVSSAndBaseScore(JsonObject sourceJsonObject, String sourceJsonObjectString) {
		try {
			if (sourceJsonObject.get(IMPACT) instanceof JsonObject) {

				JsonObject impactJsonObject = sourceJsonObject.getAsJsonObject(IMPACT);
				sourceJsonObjectString = updateCvss(impactJsonObject, sourceJsonObject, sourceJsonObjectString);
			}
		} catch (Exception e) {
			//
		}
		return sourceJsonObjectString;
	}

	//This method is used to rename a CVSS JSONArray to cvssArray along with baseScore and nested CVSS JsonArray
	public String updateCvss(JsonObject impactJsonObject, JsonObject sourceJsonObject, String sourceJsonObjectString) {
		try {
			if (sourceJsonObject.getAsJsonObject(IMPACT).get(CVSS) instanceof JsonArray) {

				JsonArray cvssJsonArray = impactJsonObject.getAsJsonArray(CVSS);

				sourceJsonObjectString = updateBaseScore(cvssJsonArray, sourceJsonObjectString);
				sourceJsonObjectString = updateBaseScore(sourceJsonObject, impactJsonObject, sourceJsonObjectString);
				sourceJsonObjectString = updateCvssArray(impactJsonObject, sourceJsonObjectString);
			}
		} catch (Exception e) {
			//
		}
		return sourceJsonObjectString;
	}

	//This method is used to rename CVSS nested JSONArray to cvssArray1
	public String updateCvssArray(JsonObject impactJsonObject, String sourceJsonObjectString) {
		try {
			Object cvssObject = impactJsonObject.get(CVSS);
			if (cvssObject instanceof JsonArray) {
				JsonArray cvssArray = impactJsonObject.getAsJsonArray(CVSS);

				if (cvssArray.get(0) instanceof JsonArray) 
					sourceJsonObjectString = sourceJsonObjectString.replace(CVSS, "cvssArray1");
				else 
					sourceJsonObjectString = sourceJsonObjectString.replace(CVSS, CVSSARRAY);
			}
		} catch (Exception e) {
			//
		}
		return sourceJsonObjectString;
	}

	//Rename baseScore string field as baseScoreString inside the cvss JSONObject field
	public String updateBaseScore(JsonObject sourceJsonObject, JsonObject impactJsonObject, String sourceJsonObjectString) {
		try {
			if (sourceJsonObject.getAsJsonObject(IMPACT).get(CVSS) instanceof JsonObject) {

				JsonObject cvssJsonObject = impactJsonObject.getAsJsonObject(CVSS);
				Object baseScore = cvssJsonObject.get(BASESCORE);

				if (baseScore instanceof String) {

					String oldBaseScore = cvssJsonObject.toString();
					String newBaseScore = oldBaseScore.replace(BASESCORE, BASESCORESTRING);
					sourceJsonObjectString = sourceJsonObjectString.replace(oldBaseScore, newBaseScore);
				}
			}
		} catch (Exception e) {
			//
		}
		return sourceJsonObjectString;
	}

	//Rename baseScore String field as baseScoreString inside CVSS JSONArray field
	public String updateBaseScore(JsonArray cvssJsonArray, String sourceJsonObjectString) {
		for (JsonElement element : cvssJsonArray) {
			try {
				JsonObject cvssJsonObject = element.getAsJsonObject();
				Object baseScore = cvssJsonObject.get(BASESCORE);
				if (cvssJsonObject.get(BASESCORE) != null && baseScore instanceof String) {

					String oldBaseScore = cvssJsonObject.toString();
					String newBaseScore = oldBaseScore.replace(BASESCORE, BASESCORESTRING);
					sourceJsonObjectString = sourceJsonObjectString.replace(oldBaseScore, newBaseScore);

				}
			} catch (Exception e) {
				//
			}
		}
		return sourceJsonObjectString;
	}

	//Method to set the vulnerability ID
	public void setVulnerabilityId(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

			if (source.getCVEDataMeta().getId() != null)
				liveKeep.setId(source.getCVEDataMeta().getId());
			else if (source.getCveId() != null)
				liveKeep.setId(source.getCveId());
			else
				liveKeep.setId(null);
	}
		
	//Method to set description which matches language as eng
	public void setDescriptions(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

		try {
			List<String> descriptions = new ArrayList<>();
			List<DescriptionData> description = source.getDescription().getDescriptionData();
			for (int i = 0; i < description.size(); i++) {
				if (description.get(i).getLang().equalsIgnoreCase(ENGLISH))
					descriptions.add(description.get(i).getValue());
			}
			liveKeep.setDescriptions(descriptions);
		} catch (Exception e) {
			liveKeep.setDescriptions(new ArrayList<>());
		}
	}

	//Method to set AssignerEmail
	public void setAssignerEmail(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {
		 liveKeep.setAssignerEmail(source.getCVEDataMeta().getAssigner());
	}

	//Method to set RequesterEmail
	public void setRequesterEmail(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {
		 liveKeep.setRequesterEmail(source.getCVEDataMeta().getRequester());
	}

	//Method to set Vulnerability status
	public void setVulnerabilityStatus(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {
		 liveKeep.setStatus(source.getCVEDataMeta().getState());
	}

	//Method to set vulnerability title
	public void setVulnerabilityTitle(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {
		 liveKeep.setTitle(source.getCVEDataMeta().getTitle());
	}
	
	//Method to set the published date
	public void setPublishedDate(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {
		String date = source.getCVEDataMeta().getDatePublic();
		if (date != null) {
			SimpleDateFormat viDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
			try {
				viDateFormat.parse(date);
			} catch (Exception e) {
				date = date.concat("T00:00:00Z");
			}
			liveKeep.setPublishedDate(date);
		} else
			liveKeep.setPublishedDate(null);
	}

	//Method to get the weakness id from the field where value is english
	public void setWeaknessId(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

		List<Weaknesses> weaknessIds = new ArrayList<>();
		Weaknesses weaknesses = new Weaknesses();

		ProblemType problemType = source.getProblemtype();
		if (problemType != null) {
			List<ProblemTypeData> problemTypeData = problemType.getProblemTypeData();
			List<Description1> description = null;
			for (int i = 0; i < problemTypeData.size(); i++) {
				description = problemTypeData.get(i).getDescription();
				for (int j = 0; j < description.size(); j++) {
					if (description.get(j).getLang().equalsIgnoreCase(ENGLISH)) {
						String id = findWeaknessId(description.get(j).getValue());
						if (id != null) {
							weaknesses.setId(id);
							weaknessIds.add(weaknesses);
						}
						liveKeep.setWeaknesses(weaknessIds);
					}
				}
			}
		}else
			liveKeep.setWeaknesses(new ArrayList<>());
	}

	//Regex finder method to get CWE ID from string
	public String findWeaknessId(String value) {

		String weaknessId = null;
		String regex = "\\b(?:CWE-\\d{1,})\\b";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(value);

		while (matcher.find()) {
			weaknessId = matcher.group();
		}
		return weaknessId;
	}

	// Method to set the references data
	public void setReferences(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

		ReferencesSource reference = source.getReferences();
		if (reference != null) {
			List<ReferenceData> referenceData = reference.getReferenceData();
			List<References> ref = new ArrayList<>();
			for (int i = 0; i < referenceData.size(); i++) {
				References references = new References();

				if (referenceData.get(i).getName() != null)
					references.setName(referenceData.get(i).getName());

				if (referenceData.get(i).getRefsource() != null)
					references.setSource(referenceData.get(i).getRefsource());

				if (referenceData.get(i).getTitle() != null)
					references.setTitle(referenceData.get(i).getTitle());

				if (referenceData.get(i).getUrl() != null)
					references.setUrl(referenceData.get(i).getUrl());

				ref.addAll(Arrays.asList(references));
			}
			liveKeep.setReferences(ref);
		} else
			liveKeep.setReferences(new ArrayList<>());
	}

	//Method to get the CVSSV3 data from different types of cvss fields
	public void getCvssV3(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

			Cvssv3 cvssv3 = new Cvssv3();
			Impact impact = source.getImpact();

			getCvssv3FromCvssArray(impact, cvssv3);
			getCvssv3FromCvssArray1(impact, cvssv3);
			getCvssv3FromCvss(impact, cvssv3);

			try {
				Cvssv3Source cvssv3Source = impact.getCvssv3();
				Bm bm = cvssv3Source.getBm();
				if (bm != null)
					getBm(bm, cvssv3);

				Tm tm = cvssv3Source.getTm();
				TemporalMetrics temporalMetrics = new TemporalMetrics();
				if (tm != null) {
					getTm(tm, temporalMetrics);
					cvssv3.setTemporalMetrics(temporalMetrics);
				}
				
				getCVSSV3Data(cvssv3Source, cvssv3);
				
			} catch (Exception e) {
				//
			}
			liveKeep.setCvssv3(cvssv3);
			
			if(cvssv3.getVersion() == null) {
				liveKeep.setCvssv3(null);
			}
	}
	
	//Method to get the CVSSV3 data from the CVSS JSONArray field
	public void getCvssv3FromCvssArray(Impact impact, Cvssv3 cvssv3) {
		
		List<CvssArray> cvssArray = null;
		try {
			cvssArray = impact.getCvssArray();
		}catch(Exception e) {
			//
		}
		
		if (cvssArray != null) {
			for (int i = 0; i < cvssArray.size(); i++) {
				String version = cvssArray.get(i).getVersion();
				if (version.equalsIgnoreCase("3.0") || version.equalsIgnoreCase("3.1")) {
					String vectorString = cvssArray.get(i).getVectorString();
					List<String> vectorList = Arrays.asList(vectorString.split("/"));

					setBaseScoreAndBaseSeverity(cvssArray, i, cvssv3);
					setVersion(vectorList, cvssv3, cvssArray, i);
					setAttackVector(vectorList, cvssv3);
					setAttackComplexity(vectorList, cvssv3);
					setPrivilegesRequired(vectorList, cvssv3);
					setUserInteraction(vectorList, cvssv3);
					setScope(vectorList, cvssv3);
					setConfidentialityImpact(vectorList, cvssv3);
					setIntegrityImpact(vectorList, cvssv3);
					setAvailabilityImpact(vectorList, cvssv3);
					setVector(vectorString, cvssv3);
				}
			}
		}
	}
	
	//Method to get the CVSSV3 data from the CVSS nested JSONArray field
	public void getCvssv3FromCvssArray1(Impact impact, Cvssv3 cvssv3) {
		
		List<List<CvssArray1>> cvssArray1 = null;
		try {
			cvssArray1 = impact.getCvssArray1();
		}catch(Exception e) {
			//
		}
		
		if (cvssArray1 != null) {
			for (int i = 0; i < cvssArray1.size(); i++) {
				for (int j = 0; j < cvssArray1.get(i).size(); j++) {
					String version = cvssArray1.get(i).get(j).getVersion();
					if (version.equalsIgnoreCase("3.0") || version.equalsIgnoreCase("3.1")) {
						String vectorString = cvssArray1.get(i).get(j).getVectorString();
						List<String> vectorList = Arrays.asList(vectorString.split("/"));

						setVersion(vectorList, cvssv3, cvssArray1, i, j);
						setAttackVector(vectorList, cvssv3);
						setAttackComplexity(vectorList, cvssv3);
						setPrivilegesRequired(vectorList, cvssv3);
						setUserInteraction(vectorList, cvssv3);
						setScope(vectorList, cvssv3);
						setConfidentialityImpact(vectorList, cvssv3);
						setIntegrityImpact(vectorList, cvssv3);
						setAvailabilityImpact(vectorList, cvssv3);
						setVector(vectorString, cvssv3);
						setScoreAndSeverity(vectorList, cvssv3);

					}
				}
			}
		}
	}
	
	//Method to get the CVSSV3 data from the CVSS JSONObject field
	public void getCvssv3FromCvss(Impact impact, Cvssv3 cvssv3) {

		Cvss cvss = null;
		try {
			cvss = impact.getCvss();

			if (cvss != null
					&& (cvss.getVersion().equalsIgnoreCase("3.0") || cvss.getVersion().equalsIgnoreCase("3.1"))) {

				setBaseScoreAndBaseSeverity(cvss, cvssv3);
				String vectorString = null;
				if (cvss.getVectorString() != null)
					vectorString = cvss.getVectorString();
				else if (cvss.getVectorstring1() != null)
					vectorString = cvss.getVectorstring1();
				else
					vectorString = cvss.getVector_string_();
				List<String> vectorList = Arrays.asList(vectorString.split("/"));

				setVector(vectorString, cvssv3);
				setVersion(vectorList, cvssv3, cvss);
				setAttackVector(vectorList, cvssv3);
				setAttackComplexity(vectorList, cvssv3);
				setPrivilegesRequired(vectorList, cvssv3);
				setUserInteraction(vectorList, cvssv3);
				setScope(vectorList, cvssv3);
				setConfidentialityImpact(vectorList, cvssv3);
				setIntegrityImpact(vectorList, cvssv3);
				setAvailabilityImpact(vectorList, cvssv3);
			}
		} catch (Exception e) {
			//
		}
	}

	//Method to set CVSSV3 version from cvss field
	public void setVersion(List<String> vectorList, Cvssv3 cvssv3, Cvss cvss) {

		if (cvss.getVersion() != null) {
			cvssv3.setVersion(cvss.getVersion());
		} else {
			for (int i = 0; i < vectorList.size(); i++) {

				if (vectorList.get(i).equalsIgnoreCase(CVSS30)) 
					cvssv3.setVersion("3.0");
				if (vectorList.get(i).equalsIgnoreCase(CVSS31)) 
					cvssv3.setVersion("3.1");
			}
		}
	}

	//Method to set CVSSV3 version from CVSS JSONArray field
	public void setVersion(List<String> vectorList, Cvssv3 cvssv3, List<CvssArray> cvssArray, int j) {

		if (cvssArray.get(j).getVersion() != null) {
			cvssv3.setVersion(cvssArray.get(j).getVersion());
		} else {
			for (int i = 0; i < vectorList.size(); i++) {

				if (vectorList.get(i).equalsIgnoreCase(CVSS30))
					cvssv3.setVersion("3.0");
				if (vectorList.get(i).equalsIgnoreCase(CVSS31)) 
					cvssv3.setVersion("3.1");
			}
		}
	}

	//Method to set CVSSV3 version from CVSS nested JSONArray field
	public void setVersion(List<String> vectorList, Cvssv3 cvssv3, List<List<CvssArray1>> cvssArray1, int j, int k) {

		if (cvssArray1.get(j).get(k).getVersion() != null) {
			cvssv3.setVersion(cvssArray1.get(j).get(k).getVersion());
		} else {
			for (int i = 0; i < vectorList.size(); i++) {

				if (vectorList.get(i).equalsIgnoreCase(CVSS30)) 
					cvssv3.setVersion("3.0");
				if (vectorList.get(i).equalsIgnoreCase(CVSS31))
					cvssv3.setVersion("3.1");
			}
		}
	}

	//Method to set CVSSV3 attack vector
	public void setAttackVector(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("AV:N"))
				cvssv3.setAttackVector(NETWORK);
			if (vectorList.get(i).equalsIgnoreCase("AV:A")) 
				cvssv3.setAttackVector(ADJACENT_NETWORK);
			if (vectorList.get(i).equalsIgnoreCase("AV:L"))
				cvssv3.setAttackVector(LOCAL);
			if (vectorList.get(i).equalsIgnoreCase("AV:P")) 
				cvssv3.setAttackVector(PHYSICAL);
		}
	}

	//Method to set CVSSV3 attack complexity
	public void setAttackComplexity(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("AC:L"))
				cvssv3.setAttackComplexity(LOW);
			if (vectorList.get(i).equalsIgnoreCase("AC:H"))
				cvssv3.setAttackComplexity(HIGH);
		}
	}

	//Method to set CVSSV3 privileges required
	public void setPrivilegesRequired(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("PR:N")) 
				cvssv3.setPrivilegesRequired(NONE);
			if (vectorList.get(i).equalsIgnoreCase("PR:L")) 
				cvssv3.setPrivilegesRequired(LOW);
			if (vectorList.get(i).equalsIgnoreCase("PR:H"))
				cvssv3.setPrivilegesRequired(HIGH);
		}
	}

	//Method to set CVSSV3 user interaction
	public void setUserInteraction(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("UI:N")) 
				cvssv3.setUserInteraction(NONE);
			if (vectorList.get(i).equalsIgnoreCase("UI:R"))
				cvssv3.setUserInteraction(REQUIRED);
		}
	}

	//Method to set CVSSV3 scope
	public void setScope(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("S:C"))
				cvssv3.setScope(CHANGED);
			if (vectorList.get(i).equalsIgnoreCase("S:U"))
				cvssv3.setScope(UNCHANGED);
		}
	}

	//Method to set CVSSV3 confidentiality impact
	public void setConfidentialityImpact(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("C:N")) 
				cvssv3.setConfidentialityImpact(NONE);
			if (vectorList.get(i).equalsIgnoreCase("C:L"))
				cvssv3.setConfidentialityImpact(LOW);
			if (vectorList.get(i).equalsIgnoreCase("C:H")) 
				cvssv3.setConfidentialityImpact(HIGH);
		}
	}

	//Method to set CVSSV3 integrity impact
	public void setIntegrityImpact(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("I:N"))
				cvssv3.setIntegrityImpact(NONE);
			if (vectorList.get(i).equalsIgnoreCase("I:L")) 
				cvssv3.setIntegrityImpact(LOW);
			if (vectorList.get(i).equalsIgnoreCase("I:H"))
				cvssv3.setIntegrityImpact(HIGH);
		}
	}

	//Method to set CVSSV3 availability impact
	public void setAvailabilityImpact(List<String> vectorList, Cvssv3 cvssv3) {

		for (int i = 0; i < vectorList.size(); i++) {

			if (vectorList.get(i).equalsIgnoreCase("A:N")) 
				cvssv3.setAvailabilityImpact(NONE);
			if (vectorList.get(i).equalsIgnoreCase("A:L")) 
				cvssv3.setAvailabilityImpact(LOW);
			if (vectorList.get(i).equalsIgnoreCase("A:H"))
				cvssv3.setAvailabilityImpact(HIGH);
		}
	}

	//Method to set CVSSV3 score and severity from cvss field
	public void setBaseScoreAndBaseSeverity(Cvss cvss, Cvssv3 cvssv3) {
		String baseScore = null;
		if (cvss.getBaseScore() != null) 
			baseScore = cvss.getBaseScore();
		if (cvss.getBaseScoreString() != null)
			baseScore = cvss.getBaseScoreString();
		
		if(baseScore != null)
			cvssv3.setScore(Double.parseDouble(baseScore));
		
		if (baseScore != null) {
			Double baseScoreValue = Double.parseDouble(baseScore);

			if (baseScoreValue == 0.0) {
				cvssv3.setSeverity(NONE);
			} else if (baseScoreValue >= 0.1 && baseScoreValue <= 3.9) {
				cvssv3.setSeverity(LOW);
			} else if (baseScoreValue >= 4.0 && baseScoreValue <= 6.9) {
				cvssv3.setSeverity(MEDIUM);
			} else if (baseScoreValue >= 7.0 && baseScoreValue <= 8.9) {
				cvssv3.setSeverity(HIGH);
			} else {
				cvssv3.setSeverity(CRITICAL);
			}
		}
	}
	
	//Method to set CVSSV3 score and severity from cvss JSONArray field
	public void setBaseScoreAndBaseSeverity(List<CvssArray> cvssArray, int i, Cvssv3 cvssv3) {
		String baseScore = null;
		if (cvssArray.get(i).getBaseScore() != null)
			baseScore = String.valueOf(cvssArray.get(i).getBaseScore());
		if (cvssArray.get(i).getBaseScoreString() != null)
			baseScore = cvssArray.get(i).getBaseScoreString();

		cvssv3.setScore(Double.parseDouble(baseScore));
		if (baseScore != null) {
			Double baseScoreValue = Double.parseDouble(baseScore);

			if (baseScoreValue == 0.0) {
				cvssv3.setSeverity(NONE);
			} else if (baseScoreValue >= 0.1 && baseScoreValue <= 3.9) {
				cvssv3.setSeverity(LOW);
			} else if (baseScoreValue >= 4.0 && baseScoreValue <= 6.9) {
				cvssv3.setSeverity(MEDIUM);
			} else if (baseScoreValue >= 7.0 && baseScoreValue <= 8.9) {
				cvssv3.setSeverity(HIGH);
			} else {
				cvssv3.setSeverity(CRITICAL);
			}
		}
	}

	//Method to set CVSSV3 vector
	public void setVector(String vectorString, Cvssv3 cvssv3) {

		String vector = null;
		String regex = "\\b(?:AV:.*/AC:.*/PR:.*/UI:.*/S:.*/C:.*/I:.*/A:.*)\\b";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(vectorString);

		while (matcher.find()) {
			vector = matcher.group();
		}
		cvssv3.setVector(vector);
	}
	
	public void getCVSSV3Data(Cvssv3Source cvssv3source, Cvssv3 cvssv3) {
		
		cvssv3.setVersion("3.0");

		String attackVector = cvssv3source.getAv();
		if (attackVector.equalsIgnoreCase("N"))
			cvssv3.setAttackVector(NETWORK);
		if (attackVector.equalsIgnoreCase("A"))
			cvssv3.setAttackVector(ADJACENT_NETWORK);
		if (attackVector.equalsIgnoreCase("L"))
			cvssv3.setAttackVector(LOCAL);
		if (attackVector.equalsIgnoreCase("P"))
			cvssv3.setAttackVector(PHYSICAL);

		String attackComplexity = cvssv3source.getAc();
		if (attackComplexity.equalsIgnoreCase("L"))
			cvssv3.setAttackComplexity(LOW);
		if (attackComplexity.equalsIgnoreCase("H"))
			cvssv3.setAttackComplexity(HIGH);

		String privilegesRequired = cvssv3source.getPr();
		if (privilegesRequired.equalsIgnoreCase("N"))
			cvssv3.setPrivilegesRequired(NONE);
		if (privilegesRequired.equalsIgnoreCase("L"))
			cvssv3.setPrivilegesRequired(LOW);
		if (privilegesRequired.equalsIgnoreCase("H"))
			cvssv3.setPrivilegesRequired(HIGH);

		String userInteraction = cvssv3source.getUi();
		if (userInteraction.equalsIgnoreCase("N"))
			cvssv3.setUserInteraction(NONE);
		if (userInteraction.equalsIgnoreCase("R"))
			cvssv3.setUserInteraction(REQUIRED);

		String scope = cvssv3source.getS();
		if (scope.equalsIgnoreCase("C"))
			cvssv3.setScope(CHANGED);
		if (scope.equalsIgnoreCase("U"))
			cvssv3.setScope(UNCHANGED);

		String confidentialityImpact = cvssv3source.getC();
		if (confidentialityImpact.equalsIgnoreCase("N"))
			cvssv3.setConfidentialityImpact(NONE);
		if (confidentialityImpact.equalsIgnoreCase("L"))
			cvssv3.setConfidentialityImpact(LOW);
		if (confidentialityImpact.equalsIgnoreCase("H"))
			cvssv3.setConfidentialityImpact(HIGH);

		String integrityImpact = cvssv3source.getI();
		if (integrityImpact.equalsIgnoreCase("N"))
			cvssv3.setIntegrityImpact(NONE);
		if (integrityImpact.equalsIgnoreCase("L"))
			cvssv3.setIntegrityImpact(LOW);
		if (integrityImpact.equalsIgnoreCase("H"))
			cvssv3.setIntegrityImpact(HIGH);

		String availabilityImpact = cvssv3source.getA();
		if (availabilityImpact.equalsIgnoreCase("N"))
			cvssv3.setAvailabilityImpact(NONE);
		if (availabilityImpact.equalsIgnoreCase("L"))
			cvssv3.setAvailabilityImpact(LOW);
		if (availabilityImpact.equalsIgnoreCase("H"))
			cvssv3.setAvailabilityImpact(HIGH);

		String score = cvssv3source.getScore();
		cvssv3.setScore(Double.parseDouble(score));

		if (score != null) {
			Double scoreValue = Double.parseDouble(score);

			if (scoreValue == 0.0) {
				cvssv3.setSeverity(NONE);
			} else if (scoreValue >= 0.1 && scoreValue <= 3.9) {
				cvssv3.setSeverity(LOW);
			} else if (scoreValue >= 4.0 && scoreValue <= 6.9) {
				cvssv3.setSeverity(MEDIUM);
			} else if (scoreValue >= 7.0 && scoreValue <= 8.9) {
				cvssv3.setSeverity(HIGH);
			} else {
				cvssv3.setSeverity(CRITICAL);
			}
		}
		
	}

	//Method to set CVSSV3 data from cvssv3 BM field
	public void getBm(Bm bm, Cvssv3 cvssv3) {

		cvssv3.setVersion("3.0");

		String attackVector = bm.getAv();
		if (attackVector.equalsIgnoreCase("N"))
			cvssv3.setAttackVector(NETWORK);
		if (attackVector.equalsIgnoreCase("A"))
			cvssv3.setAttackVector(ADJACENT_NETWORK);
		if (attackVector.equalsIgnoreCase("L"))
			cvssv3.setAttackVector(LOCAL);
		if (attackVector.equalsIgnoreCase("P"))
			cvssv3.setAttackVector(PHYSICAL);

		String attackComplexity = bm.getAc();
		if (attackComplexity.equalsIgnoreCase("L"))
			cvssv3.setAttackComplexity(LOW);
		if (attackComplexity.equalsIgnoreCase("H"))
			cvssv3.setAttackComplexity(HIGH);

		String privilegesRequired = bm.getPr();
		if (privilegesRequired.equalsIgnoreCase("N"))
			cvssv3.setPrivilegesRequired(NONE);
		if (privilegesRequired.equalsIgnoreCase("L"))
			cvssv3.setPrivilegesRequired(LOW);
		if (privilegesRequired.equalsIgnoreCase("H"))
			cvssv3.setPrivilegesRequired(HIGH);

		String userInteraction = bm.getUi();
		if (userInteraction.equalsIgnoreCase("N"))
			cvssv3.setUserInteraction(NONE);
		if (userInteraction.equalsIgnoreCase("R"))
			cvssv3.setUserInteraction(REQUIRED);

		String scope = bm.getS();
		if (scope.equalsIgnoreCase("C"))
			cvssv3.setScope(CHANGED);
		if (scope.equalsIgnoreCase("U"))
			cvssv3.setScope(UNCHANGED);

		String confidentialityImpact = bm.getC();
		if (confidentialityImpact.equalsIgnoreCase("N"))
			cvssv3.setConfidentialityImpact(NONE);
		if (confidentialityImpact.equalsIgnoreCase("L"))
			cvssv3.setConfidentialityImpact(LOW);
		if (confidentialityImpact.equalsIgnoreCase("H"))
			cvssv3.setConfidentialityImpact(HIGH);

		String integrityImpact = bm.getI();
		if (integrityImpact.equalsIgnoreCase("N"))
			cvssv3.setIntegrityImpact(NONE);
		if (integrityImpact.equalsIgnoreCase("L"))
			cvssv3.setIntegrityImpact(LOW);
		if (integrityImpact.equalsIgnoreCase("H"))
			cvssv3.setIntegrityImpact(HIGH);

		String availabilityImpact = bm.getA();
		if (availabilityImpact.equalsIgnoreCase("N"))
			cvssv3.setAvailabilityImpact(NONE);
		if (availabilityImpact.equalsIgnoreCase("L"))
			cvssv3.setAvailabilityImpact(LOW);
		if (availabilityImpact.equalsIgnoreCase("H"))
			cvssv3.setAvailabilityImpact(HIGH);

		String score = bm.getScore();
		cvssv3.setScore(Double.parseDouble(score));

		if (score != null) {
			Double scoreValue = Double.parseDouble(score);

			if (scoreValue == 0.0) {
				cvssv3.setSeverity(NONE);
			} else if (scoreValue >= 0.1 && scoreValue <= 3.9) {
				cvssv3.setSeverity(LOW);
			} else if (scoreValue >= 4.0 && scoreValue <= 6.9) {
				cvssv3.setSeverity(MEDIUM);
			} else if (scoreValue >= 7.0 && scoreValue <= 8.9) {
				cvssv3.setSeverity(HIGH);
			} else {
				cvssv3.setSeverity(CRITICAL);
			}
		}
	}

	//Method to get CVSSV3 Temporal Metrics from cvssv3 TM field
	public void getTm(Tm tm, TemporalMetrics temporalMetrics) {

		StringBuffer vectorString = new StringBuffer();
		
		String exploitability = tm.getE();
		if (exploitability.equalsIgnoreCase("U")) {
			temporalMetrics.setExploitCodeMaturity("UNPROVEN");
			vectorString.append("E:U/");
		}
		if (exploitability.equalsIgnoreCase("H")) {
			temporalMetrics.setExploitCodeMaturity(HIGH);
			vectorString.append("E:H/");
		}
		if (exploitability.equalsIgnoreCase("P")) {
			temporalMetrics.setExploitCodeMaturity("PROOF OF CONCEPT");
			vectorString.append("E:P/");
		}
		if (exploitability.equalsIgnoreCase("F")) {
			temporalMetrics.setExploitCodeMaturity("FUNCTIONAL");
			vectorString.append("E:F/");
		}
		if (exploitability.equalsIgnoreCase("X")) {
			temporalMetrics.setExploitCodeMaturity(UNDEFINED);
			vectorString.append("E:X/");
		}

		String remediationLevel = tm.getRl();
		if (remediationLevel.equalsIgnoreCase("O")) {
			temporalMetrics.setRemediationLevel("OFFICIAL FIX");
			vectorString.append("RL:O/");
		}
		if (remediationLevel.equalsIgnoreCase("U")) {
			temporalMetrics.setRemediationLevel("UNAVAILABLE");
			vectorString.append("RL:U/");
		}
		if (remediationLevel.equalsIgnoreCase("T")) {
			temporalMetrics.setRemediationLevel("TEMPORARY FIX");
			vectorString.append("RL:T/");
		}
		if (remediationLevel.equalsIgnoreCase("W")) {
			temporalMetrics.setRemediationLevel("WORKAROUND");
			vectorString.append("RL:W/");
		}
		if (remediationLevel.equalsIgnoreCase("X")) {
			temporalMetrics.setRemediationLevel(UNDEFINED);
			vectorString.append("RL:X/");
		}

		String reportConfidence = tm.getRc();
		if (reportConfidence.equalsIgnoreCase("U")) {
			temporalMetrics.setReportConfidence("UNKNOWN");
			vectorString.append("RC:U");
		}
		if (reportConfidence.equalsIgnoreCase("C")) {
			temporalMetrics.setReportConfidence("CONFIRMED");
			vectorString.append("RC:C");
		}
		if (reportConfidence.equalsIgnoreCase("R")) {
			temporalMetrics.setReportConfidence("REASONABLE");
			vectorString.append("RC:R");
		}
		if (reportConfidence.equalsIgnoreCase("X")) {
			temporalMetrics.setReportConfidence(UNDEFINED);
			vectorString.append("RC:X");
		}
		
		if(reportConfidence != null && exploitability != null && remediationLevel != null) {
			
			temporalMetrics.setVector(vectorString.toString());
		}
	}

	//Method to get CVSSV3 score and severity
	public void setScoreAndSeverity(List<String> vectorList, Cvssv3 cvssv3) {

		try {
			Double baseScore = Double.parseDouble(vectorList.get(0));
			cvssv3.setScore(baseScore);

			if (baseScore == 0.0) {
				cvssv3.setSeverity(NONE);
			} else if (baseScore >= 0.1 && baseScore <= 3.9) {
				cvssv3.setSeverity(LOW);
			} else if (baseScore >= 4.0 && baseScore <= 6.9) {
				cvssv3.setSeverity(MEDIUM);
			} else if (baseScore >= 7.0 && baseScore <= 8.9) {
				cvssv3.setSeverity(HIGH);
			} else {
				cvssv3.setSeverity(CRITICAL);
			}
		} catch (Exception e) {
			//
		}

	}
	
	//Method to get CVSSV2 data from different fields
	public void getCvssV2(VulnerabilitySourceRoot source, VulnerabilityRoot liveKeep) {

			Impact impact = source.getImpact();
			Cvssv2 cvssv2 = new Cvssv2();

			getCvssv2FromCvssArray(impact, cvssv2);
			getCvssv2FromCvssArray1(impact, cvssv2);

			liveKeep.setCvssv2(cvssv2);
			
			if(cvssv2.getVersion() == null) {
				liveKeep.setCvssv2(null);
			}
	}
	
	//Method to get CVSSV2 data from the CVSS JSONArray
	public void getCvssv2FromCvssArray(Impact impact, Cvssv2 cvssv2) {
		
		List<CvssArray> cvssArray = null;
		try{
			cvssArray = impact.getCvssArray();
		}catch(Exception e) {
			//
		}
		if (cvssArray != null) {
			for (int i = 0; i < cvssArray.size(); i++) {

				String version = cvssArray.get(i).getVersion();
				if (version.equalsIgnoreCase("2.0")) {
					String vectorString = cvssArray.get(i).getVectorString();
					List<String> vectorList = Arrays.asList(vectorString.split("/"));

					setCVSSV2Version(cvssArray, cvssv2);
					setCVSSV2ScoreAndSeverity(cvssArray, vectorList, cvssv2);
					setCVSSV2AccessVector(vectorList, cvssv2);
					setCVSSV2AccessComplexity(vectorList, cvssv2);
					setCVSSV2Authentication(vectorList, cvssv2);
					setCVSSV2ConfidentialityImpact(vectorList, cvssv2);
					setCVSSV2IntegrityImpact(vectorList, cvssv2);
					setCVSSV2AvailabilityImpact(vectorList, cvssv2);
					setCVSSV2Vector(vectorString, cvssv2);

				}
			}
		}
	}
	
	//Method to get CVSSV2 data from the CVSS nested JSONArray
	public void getCvssv2FromCvssArray1(Impact impact, Cvssv2 cvssv2) {
		
		List<List<CvssArray1>> cvssArray1 = null;
		try{
			cvssArray1 = impact.getCvssArray1();
		}catch(Exception e) {
			//
		}
		if (cvssArray1 != null) {
			for (int i = 0; i < cvssArray1.size(); i++) {
				for (int j = 0; j < cvssArray1.get(i).size(); j++) {

					String version = cvssArray1.get(i).get(j).getVersion();
					if (version.equalsIgnoreCase("2.0")) {
						String vectorString = cvssArray1.get(i).get(j).getVectorString();
						List<String> vectorList = Arrays.asList(vectorString.split("/"));

						setCVSSV2Version(cvssArray1, cvssv2, i, j);
						setCVSSV2ScoreAndSeverity(vectorList, cvssv2);
						setCVSSV2AccessVector(vectorList, cvssv2);
						setCVSSV2AccessComplexity(vectorList, cvssv2);
						setCVSSV2Authentication(vectorList, cvssv2);
						setCVSSV2ConfidentialityImpact(vectorList, cvssv2);
						setCVSSV2IntegrityImpact(vectorList, cvssv2);
						setCVSSV2AvailabilityImpact(vectorList, cvssv2);
						setCVSSV2Vector(vectorString, cvssv2);

					}
				}
			}
		}
	}
	
	//Method to set CVSSV2 version
	public void setCVSSV2Version(List<CvssArray> cvssArray, Cvssv2 cvssv2) {
		
		for(int i=0;i<cvssArray.size();i++) {
			
			String version = cvssArray.get(i).getVersion();
			if(version.equalsIgnoreCase("2.0")) {
				cvssv2.setVersion(version);
			}
		}
	}
	
	
	public void setCVSSV2Version(List<List<CvssArray1>> cvssArray1, Cvssv2 cvssv2, int i, int j) {
		
		String version = cvssArray1.get(i).get(j).getVersion();
		if (version.equalsIgnoreCase("2.0"))
			cvssv2.setVersion(version);
	}
	
	//Method to set CVSSV2 score and severity from the cvss JSONArray field
	public void setCVSSV2ScoreAndSeverity(List<CvssArray> cvssArray, List<String> vectorList, Cvssv2 cvssv2) {

		for (int i = 0; i < cvssArray.size(); i++) {

			String baseScore = null;
			Double score = null;

			try {
				score = Double.parseDouble(vectorList.get(0));
			} catch (Exception e) {
				if (cvssArray.get(i).getBaseScoreString() != null)
					baseScore = cvssArray.get(i).getBaseScoreString();
				else
					baseScore = String.valueOf(cvssArray.get(i).getBaseScore());
			}

			if(baseScore != null)
				cvssv2.setScore(Double.parseDouble(baseScore));
			else
				cvssv2.setScore(score);
			
			if (score == null && baseScore != null) 
				score = Double.parseDouble(baseScore);

			if (score >= 0.0 && score <= 3.9)
				cvssv2.setSeverity(LOW);
			else if (score >= 4.0 && score <= 6.9)
				cvssv2.setSeverity(MEDIUM);
			else
				cvssv2.setSeverity(HIGH);
		}
	}
	
	//Method to set CVSSV2 score and severity
	public void setCVSSV2ScoreAndSeverity(List<String> vectorList, Cvssv2 cvssv2) {
		
		Double score = null;

		try {
			score = Double.parseDouble(vectorList.get(0));
		} catch (Exception e) {
			//
		}

		cvssv2.setScore(score);

		if (score >= 0.0 && score <= 3.9) 
			cvssv2.setSeverity(LOW);
		else if (score >= 4.0 && score <= 6.9)
			cvssv2.setSeverity(MEDIUM);
		else
			cvssv2.setSeverity(HIGH);
	}

	//Method to set CVSSV2 vector
	public void setCVSSV2Vector(String vectorString, Cvssv2 cvssv2) {

		String vector = null;
		String regex = "\\b(?:AV:.*/AC:.*/Au:.*/C:.*/I:.*/A:.*)\\b";

		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(vectorString);

		while (matcher.find()) {
			vector = matcher.group();
		}
		cvssv2.setVector(vector);
	}
	
	//Method to set CVSSV2 access vector
	public void setCVSSV2AccessVector(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("AV:L"))
				cvssv2.setAccessVector(LOCAL);
			if(vectorList.get(i).equalsIgnoreCase("AV:A"))
				cvssv2.setAccessVector(ADJACENT_NETWORK);
			if(vectorList.get(i).equalsIgnoreCase("AV:N"))
				cvssv2.setAccessVector(NETWORK);
		}
	}
	
	//Method to set CVSSV2 access complexity
	public void setCVSSV2AccessComplexity(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("AC:L"))
				cvssv2.setAccessComplexity(LOW);
			if(vectorList.get(i).equalsIgnoreCase("AC:M"))
				cvssv2.setAccessComplexity(MEDIUM);
			if(vectorList.get(i).equalsIgnoreCase("AC:H"))
				cvssv2.setAccessComplexity(HIGH);
		}
	}
	
	//Method to set CVSSV2 authentication
	public void setCVSSV2Authentication(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("Au:M"))
				cvssv2.setAuthentication("MULTIPLE");
			if(vectorList.get(i).equalsIgnoreCase("Au:S"))
				cvssv2.setAuthentication("SINGLE");
			if(vectorList.get(i).equalsIgnoreCase("Au:N"))
				cvssv2.setAuthentication(NONE);
		}
	}
	
	//Method to set CVSSV2 confidentiality impact
	public void setCVSSV2ConfidentialityImpact(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("C:N"))
				cvssv2.setConfidentialityImpact(NONE);
			if(vectorList.get(i).equalsIgnoreCase("C:P"))
				cvssv2.setConfidentialityImpact(PARTIAL);
			if(vectorList.get(i).equalsIgnoreCase("C:C"))
				cvssv2.setConfidentialityImpact(COMPLETE);
		}
	}
	
	//Method to set CVSSV2 integrity impact
	public void setCVSSV2IntegrityImpact(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("I:N"))
				cvssv2.setIntegrityImpact(NONE);
			if(vectorList.get(i).equalsIgnoreCase("I:P"))
				cvssv2.setIntegrityImpact(PARTIAL);
			if(vectorList.get(i).equalsIgnoreCase("I:C"))
				cvssv2.setIntegrityImpact(COMPLETE);
		}
	}
	
	//Method to set CVSSV2 availability impact
	public void setCVSSV2AvailabilityImpact(List<String> vectorList, Cvssv2 cvssv2) {
		
		for(int i=0;i<vectorList.size();i++) {
			
			if(vectorList.get(i).equalsIgnoreCase("A:N"))
				cvssv2.setAvailabilityImpact(NONE);
			if(vectorList.get(i).equalsIgnoreCase("A:P"))
				cvssv2.setAvailabilityImpact(PARTIAL);
			if(vectorList.get(i).equalsIgnoreCase("A:C"))
				cvssv2.setAvailabilityImpact(COMPLETE);
		}
	}
	
	//Method to find the duration
	public String findDuration(Long startTime, Long endTime) {
		
		Long duration = endTime - startTime;
		
		long hours = TimeUnit.NANOSECONDS.toHours(duration);
		duration = duration - TimeUnit.HOURS.toNanos(hours);
		
		long minutes = TimeUnit.NANOSECONDS.toMinutes(duration);
		duration = duration - TimeUnit.MINUTES.toNanos(minutes);
		
		long seconds = TimeUnit.NANOSECONDS.toSeconds(duration);
		
		return "Parser took "+hours+" hour "+minutes+" minutes "+seconds+" seconds to complete";
	}

}
