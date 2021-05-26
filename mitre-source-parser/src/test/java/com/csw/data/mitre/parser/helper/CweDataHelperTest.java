package com.csw.data.mitre.parser.helper;

import java.math.BigInteger;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;

import org.easymock.EasyMockExtension;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.csw.data.mitre.cwe.jaxb.ExternalReferenceType;
import com.csw.data.mitre.cwe.jaxb.StatusEnumeration;
import com.csw.data.mitre.cwe.jaxb.WeaknessType;
import com.csw.data.mitre.cwe.jaxb.WeaknessCatalog.ExternalReferences;
import com.csw.data.mitre.cwe.pojo.Reference;
import com.csw.data.mitre.cwe.pojo.WeaknessMetaData;
import com.csw.data.mitre.parser.LivekeepService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@ExtendWith(EasyMockExtension.class)
class CweDataHelperTest {

    @TestSubject
    private CweDataHelper cweDataHelper = new CweDataHelper();

    @Mock
    private LivekeepService livekeepServiceMock;

    @BeforeEach
    public void setup() {
        EasyMockSupport.injectMocks(this);
    }

    @Test
    void testExtractExternalReferences() throws ParseException, DatatypeConfigurationException {
        ExternalReferences externalReferences = new ExternalReferences();
        ExternalReferenceType externalReferenceType = new ExternalReferenceType();

        DateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        Date date = format.parse("2014-04-24 11:15:00");
        GregorianCalendar cal = new GregorianCalendar();
        cal.setTime(date);
        XMLGregorianCalendar xmlGregCal = DatatypeFactory.newInstance().newXMLGregorianCalendar(cal);

        externalReferenceType.setURLDate(xmlGregCal);

        List<ExternalReferenceType> externalReferenceTypes = new ArrayList<ExternalReferenceType>();
        externalReferenceTypes.add(externalReferenceType);
        externalReferences.getExternalReference().addAll(externalReferenceTypes);
        Map<String, Reference> externalReferenceMap = cweDataHelper.extractExternalReferences(externalReferences);
    }
    
    @Test
    void testExtractExternalReferencesWithNullReference() {
        ExternalReferences externalReferences = new ExternalReferences();
        List<ExternalReferenceType> externalReferenceTypes = new ArrayList<ExternalReferenceType>();
        externalReferences.getExternalReference().addAll(externalReferenceTypes);
        Map<String, Reference> externalReferenceMap = cweDataHelper.extractExternalReferences(externalReferences);
    }
    
    @Test
    void testExtractWeakness() throws JsonMappingException, JsonProcessingException {
        
        ObjectMapper mapper = new ObjectMapper();
        
        Map<String, WeaknessMetaData> weaknessMetaDataList = new HashMap<String, WeaknessMetaData>();
        String weaknessMetaDataString = "{\"id\":\"1004\",\"title\":\"Sensitive Cookie Without 'HttpOnly' Flag\",\"type\":\"Weakness\",\"abstraction\":\"Variant\"}";
        WeaknessMetaData weaknessMetaData = mapper.readValue(weaknessMetaDataString, WeaknessMetaData.class);
        weaknessMetaDataList.put("1004", weaknessMetaData);
        
        Map<String, Reference> weaknessReferenceList = new HashMap<String, Reference>();
        String referenceString = "{\"id\":\"REF-2\",\"section\":null,\"author\":[\"OWASP\"],\"title\":\"HttpOnly\",\"edition\":null,\"publication\":null,\"publisher\":null,\"publicationYear\":null,\"publicationMonth\":null,\"publicationDay\":null,\"url\":\"https://www.owasp.org/index.php/HttpOnly\",\"urlDate\":null}";
        Reference reference = mapper.readValue(referenceString, Reference.class);
        weaknessReferenceList.put("REF-2", reference);
        
        List<WeaknessType> weaknessesList = new ArrayList<>();
        String weaknessTypeString = "{\"description\": \"The software uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.\",\"relatedWeaknesses\": {\"relatedWeakness\": [{\"nature\": \"CHILD_OF\",\"cweid\": 732,\"viewID\": 1000,\"chainID\": null,\"ordinal\": \"PRIMARY\"}]},\"weaknessOrdinalities\": null,\"applicablePlatforms\": {\"language\": [{\"name\": null,\"clazz\": \"LANGUAGE_INDEPENDENT\",\"prevalence\": \"UNDETERMINED\"}],\"operatingSystem\": [],\"architecture\": [],\"technology\": [{\"name\": null,\"clazz\": \"WEB_BASED\",\"prevalence\": \"UNDETERMINED\"}]},\"alternateTerms\": null,\"modesOfIntroduction\": {\"introduction\": [{\"phase\": \"IMPLEMENTATION\",\"note\": null},{\"phase\": \"ARCHITECTURE_AND_DESIGN\",\"note\": null}]},\"exploitationFactors\": null,\"likelihoodOfExploit\": \"MEDIUM\",\"commonConsequences\": {\"consequence\": [{\"scope\": [\"CONFIDENTIALITY\"],\"impact\": [\"READ_APPLICATION_DATA\"],\"likelihood\": null,\"consequenceID\": null},{\"scope\": [\"INTEGRITY\"],\"impact\": [\"GAIN_PRIVILEGES_OR_ASSUME_IDENTITY\"],\"likelihood\": null,\"consequenceID\": null}]},\"detectionMethods\": null,\"potentialMitigations\": {\"mitigation\": [{\"phase\": [\"IMPLEMENTATION\"],\"strategy\": null,\"effectiveness\": \"HIGH\",\"mitigationID\": null}]},\"functionalAreas\": null,\"affectedResources\": null,\"taxonomyMappings\": null,\"relatedAttackPatterns\": null,\"references\": {\"reference\": [{\"externalReferenceID\": \"REF-2\",\"section\": null}]},\"notes\": null,\"contentHistory\": {\"submission\": {\"submissionName\": \"CWE Content Team\",\"submissionOrganization\": \"MITRE\",\"submissionDate\": 1483295400000,\"submissionComment\": null},\"modification\": [{\"modificationName\": \"CWE Content Team\",\"modificationOrganization\": \"MITRE\",\"modificationDate\": 1510079400000,\"modificationImportance\": null,\"modificationComment\": \"updated Applicable_Platforms, References, Relationships\"},{\"modificationName\": \"CWE Content Team\",\"modificationOrganization\": \"MITRE\",\"modificationDate\": 1582482600000,\"modificationImportance\": null,\"modificationComment\": \"updated Applicable_Platforms, Relationships\"}],\"contribution\": [],\"previousEntryName\": []},\"id\": 1004,\"name\": \"Sensitive Cookie Without 'HttpOnly' Flag\",\"abstraction\": \"VARIANT\",\"structure\": \"SIMPLE\",\"status\": \"INCOMPLETE\"}";
        WeaknessType weaknessType = mapper.readValue(weaknessTypeString, WeaknessType.class);
        weaknessesList.add(weaknessType);
        
        cweDataHelper.extractWeakness(weaknessesList, weaknessReferenceList, weaknessMetaDataList);
        
    }

}
