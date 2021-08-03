package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.XMLEvent;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.json.cpedictionary.target.Cpe22;
import com.csw.data.nvd.json.cpedictionary.target.Cpe23;
import com.csw.data.nvd.json.cpedictionary.target.CpeDictionary;
import com.csw.data.nvd.json.cpedictionary.target.Reference;
import com.csw.data.nvd.parser.TopicProcessor;

@Service
@Qualifier("CpeDictionaryProcessor")
public class CpeDictionaryProcessor implements TopicProcessor<CpeDictionary> {

    /** The Constant LOGGER. */
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeDictionaryProcessor.class);

    @Override
    public List<CpeDictionary> unmarshallObjectFromSourceFile(String sourceFilePath) {
        sourceFilePath = "C:\\Users\\viswamr\\Desktop\\cpe_dictionary_truncated.xml";
        var sourceFile = new File(sourceFilePath);
        if (!sourceFile.exists()) {
            LOGGER.error("The source file does not exist : {}", sourceFilePath);
        }

        List<CpeDictionary> cpeDictionaries = new ArrayList<>();
        List<Reference> references = new ArrayList<>();
        CpeDictionary cpeDictionary = null;
        Cpe22 cpe22 = null;
        Cpe23 cpe23 = null;
        Reference reference = null;

        var xmlInputFactory = XMLInputFactory.newInstance();
        XMLEventReader reader;
        try {
            reader = xmlInputFactory.createXMLEventReader(new FileInputStream(sourceFilePath));
            while (reader.hasNext()) {
                XMLEvent nextEvent = reader.nextEvent();

                if (nextEvent.isStartElement()) {
                    var startElement = nextEvent.asStartElement();
                    switch (startElement.getName().getLocalPart()) {

                        case "cpe-item":
                            cpeDictionary = new CpeDictionary();
                            cpe22 = new Cpe22();
                            var uri = startElement.getAttributeByName(new QName("name"));
                            if (null != uri) {
                                cpe22.setCpe22Uri(uri.getValue());
                                cpe22 = setCpe22Components(cpe22);
                            }

                            var deprecated = startElement.getAttributeByName(new QName("deprecated"));
                            if (null != deprecated && deprecated.getValue().equals("true")) {
                                cpe22.setDeprecated(Boolean.TRUE);
                            }

                            var deprecatedBy = startElement.getAttributeByName(new QName("deprecated_by"));
                            if (null != deprecatedBy) {
                                cpe22.setDeprecatedBy(deprecatedBy.getValue());
                            }

                            var deprecationDate = startElement.getAttributeByName(new QName("deprecation_date"));
                            if (null != deprecationDate) {
                                cpe22.setDeprecationDate(dateToStandardDateFormat(deprecationDate.getValue()));
                            }
                            break;

                        case "title":
                            nextEvent = reader.nextEvent();
                            cpeDictionary.setTitle(nextEvent.asCharacters().getData());
                            break;

                        case "cpe23-item":
                            cpe23 = new Cpe23();
                            var name = startElement.getAttributeByName(new QName("name"));
                            if (null != name) {
                                cpe23.setCpe23Uri(name.getValue());
                                cpe23 = setCpe23Components(cpe23);
                            }
                            break;

                        case "deprecation":
                            var cpe23DeprecationDate = startElement.getAttributeByName(new QName("date"));
                            if (null != cpe23DeprecationDate) {
                                cpe23.setDeprecated(Boolean.TRUE);
                                cpe23.setDeprecationDate(cpe23DeprecationDate.getValue());
                            }
                            break;

                        case "deprecated-by":
                            var cpe23DeprecatedBy = startElement.getAttributeByName(new QName("name"));
                            if (null != cpe23DeprecatedBy) {
                                cpe23.setDeprecatedBy(cpe23DeprecatedBy.getValue());
                            }

                            var cpe23DeprecationReason = startElement.getAttributeByName(new QName("type"));
                            if (null != cpe23DeprecationReason) {
                                cpe23.setDeprecationReason(cpe23DeprecationReason.getValue());
                            }
                            break;

                        case "reference":
                            nextEvent = reader.nextEvent();
                            reference = new Reference();
                            var href = startElement.getAttributeByName(new QName("href"));
                            if (null != href) {
                                reference.setUrl(href.getValue());
                            }
                            reference.setTag(nextEvent.asCharacters().getData());
                            break;

                        default:
                            break;
                    }
                }

                if (nextEvent.isEndElement()) {
                    var endElement = nextEvent.asEndElement();
                    if (endElement.getName().getLocalPart().equals("reference")) {
                        references.add(reference);
                    }
                    if (endElement.getName().getLocalPart().equals("cpe-item")) {
                        cpeDictionary.setCpe22(cpe22);
                        cpeDictionary.setCpe23(cpe23);
                        cpeDictionary.setReferences(references);
                        cpeDictionaries.add(cpeDictionary);
                        references = new ArrayList<>();
                    }
                }
            }
        }
        catch (FileNotFoundException | XMLStreamException e) {
            e.printStackTrace();
        }
        return cpeDictionaries;
    }

    private static Cpe22 setCpe22Components(Cpe22 cpe22Arg) {
        var cpe22 = cpe22Arg;
        String cpe22Uri = escapeCpeUri(cpe22.getCpe22Uri());
        String[] cpe22Components = cpe22Uri.split(":");
        for (var i = 0; i < cpe22Components.length; i++) {
            switch (i) {
                case 1:
                    cpe22.setPart(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 2:
                    cpe22.setVendor(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 3:
                    cpe22.setProduct(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 4:
                    cpe22.setVersion(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 5:
                    cpe22.setUpdate(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 6:
                    cpe22.setEdition(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                case 7:
                    cpe22.setLanguage(StringUtils.stripToNull(cpe22Components[i]));
                    break;
                default:
                    break;
            }
        }
        return cpe22;
    }

    private static Cpe23 setCpe23Components(Cpe23 cpe23Arg) {
        var cpe23 = cpe23Arg;
        String cpe23Uri = escapeCpeUri(cpe23.getCpe23Uri());
        String[] cpe23Components = cpe23Uri.split(":");
        for (var i = 0; i < cpe23Components.length; i++) {
            switch (i) {
                case 2:
                    cpe23.setPart(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 3:
                    cpe23.setVendor(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 4:
                    cpe23.setProduct(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 5:
                    cpe23.setVersion(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 6:
                    cpe23.setUpdate(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 7:
                    cpe23.setEdition(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 8:
                    cpe23.setLanguage(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 9:
                    cpe23.setSoftwareEdition(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 10:
                    cpe23.setTargetSoftware(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 11:
                    cpe23.setTargetHardware(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                case 12:
                    cpe23.setOther(StringUtils.stripToNull(cpe23Components[i]));
                    break;
                default:
                    break;
            }
        }
        return cpe23;
    }

    private static String escapeCpeUri(String cpeUri) {
        cpeUri = cpeUri.replace("\\@", "@");
        cpeUri = cpeUri.replace("\\/", "/");
        cpeUri = cpeUri.replace("cpe:/", "cpe:");
        cpeUri = cpeUri.replace("*", "");
        return cpeUri;
    }

    private static String dateToStandardDateFormat(String sourceDate) {
        String targetDate = null;
        var originalStringFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
        var desiredStringFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

        var readingFormat = new SimpleDateFormat(originalStringFormat);
        var outputFormat = new SimpleDateFormat(desiredStringFormat);

        Date date;
        try {
            date = readingFormat.parse(sourceDate);
            targetDate = outputFormat.format(date);
        }
        catch (ParseException e) {
            e.printStackTrace();
        }
        return targetDate;
    }

}
