package com.csw.data.nvd.parser.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.config.ParseType;
import com.csw.data.nvd.json.targets.VendorComment;
import com.csw.data.nvd.json.targets.Vulnerability;
import com.csw.data.nvd.parser.CveProcessor;
import com.csw.data.nvd.parser.helper.CveConstructor;
import com.csw.data.util.ParserConstants;
import com.csw.data.util.ParserFileUtils;

@Service
@Qualifier("CveProcessor")
public class CveProcessorImpl implements CveProcessor {

    @Value("${parser.cve.source.directory}")
    private String cveSourceDirectory;

    @Autowired
    private CveConstructor cveConstructor;

    @Override
    public Map<String, List<VendorComment>> extractVendorComments(List<String> vendorCommentUrls) {
        Map<String, List<VendorComment>> vendorComments = new HashMap<>();
        List<String> sourceFiles = ParserFileUtils.extractSourceFilesWithExtension(cveSourceDirectory, vendorCommentUrls, ParseType.COMMENT.name(), ParserConstants.XML_FILE_EXTENSION);
        vendorComments.putAll(processVendorCommentsFromSource(sourceFiles));
        return vendorComments;
    }

    @Override
    public List<Vulnerability> extractVulnerabilitiesFromSource(String sourceFile, Map<String, List<VendorComment>> vendorComments) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        vulnerabilities.addAll(cveConstructor.constructVulnerabilititesFromSource(sourceFile, vendorComments));
        return vulnerabilities;
    }

    private Map<String, List<VendorComment>> processVendorCommentsFromSource(List<String> sourceFiles) {
        Map<String, List<VendorComment>> result = new HashMap<>();
        for (String sourceFile : sourceFiles) {
            result.putAll(cveConstructor.constructVendorCommentsFromSource(sourceFile));
        }
        return result;
    }

}
