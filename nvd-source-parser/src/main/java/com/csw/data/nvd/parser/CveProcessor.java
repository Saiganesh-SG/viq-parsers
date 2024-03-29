package com.csw.data.nvd.parser;

import java.util.List;
import java.util.Map;

import com.csw.data.nvd.json.targets.VendorComment;
import com.csw.data.nvd.json.targets.Vulnerability;

public interface CveProcessor {
	
	Map<String, List<VendorComment>> extractVendorComments(List<String> vendorCommentUrls);

	List<Vulnerability> extractVulnerabilitiesFromSource(String sourceFile, Map<String, List<VendorComment>> vendorComments);

}
