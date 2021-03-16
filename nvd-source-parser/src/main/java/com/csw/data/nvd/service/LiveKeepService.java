package com.csw.data.nvd.service;

import java.io.IOException;
import java.util.List;

import org.json.JSONArray;

import com.csw.data.nvd.json.target.Vulnerability;

public interface LiveKeepService {

	JSONArray writeFileToLiveKeep(List<Vulnerability> vulnerabilities, String cveLocalDirectory) throws IOException;

}
