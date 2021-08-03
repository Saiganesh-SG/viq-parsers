package com.csw.data.nvd.service;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;

import com.csw.data.nvd.json.cpedictionary.targets.CpeDictionary;

public interface LiveKeepService<T> {

	JSONArray writeFileToLiveKeep(List<T> vulnerabilities, String cveLocalDirectory, Map<String, Integer> recordStats) throws IOException;

    JSONArray writeCpeDictionaryFileToKafka(List<CpeDictionary> cpeDictionaryList, Object object, Map<String, Integer> recordStats);

}
