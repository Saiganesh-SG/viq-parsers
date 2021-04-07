package com.csw.data.mitre.parser;

import java.util.Map;

import org.json.JSONObject;

import com.csw.data.mitre.cwe.pojo.WeaknessRoot;

public interface LivekeepService {

	JSONObject writeToLiveKeep(WeaknessRoot weakness, String sourceFilePath, Map<String, Integer> recordStats) throws Exception ;
	
}
