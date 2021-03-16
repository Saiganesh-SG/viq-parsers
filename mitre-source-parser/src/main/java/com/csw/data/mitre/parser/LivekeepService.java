package com.csw.data.mitre.parser;

import org.json.JSONObject;

import com.csw.data.mitre.pojo.cwe.WeaknessRoot;

public interface LivekeepService {

	JSONObject writeToLiveKeep(WeaknessRoot weakness, String sourceFilePath) throws Exception ;
	
}
