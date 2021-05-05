package com.csw.data.mitre.parser;

import java.util.List;

public interface DataProcessor {
	
    public void process(List<String> sourceFiles) throws Exception;
    
}
