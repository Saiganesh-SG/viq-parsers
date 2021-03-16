package com.csw.data.nvd.parser;

import org.springframework.stereotype.Service;

@Service
public interface NvdTopicParser {
	
    public void run(String parseType) throws Exception;
    
}
