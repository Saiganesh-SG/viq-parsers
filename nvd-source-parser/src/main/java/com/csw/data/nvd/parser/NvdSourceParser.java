package com.csw.data.nvd.parser;

import org.springframework.stereotype.Service;

@Service
public interface NvdSourceParser {
	
    public void run(String parseType, boolean isLatest) throws Exception;
    
}
