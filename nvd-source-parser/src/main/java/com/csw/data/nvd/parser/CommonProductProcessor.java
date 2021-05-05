package com.csw.data.nvd.parser;

import java.io.IOException;

public interface CommonProductProcessor {
	
	void process(String path) throws Exception;
	
	void parseCpe() throws IOException;

}
