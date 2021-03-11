package com.csw.data.mitre.parser;

import java.io.IOException;

import org.springframework.stereotype.Service;

/**
 * The Interface MitreSourceParser.
 */
@Service
public interface WeaknessParser {
	
    /**
     * Parses the weakness.
     *
     * @param isLatest the is latest
     * @throws IOException Signals that an I/O exception has occurred.
     */
    void extractWeaknessFile() throws Exception;
    
}
