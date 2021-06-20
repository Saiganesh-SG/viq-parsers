package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.json.cpe.source.DefCpeMatch;
import com.csw.data.nvd.parser.TopicProcessor;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
@Qualifier("CpeProcessor")
public class CpeProcessor implements TopicProcessor<DefCpeMatch> {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeProcessor.class);

    @Override
    public List<DefCpeMatch> unmarshallObjectFromSourceFile(String sourceFilePath) {
        List<DefCpeMatch> defCpeMatchs = new ArrayList<>();
        try {
            defCpeMatchs = parseJsonFromFile(new File(sourceFilePath));
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return defCpeMatchs;
    }

    private List<DefCpeMatch> parseJsonFromFile(File sourceFilePath) throws JsonParseException, IOException {
        InputStream nvdCpeMatchInputStream = new FileInputStream(sourceFilePath);
        List<DefCpeMatch> defCpeMatchs = new ArrayList<>();
        // Create and configure an ObjectMapper instance
        ObjectMapper mapper = new ObjectMapper();
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        // Create a JsonParser instance
        try (JsonParser jsonParser = mapper.getFactory().createParser(nvdCpeMatchInputStream)) {
            
            JsonToken currentToken;
            currentToken = jsonParser.nextToken();
            
            // Check the first token
            if (currentToken != JsonToken.START_OBJECT) {
                throw new IllegalStateException("Expected content to be an object");
            }
            
            // Iterate over the tokens until the end of the object
            while (jsonParser.nextToken() != JsonToken.END_OBJECT) {
                
                String fieldName = jsonParser.getCurrentName();
                currentToken = jsonParser.nextToken();
                if (fieldName.equals("matches")) {
                    if (currentToken == JsonToken.START_ARRAY) {
                        // For each of the records in the array
                        while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                            DefCpeMatch defCpeMatch = mapper.readValue(jsonParser, DefCpeMatch.class);
                            defCpeMatchs.add(defCpeMatch);
                        }
                    }
                }
            }
        }
        return defCpeMatchs;
    }

}
