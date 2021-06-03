package com.csw.data.nvd.parser.impl;

import java.io.File;
import java.io.IOException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.json.cpe.source.DefCpeMatch;
import com.csw.data.nvd.json.cpe.source.NvdCpeMatch;
import com.csw.data.nvd.parser.TopicProcessor;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
@Qualifier("CpeProcessor")
public class CpeProcessor implements TopicProcessor<NvdCpeMatch, DefCpeMatch> {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeProcessor.class);

    /**
     * Unmarshall NvdCpeMatch from source file.
     *
     * @param sourceFilePath the source file path
     * @param topic the topic
     * @return the nvd cpe match
     */
    @Override
    public NvdCpeMatch unmarshallObjectFromSourceFile(String sourceFilePath) {
        
        ObjectMapper mapper = new ObjectMapper();
        NvdCpeMatch nvdCpeMatch = null;
        try {
            nvdCpeMatch = mapper.readValue(new File(sourceFilePath), NvdCpeMatch.class);
        }
        catch (IOException e) {
            LOGGER.error("Error while unmarshalling the cpe source file : {}", sourceFilePath);
        }
        return nvdCpeMatch;
    }

    @Override
    public List<DefCpeMatch> extractTopicContentFromSource(NvdCpeMatch cpeMatches) {
        return cpeMatches.getMatches();
    }
    
}
