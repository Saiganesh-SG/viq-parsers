package com.csw.data.nvd.service;

import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.csw.data.nvd.config.ParseType;
import com.csw.data.nvd.json.cpe.source.DefCpeMatch;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
@Qualifier("CpeLiveKeepServiceImpl")
public class CpeLiveKeepServiceImpl implements LiveKeepService<DefCpeMatch> {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(CpeLiveKeepServiceImpl.class);
    
    @Override
    public JSONArray writeFileToLiveKeep(List<DefCpeMatch> defCpeMatchs, String cpeLocalDirectory, Map<String, Integer> recordStats) {
        var kafkaMessages = new JSONArray();
        for (DefCpeMatch defCpeMatch : defCpeMatchs) {
            if(!defCpeMatch.getCpe23Uri().equalsIgnoreCase("cpe:2.3:h:intel:core_i7:8850h:*:*:*:*:*:*:*")) {
                continue;
            }
            JSONObject message = createKafkaMessage(defCpeMatch.getCpe23Uri(), defCpeMatch, ParseType.CPE);
            kafkaMessages.put(message);
        }
        recordStats.put("newRecords", defCpeMatchs.size());
        return kafkaMessages;
    }
    
    private JSONObject createKafkaMessage(String id, DefCpeMatch defCpeMatch, ParseType cpe) {
        var mapper = new ObjectMapper();
        var message = new JSONObject();
        try {
            message.put("id", id);
            message.put("content", mapper.writeValueAsString(defCpeMatch));
            message.put("fileType", cpe);
        } catch (JSONException e) {
            LOGGER.error("JSONException while creating kafka message for cpe file : {}", e.getMessage());
        }
        catch (JsonProcessingException e) {
            LOGGER.error("JsonProcessingException while creating kafka message for cpe file : {}", e.getMessage());
        }
        return message;
    }
}
