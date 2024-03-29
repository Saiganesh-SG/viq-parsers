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
import com.csw.data.nvd.json.cpedictionary.targets.CpeDictionary;
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
            JSONObject message = createKafkaMessage(defCpeMatch.getCpe23Uri(), defCpeMatch, ParseType.CPE);
            kafkaMessages.put(message);
        }
        recordStats.put("newRecords", defCpeMatchs.size());
        return kafkaMessages;
    }

    @Override
    public JSONArray writeCpeDictionaryFileToKafka(List<CpeDictionary> cpeDictionaryList, Object object, Map<String, Integer> recordStats) {
        var kafkaMessages = new JSONArray();
        for (CpeDictionary cpeDictionary : cpeDictionaryList) {
            JSONObject message = createCpeDictionaryKafkaMessage(cpeDictionary.getCpe22().cpe22Uri, cpeDictionary, ParseType.CPE_DICTIONARY);
            kafkaMessages.put(message);
        }
        recordStats.put("newRecords", cpeDictionaryList.size());
        return kafkaMessages;
    }

    private JSONObject createKafkaMessage(String id, DefCpeMatch defCpeMatch, ParseType cpe) {
        var mapper = new ObjectMapper();
        var message = new JSONObject();
        try {
            message.put("id", id);
            message.put("content", mapper.writeValueAsString(defCpeMatch));
            message.put("fileType", cpe);
        }
        catch (JSONException e) {
            LOGGER.error("JSONException while creating kafka message for cpe file : {}", e.getMessage());
        }
        catch (JsonProcessingException e) {
            LOGGER.error("JsonProcessingException while creating kafka message for cpe file : {}", e.getMessage());
        }
        return message;
    }

    private JSONObject createCpeDictionaryKafkaMessage(String id, CpeDictionary cpeDictionary, ParseType cpeDictionaryType) {
        var mapper = new ObjectMapper();
        var message = new JSONObject();

        try {
            message.put("id", id);
            message.put("content", mapper.writeValueAsString(cpeDictionary));
            message.put("fileType", cpeDictionaryType);
        }
        catch (JSONException e) {
            LOGGER.error("JSONException while creating kafka message for cpe file : {}", e.getMessage());
        }
        catch (JsonProcessingException e) {
            LOGGER.error("JsonProcessingException while creating kafka message for cpe file : {}", e.getMessage());
        }

        return message;
    }

}
