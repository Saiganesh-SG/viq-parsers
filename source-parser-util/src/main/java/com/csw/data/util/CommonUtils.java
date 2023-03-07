package com.csw.data.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.text.StringEscapeUtils;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The Class CommonUtils.
 */
public class CommonUtils {
    
    /**
     * Instantiates a new common utils.
     */
    private CommonUtils() {
    }
    
    /**
     * Split json array by chunk limit.
     *
     * @param kafkaMessages the kafka messages
     * @param limit the limit
     * @return the list
     */
    public static List<JSONArray> splitJsonArrayByChunkLimit(JSONArray kafkaMessages, int limit) {
        List<JSONArray> jsonArraysList = new ArrayList<>();
        int counter = 0;
        JSONArray messageList = new JSONArray();
        for (int i = 0; i < kafkaMessages.length(); i++) {
            
            //push the array to list when it hits the limit
            if(counter >= limit) {
                jsonArraysList.add(messageList);
                counter = 0;
                messageList = new JSONArray();
            }

            //extract every json message
            JSONObject message = kafkaMessages.getJSONObject(i);
            messageList.put(message);
            
            //terminate the loop if the count is less than limit
            if(i == kafkaMessages.length()-1) {
                jsonArraysList.add(messageList);
                continue;
            }
            
            counter++;
        }
        return jsonArraysList;
    }

    public static String unescapeString(String input){
        return StringEscapeUtils.unescapeJava(input);
    }

}
