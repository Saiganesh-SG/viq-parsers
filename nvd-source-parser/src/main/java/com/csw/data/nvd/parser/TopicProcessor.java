package com.csw.data.nvd.parser;

import java.util.List;

public interface TopicProcessor<T> {
    
    List<T> unmarshallObjectFromSourceFile(String sourceFilePath);

}
