package com.csw.data.nvd.parser;

import java.util.List;

public interface TopicProcessor<T, U> {
    
    T unmarshallObjectFromSourceFile(String sourceFilePath);

    List<U> extractTopicContentFromSource(T sourceFileObject);

}
