package com.csw.data.mitre;

import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

import org.easymock.EasyMock;
import org.easymock.EasyMockExtension;
import org.easymock.EasyMockSupport;
import org.easymock.Mock;
import org.easymock.TestSubject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.csw.data.mitre.parser.impl.MitreTopicParserImpl;


@ExtendWith(EasyMockExtension.class)
public class MitreSourceParserApplicationTest {
    
    @TestSubject
    private MitreSourceParserApplication mitreSourceParserApplication;
    
    @Mock
    private MitreTopicParserImpl mitreTopicParserMock;
    
    @BeforeEach
    public void setup() {
        EasyMockSupport.injectMocks(this);
    }
    
    @Test
    void testRun() throws Exception {
        mitreTopicParserMock.parseTopicType(EasyMock.anyString());
        EasyMock.expectLastCall();
        replay(mitreTopicParserMock);
        mitreSourceParserApplication.run("test");
        verify(mitreTopicParserMock);
    }

}
