package com.csw.data.mitre.service;

public interface EtlService {
    public void run(String parserType, boolean isLatest) throws Exception;
}
