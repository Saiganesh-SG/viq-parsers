package com.csw.data.nvd.service;

public interface EtlService {
    public void run(String parserType, boolean isLatest) throws Exception;
}
