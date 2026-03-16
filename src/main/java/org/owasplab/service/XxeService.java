package org.owasplab.service;

import java.util.Map;

public interface XxeService {

    Map<String, Object> parseVuln(String xmlContent);

    Map<String, Object> parseSafe(String xmlContent);

    Map<String, Object> getInfo();
}