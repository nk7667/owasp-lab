package org.owasplab.service;

import org.owasplab.core.Mode;

import java.util.Map;

public interface CommandExecutionService {
    Map<String, Object> executePing(Mode mode, String host, int weakLevel);

    Map<String, Object> executeLs(Mode mode, String path, int weakLevel);

    Map<String, Object> executeGrep(Mode mode, String keyword, int weakLevel);
    
    Map<String, Object> executeCat(Mode mode, String filename, int weakLevel);
}
