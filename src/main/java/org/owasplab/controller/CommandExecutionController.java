package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.owasplab.service.CommandExecutionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/command-execution")
public class CommandExecutionController {
    @Autowired
    private CommandExecutionService commandExecutionService;

    @PostMapping("/network/ping/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> ping(
            @PathVariable String mode,
            @RequestParam String host,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {
        
        Mode m = resolveMode(mode);
        String ctx = "network_ping";
        ApiMeta meta = new ApiMeta("command_execution", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-78", ctx);

        Map<String, Object> result = commandExecutionService.executePing(m, host, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    @PostMapping("/file/ls/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> ls(
            @PathVariable String mode,
            @RequestParam String path,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {
        
        Mode m = resolveMode(mode);
        String ctx = "file_ls";
        ApiMeta meta = new ApiMeta("command_execution", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-78", ctx);

        Map<String, Object> result = commandExecutionService.executeLs(m, path, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    @PostMapping("/file/grep/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> grep(
            @PathVariable String mode,
            @RequestParam String keyword,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {
        
        Mode m = resolveMode(mode);
        String ctx = "file_grep";
        ApiMeta meta = new ApiMeta("command_execution", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-78", ctx);

        Map<String, Object> result = commandExecutionService.executeGrep(m, keyword, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }
    
    @PostMapping("/file/cat/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> cat(
            @PathVariable String mode,
            @RequestParam String filename,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {
        
        Mode m = resolveMode(mode);
        String ctx = "file_cat";
        ApiMeta meta = new ApiMeta("command_execution", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-78", ctx);

        Map<String, Object> result = commandExecutionService.executeCat(m, filename, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    private Mode resolveMode(String mode) {
        try {
            return Mode.valueOf(mode.toUpperCase());
        } catch (IllegalArgumentException e) {
            return Mode.VULN;
        }
    }
}
