package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
@RestController
public class HealthController {

    @GetMapping("/api/v1/health")
    public ApiResponse<Map<String,Object>> health() {
        Map<String,Object> data = new HashMap<>();
        data.put("app","owasp-lab");
        data.put("status","ok");

        ApiMeta meta = new ApiMeta(
                "health",
                Mode.NORMAL,
                Arrays.asList("requirements","coding_sast","testing_dast"),
                SignalChannel.none,
                "CWE-000"
        );
        return ApiResponse.ok(data,meta);
    }
}
