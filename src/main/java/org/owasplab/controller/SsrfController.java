package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.owasplab.service.SsrfService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/ssrf")
public class SsrfController {

    @Autowired
    private SsrfService ssrfService;

    @PostMapping("/fetch/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> fetch(
            @PathVariable String mode,
            @RequestParam String url,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {

        Mode m = resolveMode(mode);
        String ctx = "ssrf_fetch";
        ApiMeta meta = new ApiMeta("ssrf", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-918", ctx);

        Map<String, Object> result = ssrfService.fetchUrl(m, url, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    @PostMapping("/image-proxy/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> imageProxy(
            @PathVariable String mode,
            @RequestParam String imageUrl,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {

        Mode m = resolveMode(mode);
        String ctx = "ssrf_image_proxy";
        ApiMeta meta = new ApiMeta("ssrf", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-918", ctx);

        Map<String, Object> result = ssrfService.proxyImage(m, imageUrl, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    @PostMapping("/download/{mode}")
    public ResponseEntity<ApiResponse<Map<String, Object>>> download(
            @PathVariable String mode,
            @RequestParam String fileUrl,
            @RequestParam(required = false, defaultValue = "1") int weakLevel) {

        Mode m = resolveMode(mode);
        String ctx = "ssrf_download";
        ApiMeta meta = new ApiMeta("ssrf", m,
                Arrays.asList("coding_sast", "testing_dast"),
                SignalChannel.inband, "CWE-918", ctx);

        Map<String, Object> result = ssrfService.downloadFile(m, fileUrl, weakLevel);
        result.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(result, meta));
    }

    /**
     * 模拟云元数据端点，仅用于 SSRF 靶场演示（VULN 模式下通过 127.0.0.1 访问）。
     */
    @GetMapping("/internal/metadata")
    public Map<String, Object> internalMetadata() {
        Map<String, Object> mock = new HashMap<>();
        mock.put("description", "模拟云元数据（仅内网可访问，用于 SSRF 演示）");

        Map<String, Object> meta = new HashMap<>();
        meta.put("instance-id", "lab-ssrf-demo-001");
        meta.put("local-ipv4", "127.0.0.1");
        meta.put("ami-id", "lab-ami-ssrf");
        mock.put("meta-data", meta);

        mock.put("hint", "若在 VULN 模式下用 http://127.0.0.1:8081/api/v1/ssrf/internal/metadata 请求，说明存在 SSRF");
        return mock;
    }

    private Mode resolveMode(String mode) {
        try {
            return Mode.valueOf(mode.toUpperCase());
        } catch (IllegalArgumentException e) {
            return Mode.VULN;
        }
    }
}
