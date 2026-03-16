package org.owasplab.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.sanitize.FlowSanitizer;
import org.owasplab.coach.store.FlowStore;
import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;

/**
 * CSP 违规报告接收端点（用于“可观测闭环”）。
 * - 浏览器在触发 CSP 违规时，会向 report-uri 发送 JSON（常见 content-type=application/csp-report 或 application/json）
 * - 这里将报告写入 FlowStore，作为一种“可分析的 FlowRecord”，让 Coach 能看到 CSP 的价值与局限
 */
@RestController
public class CspReportController {

    private final FlowStore flowStore;
    private final FlowSanitizer sanitizer;
    private final ObjectMapper objectMapper;

    public CspReportController(FlowStore flowStore, FlowSanitizer sanitizer, ObjectMapper objectMapper) {
        this.flowStore = flowStore;
        this.sanitizer = sanitizer;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/api/v1/security/csp/report")
    public ApiResponse<Map<String, Object>> report(@RequestBody(required = false) String body, HttpServletRequest request) {
        long ts = System.currentTimeMillis();
        String sessionKey = resolveSessionKey(request);

        String contentType = request == null ? null : request.getContentType();
        String reqBody = null;
        try {
            String raw = body == null ? "" : body;
            // 先尝试“能否解析”为 JSON：用于过滤掉非 JSON 噪音（不抛出到启动阶段）
            if (objectMapper != null && raw.trim().startsWith("{")) {
                objectMapper.readTree(raw);
            }
            reqBody = sanitizer == null ? raw : sanitizer.sanitizeBody(contentType, raw, 4096);
        } catch (Exception ignore) {
            // 解析失败也不影响接收：降级为截断后的纯文本
            String raw = body == null ? "" : body;
            reqBody = raw.length() > 2048 ? raw.substring(0, 2048) : raw;
        }

        Map<String, String> headers = new LinkedHashMap<>();
        if (request != null) {
            headers.put("content-type", trim(request.getHeader(HttpHeaders.CONTENT_TYPE)));
            headers.put("user-agent", trim(request.getHeader(HttpHeaders.USER_AGENT)));
            headers.put("origin", trim(request.getHeader("Origin")));
            headers.put("referer", trim(request.getHeader(HttpHeaders.REFERER)));
            headers.put("sec-fetch-site", trim(request.getHeader("Sec-Fetch-Site")));
        }
        Map<String, String> storedHeaders = sanitizer == null ? headers : sanitizer.sanitizeHeaders(headers);

        FlowRecord record = new FlowRecord(
                UUID.randomUUID().toString(),
                ts,
                sessionKey,
                "CSP",
                "/__csp__",
                request == null ? null : request.getQueryString(),
                204,
                0L,
                "csp_violation_report",
                storedHeaders,
                reqBody,
                null
        );
        flowStore.append(record);

        Map<String, Object> data = new HashMap<>();
        data.put("stored", true);
        data.put("id", record.getId());
        data.put("sessionKey", sessionKey);

        ApiMeta meta = new ApiMeta(
                "security",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.none,
                "CWE-000",
                "csp_report"
        );
        return ApiResponse.ok(data, meta);
    }

    private static String resolveSessionKey(HttpServletRequest request) {
        if (request == null) return "anon:unknown";
        HttpSession session = request.getSession(false);
        if (session != null) return session.getId();

        String ip = request.getRemoteAddr();
        if (ip == null || ip.trim().isEmpty()) ip = "unknown";
        return "anon:" + ip;
    }

    private static String trim(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}

