package org.owasplab.coach;

import org.owasplab.coach.dto.CoachAnalyzeRequest;
import org.owasplab.coach.dto.CoachUiEventRequest;
import org.owasplab.coach.llm.DashscopeOpenAiCompatibleClient;
import org.owasplab.coach.llm.CoachAnswerService;
import org.owasplab.coach.llm.CoachLlmProperties;
import org.owasplab.coach.llm.StubLlmClient;
import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.sanitize.FlowSanitizer;
import org.owasplab.coach.spec.CoachSpec;
import org.owasplab.coach.spec.CoachSpecRegistry;
import org.owasplab.coach.store.FlowStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.*;
import java.util.UUID;


@RestController
public class CoachController {

    private final FlowStore flowStore;
    private final CoachSpecRegistry specRegistry;
    private final CoachAnswerService answerService;
    private final CoachLlmProperties llmProps;
    private final DashscopeOpenAiCompatibleClient dashscopeClient;
    private final StubLlmClient stubClient;
    private final FlowSanitizer sanitizer;
    private final ObjectMapper objectMapper;

    public CoachController(
            FlowStore flowStore,
            CoachSpecRegistry specRegistry,
            CoachAnswerService answerService,
            CoachLlmProperties llmProps,
            DashscopeOpenAiCompatibleClient dashscopeClient,
            StubLlmClient stubClient,
            FlowSanitizer sanitizer,
            ObjectMapper objectMapper
    ){
        this.flowStore =flowStore;
        this.specRegistry = specRegistry;
        this.answerService = answerService;
        this.llmProps = llmProps;
        this.dashscopeClient = dashscopeClient;
        this.stubClient = stubClient;
        this.sanitizer = sanitizer;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/api/v1/coach/recent")
    public ApiResponse<Map<String, Object>>recent(
            @RequestParam(required = false,defaultValue = "10") int limit,
            HttpServletRequest request
    ){
        String sessionKey =resolveSessionKey(request);
        List<FlowRecord> items = flowStore.recent(sessionKey, limit);

        Map<String, Object> data = new HashMap<>();
        data.put("sessionKey", sessionKey);
        data.put("items", items);

        ApiMeta meta = new ApiMeta(
                "coach",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.none,
                "CWE-000",
                "recent"
        );
        return ApiResponse.ok(data, meta);
    }

    @PostMapping("/api/v1/coach/analyze")
    public ApiResponse<Map<String, Object>> analyze(@RequestBody CoachAnalyzeRequest req, HttpServletRequest request) {
        String sessionKey = resolveSessionKey(request);

        int limit = (req == null || req.getLimit() == null) ? 5 : req.getLimit();
        if (limit <= 0) limit = 5;
        if (limit > 20) limit = 20;

        List<FlowRecord> flows = flowStore.recent(sessionKey, limit);
        FlowRecord last = flows.isEmpty() ? null : flows.get(0);
        String lastPath = last == null ? null : last.getPath();

        CoachSpec spec = null;
        String ctx = (last == null ? null : last.getMetaContext());
        if (ctx != null && !ctx.trim().isEmpty()) {
            spec = specRegistry.getByContext(ctx);
        }
        if (spec == null) {
            spec = (lastPath == null) ? null : specRegistry.matchByPath(lastPath);
        }

        Map<String, Object> analysis = new HashMap<>();
        analysis.put("prompt", req == null ? null : req.getPrompt());
        analysis.put("flowsUsed", flows.size());
        analysis.put("matchedContext", spec == null ? "unknown" : spec.getContext());
        analysis.put("title", spec == null ? null : spec.getTitle());
        analysis.put("last", buildLastSummary(last));
        analysis.put("structuredInput", answerService.buildStructuredInputJson(req == null ? null : req.getPrompt(), flows, spec));

        if (spec == null) {
            List<String> notices = new ArrayList<>();
            notices.add("未命中关卡 spec：请先访问某个已支持关卡的接口（例如 /api/v1/sqli/*/login、/api/v1/sqli/*/users/detail、/api/v1/sqli/*/users/list）后再分析。");
            analysis.put("notices", notices);
            analysis.put("nextSteps", Collections.emptyList());
            analysis.put("whySafe", Collections.emptyList());
            analysis.put("answer", answerService.buildAnswer(req == null ? null : req.getPrompt(), flows, null));
        } else {
            analysis.put("notices", nullToEmpty(spec.getNotices()));
            analysis.put("nextSteps", nullToEmpty(spec.getNextSteps()));
            analysis.put("whySafe", nullToEmpty(spec.getWhySafe()));

            analysis.put("answer", answerService.buildAnswer(req == null ? null : req.getPrompt(), flows, spec));
        }

        Map<String, Object> data = new HashMap<>();
        data.put("sessionKey", sessionKey);
        data.put("analysis", analysis);
        data.put("recent", flows);

        ApiMeta meta = new ApiMeta(
                "coach",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.none,
                "CWE-000",
                "analyze_spec"
        );
        return ApiResponse.ok(data, meta);
    }

    /**
     * 前端训练事件上报（用于 DOM XSS / srcDoc / postMessage 等“可能不产生新的后端 API 请求”的链路）。
     * - 不采集 Cookie/Authorization/密码等敏感信息
     * - 仅接收最小字段集（context/mode/target/focus/input/ts），并对 input 做强截断 + inline 脱敏
     * - 写入 FlowStore，作为一种“UI FlowRecord”，method 固定为 UI，path 固定为 /__ui__
     */
    @PostMapping("/api/v1/coach/event")
    public ApiResponse<Map<String, Object>> event(@RequestBody CoachUiEventRequest req, HttpServletRequest request) {
        String sessionKey = resolveSessionKey(request);

        String ctx = trimToEmpty(req == null ? null : req.getContext());
        if (ctx.isEmpty() || ctx.length() > 120) {
            Map<String, Object> data = new HashMap<>();
            data.put("stored", false);
            data.put("reason", "context_required");
            data.put("sessionKey", sessionKey);
            ApiMeta meta = new ApiMeta(
                    "coach",
                    Mode.NORMAL,
                    Arrays.asList("testing_dast"),
                    SignalChannel.none,
                    "CWE-000",
                    "ui_event"
            );
            return ApiResponse.ok(data, meta);
        }

        long ts = (req != null && req.getTs() != null && req.getTs() > 0) ? req.getTs() : System.currentTimeMillis();
        String mode = truncate(trimToEmpty(req == null ? null : req.getMode()), 16);
        String target = truncate(trimToEmpty(req == null ? null : req.getTarget()), 24);
        String focus = truncate(trimToEmpty(req == null ? null : req.getFocus()), 24);
        String input = truncate(req == null ? null : req.getInput(), 200);
        Integer weakLevel = (req != null && req.getWeakLevel() != null) ? req.getWeakLevel() : null;

        Map<String, Object> evt = new LinkedHashMap<>();
        evt.put("context", ctx);
        evt.put("mode", mode);
        evt.put("target", target);
        evt.put("focus", focus);
        evt.put("input", input);
        evt.put("ts", ts);
        if (weakLevel != null) evt.put("weakLevel", weakLevel);

        String reqBody = null;
        try {
            String rawJson = objectMapper.writeValueAsString(evt);
            reqBody = sanitizer == null ? rawJson : sanitizer.sanitizeBody("application/json", rawJson, 1024);
        } catch (Exception ignore) {
            // ignore
        }

        FlowRecord record = new FlowRecord(
                UUID.randomUUID().toString(),
                ts,
                sessionKey,
                "UI",
                "/__ui__",
                null,
                200,
                0L,
                ctx,
                Collections.emptyMap(),
                reqBody,
                null
        );
        flowStore.append(record);

        Map<String, Object> data = new HashMap<>();
        data.put("stored", true);
        data.put("sessionKey", sessionKey);
        data.put("id", record.getId());
        data.put("metaContext", record.getMetaContext());

        ApiMeta meta = new ApiMeta(
                "coach",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.none,
                "CWE-000",
                "ui_event"
        );
        return ApiResponse.ok(data, meta);
    }

    @GetMapping("/api/v1/coach/llm/status")
    public ApiResponse<Map<String, Object>> llmStatus() {
        Map<String, Object> data = new LinkedHashMap<>();

        String pKey = (llmProps == null) ? null : llmProps.getApiKey();
        String envCoach = System.getenv("COACH_LLM_API_KEY");
        String envDash = System.getenv("DASHSCOPE_API_KEY");

        String source = "none";
        boolean effectivePresent = false;
        if (pKey != null && !pKey.trim().isEmpty()) {
            source = "props.apiKey";
            effectivePresent = true;
        } else if (envCoach != null && !envCoach.trim().isEmpty()) {
            source = "env.COACH_LLM_API_KEY";
            effectivePresent = true;
        } else if (envDash != null && !envDash.trim().isEmpty()) {
            source = "env.DASHSCOPE_API_KEY";
            effectivePresent = true;
        }

        Map<String, Object> llm = new LinkedHashMap<>();
        llm.put("enabled", llmProps != null && llmProps.isEnabled());
        llm.put("provider", llmProps == null ? null : llmProps.getProvider());
        llm.put("baseUrl", llmProps == null ? null : llmProps.getBaseUrl());
        llm.put("model", llmProps == null ? null : llmProps.getModel());
        llm.put("temperature", llmProps == null ? null : llmProps.getTemperature());
        llm.put("maxTokens", llmProps == null ? null : llmProps.getMaxTokens());

        Map<String, Object> key = new LinkedHashMap<>();
        key.put("propsApiKeyPresent", pKey != null && !pKey.trim().isEmpty());
        key.put("envCoachPresent", envCoach != null && !envCoach.trim().isEmpty());
        key.put("envDashscopePresent", envDash != null && !envDash.trim().isEmpty());
        key.put("effectivePresent", effectivePresent);
        key.put("effectiveSource", source);
        llm.put("apiKey", key);

        data.put("llm", llm);

        ApiMeta meta = new ApiMeta(
                "coach",
                Mode.NORMAL,
                Arrays.asList("coding_sast"),
                SignalChannel.none,
                "CWE-000",
                "llm_status"
        );
        return ApiResponse.ok(data, meta);
    }

    /**
     * 连接检查（会尝试真实调用一次 LLM）。
     * - enabled=false: 不请求外部，只返回 disabled
     * - provider=dashscope: 发起极小请求验证连通性/鉴权
     * - provider=stub: 直接 ok（无外部请求）
     */
    @GetMapping("/api/v1/coach/llm/check")
    public ApiResponse<Map<String, Object>> llmCheck() {
        Map<String, Object> data = new LinkedHashMap<>();

        boolean enabled = llmProps != null && llmProps.isEnabled();
        String provider = llmProps == null ? null : llmProps.getProvider();
        String p = provider == null ? "" : provider.trim().toLowerCase(Locale.ROOT);

        Map<String, Object> llm = new LinkedHashMap<>();
        llm.put("enabled", enabled);
        llm.put("provider", provider);
        llm.put("baseUrl", llmProps == null ? null : llmProps.getBaseUrl());
        llm.put("model", llmProps == null ? null : llmProps.getModel());
        data.put("llm", llm);

        Map<String, Object> check = new LinkedHashMap<>();
        if (!enabled) {
            check.put("attempted", false);
            check.put("ok", false);
            check.put("reason", "disabled");
        } else if ("stub".equals(p) || p.isEmpty()) {
            check.put("attempted", false);
            check.put("ok", true);
            check.put("provider", "stub");
            check.put("note", "stub provider（不发起外部请求）");
        } else if ("dashscope".equals(p) || "qwen".equals(p) || "bailian".equals(p) || "aliyun".equals(p)) {
            check.put("attempted", true);
            check.putAll(dashscopeClient.ping());
        } else {
            // 未识别 provider：退回 stub（不发外部请求）
            check.put("attempted", false);
            check.put("ok", true);
            check.put("provider", "stub");
            check.put("note", "unknown provider，已回退 stub（不发起外部请求）");
        }

        data.put("check", check);

        ApiMeta meta = new ApiMeta(
                "coach",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.none,
                "CWE-000",
                "llm_check"
        );
        return ApiResponse.ok(data, meta);
    }

    private static String resolveSessionKey(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) return session.getId();

        String ip = request.getRemoteAddr();
        if (ip == null || ip.trim().isEmpty()) ip = "unknown";
        return "anon:" + ip;
    }

    private static List<String> nullToEmpty(List<String> xs) {
        return xs == null ? Collections.emptyList() : xs;
    }

    private static String trimToEmpty(String s) {
        return s == null ? "" : s.trim();
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return null;
        if (maxLen <= 0) return "";
        String t = s;
        if (t.length() <= maxLen) return t;
        return t.substring(0, maxLen);
    }

    private static String buildAnswer(CoachSpec spec) {
        StringBuilder sb = new StringBuilder();
        sb.append("关卡：").append(spec.getContext()).append(" · ").append(spec.getTitle()).append("\n");
        if (spec.getGoal() != null && !spec.getGoal().trim().isEmpty()) {
            sb.append("目标：").append(spec.getGoal()).append("\n");
        }
        sb.append("\n注意事项：\n");
        for (String x : nullToEmpty(spec.getNotices())) sb.append("- ").append(x).append("\n");
        sb.append("\n下一步：\n");
        for (String x : nullToEmpty(spec.getNextSteps())) sb.append("- ").append(x).append("\n");
        sb.append("\n为什么 SAFE 挡住：\n");
        for (String x : nullToEmpty(spec.getWhySafe())) sb.append("- ").append(x).append("\n");
        return sb.toString();
    }

    private static Map<String, Object> buildLastSummary(FlowRecord last) {
        if (last == null) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("method", last.getMethod());
        m.put("path", last.getPath());
        m.put("query", last.getQuery());
        m.put("status", last.getStatus());
        m.put("durationMs", last.getDurationMs());
        m.put("metaContext", last.getMetaContext());
        return m;
    }
}