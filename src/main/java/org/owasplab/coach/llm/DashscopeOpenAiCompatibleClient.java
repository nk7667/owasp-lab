package org.owasplab.coach.llm;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.spec.CoachSpec;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.*;

/**
 * DashScope/百炼 OpenAI 兼容模式：
 * baseUrl: https://dashscope.aliyuncs.com/compatible-mode/v1
 * endpoint: POST {baseUrl}/chat/completions
 *
 * 参考（第三方汇总，含官方链接入口）：
 * https://docs.litellm.ai/docs/providers/dashscope
 */
@Service
public class DashscopeOpenAiCompatibleClient implements LlmClient {
    private final CoachLlmProperties props;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final CoachStructuredInputBuilder structuredInputBuilder;

    public DashscopeOpenAiCompatibleClient(
            CoachLlmProperties props,
            RestTemplateBuilder restTemplateBuilder,
            ObjectMapper objectMapper,
            CoachStructuredInputBuilder structuredInputBuilder
    ) {
        this.props = props;
        this.objectMapper = objectMapper;
        this.structuredInputBuilder = structuredInputBuilder;
        this.restTemplate = restTemplateBuilder
                .setConnectTimeout(Duration.ofSeconds(10))
                .setReadTimeout(Duration.ofSeconds(30))
                .build();
    }

    @Override
    public String analyze(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        String apiKey = props == null ? null : props.getApiKey();
        if (apiKey == null || apiKey.trim().isEmpty()) {
            // 兼容：用户可能习惯用 DASHSCOPE_API_KEY
            apiKey = getenvFirstNonEmpty("COACH_LLM_API_KEY", "DASHSCOPE_API_KEY");
        }
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new IllegalStateException("coach.llm.apiKey 未配置（建议用环境变量 COACH_LLM_API_KEY 或 DASHSCOPE_API_KEY 注入）");
        }

        String baseUrl = props.getBaseUrl();
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            baseUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1";
        }
        String url = baseUrl.endsWith("/") ? baseUrl + "chat/completions" : baseUrl + "/chat/completions";

        String model = props.getModel();
        if (model == null || model.trim().isEmpty()) model = "qwen-plus";

        String structured = structuredInputBuilder.build(prompt, flows, spec);

        String system = ""
                + "你是 OWASP 漏洞靶场的 AI Coach。\\n"
                + "只使用输入里的信息（流量/响应已脱敏），不要猜测服务端源码或不存在的组件（如 WAF/网关），除非输入明确出现。\\n"
                + "输出风格：以“渗透验证/复现”为主，聚焦 VULN 侧的可观测信号（success/message/meta/debug/响应体），避免把回答写成“VULN vs SAFE 对比报告”。\\n"
                + "为什么 SAFE 挡住：必须基于 spec.whySafe（安全控制点）解释，不要用“可能是 WAF”之类的猜测。\\n"
                + "输出格式必须严格如下（标题单独一行，标题前不要加 '-'）：\\n"
                + "注意事项：\\n"
                + "- ...\\n"
                + "下一步：\\n"
                + "- ...\\n"
                + "为什么 SAFE 挡住：\\n"
                + "- ...\\n";

        String user = ""
                + "这是最近 N 条请求与响应的结构化数据（JSON，已脱敏，含 spec 摘要）：\\n"
                + structured
                + "\\n\\n"
                + "要求：\\n"
                + "1) 结合 flows[*].reqBody/respBody，判断这次请求是否真的“成功/失败”，不要凭空假设。\\n"
                + "2) 只围绕 spec.notices/spec.nextSteps/spec.whySafe 给出贴近当前操作的建议；不要输出 origin/referer 之类无关浏览器头分析。\\n"
                + "3) 下一步优先给出“继续渗透/验证”的动作（payload 变体、成功信号、失败信号、如何确认认证态），SAFE/锁定/审计只作为必要补充。\\n";

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("model", model);
        payload.put("messages", Arrays.asList(
                msg("system", system),
                msg("user", user)
        ));
        if (props.getTemperature() != null) payload.put("temperature", props.getTemperature());
        if (props.getMaxTokens() != null) payload.put("max_tokens", props.getMaxTokens());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey.trim());

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(payload, headers);

        ResponseEntity<String> resp = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
        if (!resp.getStatusCode().is2xxSuccessful()) {
            throw new IllegalStateException("LLM 调用失败，HTTP " + resp.getStatusCodeValue());
        }
        String body = resp.getBody();
        if (body == null || body.trim().isEmpty()) {
            throw new IllegalStateException("LLM 返回空响应");
        }

        try {
            JsonNode root = objectMapper.readTree(body);
            // OpenAI-compatible: choices[0].message.content
            JsonNode content = root.path("choices").path(0).path("message").path("content");
            if (content.isMissingNode() || content.isNull()) {
                // 兼容某些实现：choices[0].delta.content（流式）不会出现在非流式响应；这里只兜底 error.message
                JsonNode err = root.path("error").path("message");
                if (!err.isMissingNode() && !err.isNull()) {
                    throw new IllegalStateException("LLM 错误: " + err.asText());
                }
                throw new IllegalStateException("LLM 响应缺少 choices[0].message.content");
            }
            return content.asText();
        } catch (Exception e) {
            throw new IllegalStateException("解析 LLM 响应失败: " + safeMsg(e.getMessage()));
        }
    }

    /**
     * 连接检查：发起一次极小的 chat/completions 调用，用于验证：
     * - apiKey 是否有效
     * - baseUrl 是否可达
     * - 模型是否可用
     *
     * 注意：该方法会产生一次真实的外部请求（可能计费），仅用于“手动点击检查”。
     */
    public Map<String, Object> ping() {
        long t0 = System.currentTimeMillis();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("provider", "dashscope");

        try {
            String apiKey = props == null ? null : props.getApiKey();
            if (apiKey == null || apiKey.trim().isEmpty()) {
                apiKey = getenvFirstNonEmpty("COACH_LLM_API_KEY", "DASHSCOPE_API_KEY");
            }
            if (apiKey == null || apiKey.trim().isEmpty()) {
                throw new IllegalStateException("coach.llm.apiKey 未配置（建议用环境变量 COACH_LLM_API_KEY 或 DASHSCOPE_API_KEY 注入）");
            }

            String baseUrl = (props == null) ? null : props.getBaseUrl();
            if (baseUrl == null || baseUrl.trim().isEmpty()) {
                baseUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1";
            }
            String url = baseUrl.endsWith("/") ? baseUrl + "chat/completions" : baseUrl + "/chat/completions";

            String model = (props == null) ? null : props.getModel();
            if (model == null || model.trim().isEmpty()) model = "qwen-plus";

            out.put("baseUrl", baseUrl);
            out.put("model", model);

            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("model", model);
            payload.put("messages", Arrays.asList(
                    msg("system", "You are a health check endpoint. Reply with 'pong'."),
                    msg("user", "ping")
            ));
            payload.put("temperature", 0.0);
            payload.put("max_tokens", 1);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(apiKey.trim());

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(payload, headers);

            ResponseEntity<String> resp = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
            if (!resp.getStatusCode().is2xxSuccessful()) {
                throw new IllegalStateException("LLM 调用失败，HTTP " + resp.getStatusCodeValue());
            }
            String body = resp.getBody();
            if (body == null || body.trim().isEmpty()) {
                throw new IllegalStateException("LLM 返回空响应");
            }

            JsonNode root = objectMapper.readTree(body);
            JsonNode content = root.path("choices").path(0).path("message").path("content");
            if (content.isMissingNode() || content.isNull()) {
                JsonNode err = root.path("error").path("message");
                if (!err.isMissingNode() && !err.isNull()) {
                    throw new IllegalStateException("LLM 错误: " + err.asText());
                }
                throw new IllegalStateException("LLM 响应缺少 choices[0].message.content");
            }

            out.put("ok", true);
            out.put("latencyMs", System.currentTimeMillis() - t0);
            // 不回显完整内容，避免污染日志/成本，只给出长度与截断样本
            String text = content.asText();
            out.put("contentLength", text == null ? 0 : text.length());
            if (text != null) {
                String sample = text.replace("\n", " ").replace("\r", " ");
                if (sample.length() > 60) sample = sample.substring(0, 60) + "...";
                out.put("sample", sample);
            }
            return out;

        } catch (Exception e) {
            out.put("ok", false);
            out.put("latencyMs", System.currentTimeMillis() - t0);
            out.put("error", safeMsg(e.getMessage()));
            return out;
        }
    }

    private static Map<String, String> msg(String role, String content) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("role", role);
        m.put("content", content);
        return m;
    }

    private static String safeMsg(String s) {
        if (s == null) return "unknown";
        s = s.replace("\n", " ").replace("\r", " ");
        if (s.length() > 240) s = s.substring(0, 240) + "...";
        return s;
    }

    private static String getenvFirstNonEmpty(String... names) {
        if (names == null) return null;
        for (String n : names) {
            if (n == null) continue;
            String v = System.getenv(n);
            if (v != null && v.trim().length() > 0) return v;
        }
        return null;
    }
}

