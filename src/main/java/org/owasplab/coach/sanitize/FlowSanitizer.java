package org.owasplab.coach.sanitize;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Pattern;

/**
 * 将采集到的 request headers/body 做白名单过滤 + 脱敏 + 截断。
 * MVP 原则：宁可少采集，也不要泄露敏感信息。
 */
@Service
public class FlowSanitizer {
    private static final String REDACTED = "<redacted>";
    private static final Pattern FLAG_PATTERN = Pattern.compile("flag\\{[^}]{0,200}\\}", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY_PATTERN = Pattern.compile("sk-[A-Za-z0-9]{10,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern BEARER_PATTERN = Pattern.compile("Bearer\\s+[^\\s]{10,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern JSESSIONID_PATTERN = Pattern.compile("JSESSIONID=[A-Za-z0-9]{8,}", Pattern.CASE_INSENSITIVE);

    private final ObjectMapper objectMapper;

    private final Set<String> headerAllowList = new HashSet<>(Arrays.asList(
            "accept",
            "content-type",
            "user-agent"
    ));

    private final Set<String> sensitiveKeys = new HashSet<>(Arrays.asList(
            "password",
            "passwd",
            "secret",
            "flag",
            "token",
            "authorization",
            "cookie",
            "jsessionid"
    ));

    public FlowSanitizer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Map<String, String> sanitizeHeaders(Map<String, String> raw) {
        if (raw == null || raw.isEmpty()) return Collections.emptyMap();

        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : raw.entrySet()) {
            if (e.getKey() == null) continue;
            String name = e.getKey();
            String lower = name.toLowerCase(Locale.ROOT);

            if (!headerAllowList.contains(lower)) continue;
            // defense-in-depth: 这两个即便误入 allowlist，也永远不回传
            if ("cookie".equals(lower) || "authorization".equals(lower)) {
                out.put(name, REDACTED);
                continue;
            }
            out.put(name, truncate(e.getValue(), 256));
        }
        return out;
    }

    public String sanitizeBody(String contentType, String body, int maxLen) {
        if (body == null) return null;
        String trimmed = body.trim();
        if (trimmed.isEmpty()) return "";

        // 只对 JSON 做结构化脱敏；其他类型直接截断（避免误处理）
        boolean isJson = contentType != null && contentType.toLowerCase(Locale.ROOT).contains("application/json");
        if (isJson) {
            try {
                JsonNode root = objectMapper.readTree(trimmed);
                JsonNode sanitized = sanitizeJson(root);
                String out = objectMapper.writeValueAsString(sanitized);
                return truncate(maskInlineSecrets(out), maxLen);
            } catch (Exception ignore) {
                // fallback to text sanitize
            }
        }

        // 文本兜底：尽量不猜测格式，只做截断
        return truncate(maskInlineSecrets(trimmed), maxLen);
    }

    private JsonNode sanitizeJson(JsonNode node) {
        if (node == null || node.isNull()) return node;
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node.deepCopy();
            Iterator<Map.Entry<String, JsonNode>> it = obj.fields();
            List<String> keys = new ArrayList<>();
            while (it.hasNext()) keys.add(it.next().getKey());
            for (String k : keys) {
                String lower = k == null ? "" : k.toLowerCase(Locale.ROOT);
                if (sensitiveKeys.contains(lower)) {
                    obj.set(k, TextNode.valueOf(REDACTED));
                } else {
                    obj.set(k, sanitizeJson(obj.get(k)));
                }
            }
            return obj;
        }
        if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node.deepCopy();
            for (int i = 0; i < arr.size(); i++) {
                arr.set(i, sanitizeJson(arr.get(i)));
            }
            return arr;
        }
        return node;
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return null;
        if (maxLen <= 0) return "";
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen) + "...(truncated)";
    }

    private static String maskInlineSecrets(String s) {
        if (s == null || s.isEmpty()) return s;
        String out = s;
        out = FLAG_PATTERN.matcher(out).replaceAll("flag{<redacted>}");
        out = API_KEY_PATTERN.matcher(out).replaceAll("sk-<redacted>");
        out = BEARER_PATTERN.matcher(out).replaceAll("Bearer <redacted>");
        out = JSESSIONID_PATTERN.matcher(out).replaceAll("JSESSIONID=<redacted>");
        return out;
    }
}

