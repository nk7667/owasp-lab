package org.owasplab.service;

import org.owasplab.core.Mode;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URL;
import java.util.*;

/**
 * SSRF 靶场实现：fetch / image-proxy / download 三类场景。
 *
 * - VULN：几乎不做校验，演示经典 SSRF。
 * - WEAK：只做部分、不足够的校验，方便做绕过练习。
 * - SAFE：协议 + 主机/IP 白名单/黑名单校验，演示合理防御思路。
 */
@Service
public class SsrfServiceImpl implements SsrfService {

    // 示例：允许访问的外部域名（SAFE 模式）
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
            "httpbin.org",
            "jsonplaceholder.typicode.com",
            "api.github.com"
    ));

    // 内网/本机 IP 段（用于 SAFE 黑名单）
    private static final List<String> PRIVATE_PREFIXES = Arrays.asList(
            "10.",
            "127.",
            "169.254.",
            "192.168."
    );

    @Override
    public Map<String, Object> fetchUrl(Mode mode, String url, int weakLevel) {
        Map<String, Object> out = baseResult("fetch", mode, url, weakLevel);
        try {
            ValidationResult vr = validateUrlForMode(mode, url, weakLevel);
            if (!vr.allowed) {
                out.put("success", false);
                out.put("blocked", true);
                out.put("blockedReason", vr.reason);
                return out;
            }

            HttpResponseSummary r = httpGet(url, 4000, 8000, 2048);
            out.put("success", r.success);
            out.put("statusCode", r.statusCode);
            out.put("bodyPreview", r.bodyPreview);
            out.put("error", r.error);
        } catch (Exception e) {
            out.put("success", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    @Override
    public Map<String, Object> proxyImage(Mode mode, String imageUrl, int weakLevel) {
        Map<String, Object> out = baseResult("imageProxy", mode, imageUrl, weakLevel);
        try {
            ValidationResult vr = validateUrlForMode(mode, imageUrl, weakLevel);
            if (!vr.allowed) {
                out.put("success", false);
                out.put("blocked", true);
                out.put("blockedReason", vr.reason);
                return out;
            }

            HttpURLConnection conn = open(imageUrl, 3000, 6000);
            int code = conn.getResponseCode();
            String contentType = conn.getContentType();
            int contentLength = conn.getContentLength();

            out.put("success", code == 200);
            out.put("statusCode", code);
            out.put("contentType", contentType);
            out.put("contentLength", contentLength);
        } catch (Exception e) {
            out.put("success", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    @Override
    public Map<String, Object> downloadFile(Mode mode, String fileUrl, int weakLevel) {
        Map<String, Object> out = baseResult("download", mode, fileUrl, weakLevel);
        try {
            ValidationResult vr = validateUrlForMode(mode, fileUrl, weakLevel);
            if (!vr.allowed) {
                out.put("success", false);
                out.put("blocked", true);
                out.put("blockedReason", vr.reason);
                return out;
            }

            HttpURLConnection conn = open(fileUrl, 3000, 6000);
            conn.setRequestMethod("HEAD");
            int code = conn.getResponseCode();
            String contentType = conn.getContentType();
            int contentLength = conn.getContentLength();
            String fileName = extractFileName(fileUrl);

            out.put("success", code == 200);
            out.put("statusCode", code);
            out.put("contentType", contentType);
            out.put("contentLength", contentLength);
            out.put("fileName", fileName);
        } catch (Exception e) {
            out.put("success", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    // --- 内部工具 ---

    private Map<String, Object> baseResult(String type, Mode mode, String url, int weakLevel) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        m.put("mode", mode == null ? null : mode.name());
        m.put("requestedUrl", url);
        m.put("weakLevel", weakLevel);
        return m;
    }

    private static class ValidationResult {
        final boolean allowed;
        final String reason;
        ValidationResult(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }
    }

    private ValidationResult validateUrlForMode(Mode mode, String url, int weakLevel) {
        if (mode == null) mode = Mode.VULN;
        if (mode == Mode.VULN) {
            return new ValidationResult(true, null);
        }
        if (url == null || url.trim().isEmpty()) {
            return new ValidationResult(false, "empty_url");
        }

        try {
            URI uri = URI.create(url.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return new ValidationResult(false, "invalid_url");
            }

            // WEAK：只限制协议
            if (mode == Mode.WEAK) {
                if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                    return new ValidationResult(false, "only_http_https_allowed_in_weak");
                }
                // weakLevel>1 时，额外拒绝显式 127.0.0.1
                if (weakLevel > 1 && "127.0.0.1".equals(host)) {
                    return new ValidationResult(false, "127.0.0.1_blocked_in_weak");
                }
                return new ValidationResult(true, null);
            }

            // SAFE：协议 + 主机白名单 + IP 黑名单
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return new ValidationResult(false, "only_http_https_allowed");
            }

            // 解析 IP，用于识别内网/本机
            InetAddress addr = InetAddress.getByName(host);
            String ip = addr.getHostAddress();
            if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()) {
                return new ValidationResult(false, "loopback_or_anylocal_blocked");
            }
            for (String prefix : PRIVATE_PREFIXES) {
                if (ip.startsWith(prefix)) {
                    return new ValidationResult(false, "private_ip_blocked:" + ip);
                }
            }

            if (!ALLOWED_HOSTS.contains(host)) {
                return new ValidationResult(false, "host_not_in_allowlist:" + host);
            }
            return new ValidationResult(true, null);
        } catch (Exception e) {
            return new ValidationResult(false, "url_parse_error:" + e.getMessage());
        }
    }

    private HttpURLConnection open(String url, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("User-Agent", "owasp-lab-ssrf");
        return conn;
    }

    private static class HttpResponseSummary {
        boolean success;
        int statusCode;
        String bodyPreview;
        String error;
    }

    private HttpResponseSummary httpGet(String url, int connectTimeoutMs, int readTimeoutMs, int maxBodyChars) {
        HttpResponseSummary r = new HttpResponseSummary();
        HttpURLConnection conn = null;
        try {
            conn = open(url, connectTimeoutMs, readTimeoutMs);
            int code = conn.getResponseCode();
            r.statusCode = code;
            StringBuilder sb = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            code >= 200 && code < 400 ? conn.getInputStream() : conn.getErrorStream()
                    ))) {
                String line;
                while ((line = reader.readLine()) != null && sb.length() < maxBodyChars) {
                    sb.append(line).append('\n');
                }
            } catch (Exception ignore) {
                // ignore
            }
            r.bodyPreview = sb.toString();
            r.success = (code >= 200 && code < 400);
        } catch (Exception e) {
            r.success = false;
            r.error = e.getMessage();
        } finally {
            if (conn != null) conn.disconnect();
        }
        return r;
    }

    private String extractFileName(String url) {
        try {
            String path = new URL(url).getPath();
            int idx = path.lastIndexOf('/');
            return idx >= 0 ? path.substring(idx + 1) : path;
        } catch (Exception e) {
            return "unknown";
        }
    }
}

