package org.owasplab.service;

import org.owasplab.core.Mode;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.IDN;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;

/**
 * SSRF 靶场实现：fetch / image-proxy / download 三类场景。
 *
 * - VULN：几乎不做校验，演示经典 SSRF。
 * - WEAK：只做部分、不足够的校验，方便做绕过练习。
 * - SAFE：协议 + 主机/IP 白名单/黑名单校验，演示合理防御思路。
 */
@Service
public class SsrfServiceImpl implements SsrfService {
    private static final int SAFE_MAX_URL_LEN = 2048;
    private static final Set<Integer> SAFE_ALLOWED_PORTS = new HashSet<>(Arrays.asList(80, 443));
    private static final int SAFE_MAX_DNS_RESULTS = 16;

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

            HttpResponseSummary r = httpGetPinned(mode, url, vr, 4000, 8000, 2048);
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

            HttpURLConnection conn = openPinned(mode, imageUrl, vr, 3000, 6000);
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

            HttpURLConnection conn = openPinned(mode, fileUrl, vr, 3000, 6000);
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
        final PinnedTarget pinned;
        ValidationResult(boolean allowed, String reason, PinnedTarget pinned) {
            this.allowed = allowed;
            this.reason = reason;
            this.pinned = pinned;
        }

        static ValidationResult allow() {
            return new ValidationResult(true, null, null);
        }

        static ValidationResult allowWithPinned(PinnedTarget pinned) {
            return new ValidationResult(true, null, pinned);
        }

        static ValidationResult deny(String reason) {
            return new ValidationResult(false, reason, null);
        }
    }

    private ValidationResult validateUrlForMode(Mode mode, String url, int weakLevel) {
        if (mode == null) mode = Mode.VULN;
        if (mode == Mode.VULN) {
            return ValidationResult.allow();
        }
        if (url == null || url.trim().isEmpty()) {
            return ValidationResult.deny("empty_url");
        }
        if (url.length() > SAFE_MAX_URL_LEN) {
            return ValidationResult.deny("url_too_long");
        }

        try {
            URI uri = URI.create(url.trim()).normalize();
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return ValidationResult.deny("invalid_url");
            }
            // 防御纵深：禁止在 authority 内使用百分号编码（避免 %40/%2f 等把结构隐藏在编码里）
            // 说明：不要对整个 URL 做 URLDecoder.decode，这会改变 URI 结构分隔符，反而引入歧义。
            String rawAuthority = uri.getRawAuthority();
            if (rawAuthority != null && rawAuthority.contains("%")) {
                return ValidationResult.deny("encoded_authority_not_allowed");
            }
            if (uri.getUserInfo() != null) {
                return ValidationResult.deny("userinfo_not_allowed");
            }
            if (uri.getFragment() != null) {
                return ValidationResult.deny("fragment_not_allowed");
            }

            // WEAK：只限制协议
            if (mode == Mode.WEAK) {
                int lvl = weakLevel;
                if (lvl < 1 || lvl > 5) lvl = 1;
                String lowerHost = host.toLowerCase(Locale.ROOT);
                String raw = url.trim().toLowerCase(Locale.ROOT);

                switch (lvl) {
                    case 1:
                        // WEAK-1：仅字符串拦截 localhost / 127.0.0.1
                        if ("localhost".equals(lowerHost) || "127.0.0.1".equals(lowerHost)) {
                            return ValidationResult.deny("weak1_localhost_or_127001_blocked");
                        }
                        return ValidationResult.allow();

                    case 2:
                        // WEAK-2：在 WEAK-1 基础上，解析一次 IP 并做内网前缀黑名单（无 pinning）
                        if ("localhost".equals(lowerHost) || "127.0.0.1".equals(lowerHost)) {
                            return ValidationResult.deny("weak2_localhost_or_127001_blocked");
                        }
                        try {
                            InetAddress resolved = InetAddress.getByName(lowerHost);
                            String ip = resolved.getHostAddress();
                            if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.")
                                    || ip.startsWith("169.254.")) {
                                return ValidationResult.deny("weak2_private_ip_blocked:" + ip);
                            }
                            if (ip.startsWith("172.")) {
                                String[] parts = ip.split("\\.");
                                if (parts.length >= 2) {
                                    int second = Integer.parseInt(parts[1]);
                                    if (second >= 16 && second <= 31) {
                                        return ValidationResult.deny("weak2_private_ip_blocked:" + ip);
                                    }
                                }
                            }
                        } catch (Exception e) {
                            return ValidationResult.deny("weak2_dns_or_parse_error:" + e.getMessage());
                        }
                        return ValidationResult.allow();

                    case 3:
                        // WEAK-3：仅允许 http/https（不做主机/IP限制）
                        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                            return ValidationResult.deny("weak3_only_http_https_allowed");
                        }
                        return ValidationResult.allow();

                    case 4:
                        // WEAK-4：组合字符串过滤 + 协议限制（仍可被编码/非常规写法绕过）
                        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                            return ValidationResult.deny("weak4_only_http_https_allowed");
                        }
                        if (raw.contains("localhost") || raw.contains("127.0.0.1") || raw.contains("[::1]")) {
                            return ValidationResult.deny("weak4_keyword_blocked");
                        }
                        return ValidationResult.allow();

                    case 5:
                        // WEAK-5：更严格黑名单（仍不做 SAFE 的全量解析/编码结构约束/pinning）
                        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                            return ValidationResult.deny("weak5_only_http_https_allowed");
                        }
                        if ("localhost".equals(lowerHost) || lowerHost.endsWith(".localhost")) {
                            return ValidationResult.deny("weak5_localhost_blocked");
                        }
                        try {
                            InetAddress resolved = InetAddress.getByName(lowerHost);
                            String reason = blockedIpReason(resolved);
                            if (reason != null) {
                                return ValidationResult.deny("weak5_" + reason + ":" + resolved.getHostAddress());
                            }
                        } catch (Exception e) {
                            return ValidationResult.deny("weak5_dns_or_parse_error:" + e.getMessage());
                        }
                        return ValidationResult.allow();

                    default:
                        return ValidationResult.allow();
                }
            }

            // SAFE：不依赖域名白名单；以“协议白名单 + 端口限制 + 解析后 IP 全量校验”为核心
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return ValidationResult.deny("only_http_https_allowed");
            }

            int port = uri.getPort();
            if (port == -1) {
                port = "https".equalsIgnoreCase(scheme) ? 443 : 80;
            }
            if (!SAFE_ALLOWED_PORTS.contains(port)) {
                return ValidationResult.deny("port_not_allowed:" + port);
            }

            String asciiHost;
            try {
                asciiHost = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
            } catch (Exception e) {
                return ValidationResult.deny("invalid_host");
            }
            if ("localhost".equals(asciiHost) || asciiHost.endsWith(".localhost")) {
                return ValidationResult.deny("localhost_blocked");
            }

            // SAFE：在校验阶段完成 DNS pinning，后续请求复用 pinned 结果，避免二次解析窗口
            return validateAndPinSafe(uri, scheme, asciiHost);
        } catch (Exception e) {
            return ValidationResult.deny("url_parse_error:" + e.getMessage());
        }
    }

    private ValidationResult validateAndPinSafe(URI uri, String scheme, String asciiHost) throws Exception {
        InetAddress[] addrs = InetAddress.getAllByName(asciiHost);
        if (addrs == null || addrs.length == 0) {
            return ValidationResult.deny("dns_empty");
        }
        if (addrs.length > SAFE_MAX_DNS_RESULTS) {
            return ValidationResult.deny("too_many_dns_records:" + addrs.length);
        }
        for (InetAddress addr : addrs) {
            String ip = addr.getHostAddress();
            String reason = blockedIpReason(addr);
            if (reason != null) {
                return ValidationResult.deny(reason + ":" + ip);
            }
        }

        // 选择一个通过校验的 IP 作为 pin 目标（由于上面已确保全量安全，这里取第一个即可）
        InetAddress chosen = addrs[0];
        int port = uri.getPort();
        if (port == -1) port = "https".equalsIgnoreCase(scheme) ? 443 : 80;

        String ipLiteral = chosen.getHostAddress();
        if (ipLiteral.contains(":") && !ipLiteral.startsWith("[")) {
            ipLiteral = "[" + ipLiteral + "]";
        }

        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = uri.getRawQuery();
        String file = query == null ? path : path + "?" + query;

        URL connectUrl = new URL(scheme, ipLiteral, port, file);
        return ValidationResult.allowWithPinned(new PinnedTarget(connectUrl, asciiHost, chosen));
    }

    private String blockedIpReason(InetAddress addr) {
        if (addr == null) return "ip_invalid";
        if (addr.isAnyLocalAddress()) return "anylocal_blocked";
        if (addr.isLoopbackAddress()) return "loopback_blocked";
        if (addr.isLinkLocalAddress()) return "linklocal_blocked";
        if (addr.isMulticastAddress()) return "multicast_blocked";
        if (addr.isSiteLocalAddress()) return "sitelocal_blocked"; // e.g. 10/172.16-31/192.168, fc00::/7 (impl-dependent)

        byte[] b = addr.getAddress();
        if (b == null) return "ip_invalid";

        // IPv4-mapped IPv6 (::ffff:w.x.y.z) / IPv4-compatible (::w.x.y.z) safety: treat the mapped v4 as v4 and re-apply v4 blocks.
        if (b.length == 16) {
            boolean v4Compat = true;
            for (int i = 0; i < 12; i++) {
                if (b[i] != 0) { v4Compat = false; break; }
            }
            boolean v4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (b[i] != 0) { v4Mapped = false; break; }
            }
            v4Mapped = v4Mapped && (b[10] == (byte) 0xff) && (b[11] == (byte) 0xff);

            if (v4Mapped || v4Compat) {
                byte[] v4 = new byte[] { b[12], b[13], b[14], b[15] };
                String r = blockedV4BytesReason(v4);
                if (r != null) return r;
            }
        }

        // IPv4 extra ranges that are commonly unsafe or non-routable
        if (b.length == 4) {
            String r = blockedV4BytesReason(b);
            if (r != null) return r;
        }

        // IPv6: block ULA fc00::/7 and link-local fe80::/10 (link-local handled above, but keep explicit)
        if (b.length == 16) {
            int b0 = b[0] & 0xff;
            int b1 = b[1] & 0xff;
            if ((b0 & 0xfe) == 0xfc) return "ula_v6_blocked"; // fc00::/7
            if (b0 == 0xfe && (b1 & 0xc0) == 0x80) return "linklocal_blocked"; // fe80::/10
        }

        return null;
    }

    private String blockedV4BytesReason(byte[] b) {
        if (b == null || b.length != 4) return "ip_invalid";
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        int b2 = b[2] & 0xff;
        int b3 = b[3] & 0xff;

        // 0.0.0.0/8
        if (b0 == 0) return "reserved_v4_blocked";
        // 127.0.0.0/8
        if (b0 == 127) return "loopback_blocked";
        // 10.0.0.0/8
        if (b0 == 10) return "sitelocal_blocked";
        // 172.16.0.0/12
        if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return "sitelocal_blocked";
        // 192.168.0.0/16
        if (b0 == 192 && b1 == 168) return "sitelocal_blocked";
        // 169.254.0.0/16 (link-local)
        if (b0 == 169 && b1 == 254) return "linklocal_blocked";
        // 100.64.0.0/10 (CGNAT)
        if (b0 == 100 && (b1 >= 64 && b1 <= 127)) return "cgnat_v4_blocked";
        // 198.18.0.0/15 (benchmarking)
        if (b0 == 198 && (b1 == 18 || b1 == 19)) return "benchmark_v4_blocked";
        // 255.255.255.255 (limited broadcast)
        if (b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255) return "broadcast_blocked";
        // 224.0.0.0/4 (multicast) handled above, but keep explicit
        if (b0 >= 224) return "multicast_or_reserved_v4_blocked";
        return null;
    }

    private static class PinnedTarget {
        final URL connectUrl;         // URL host is pinned IP literal
        final String originalHost;    // normalized hostname for Host/SNI
        final InetAddress pinnedIp;   // chosen IP

        private PinnedTarget(URL connectUrl, String originalHost, InetAddress pinnedIp) {
            this.connectUrl = connectUrl;
            this.originalHost = originalHost;
            this.pinnedIp = pinnedIp;
        }
    }

    private HttpURLConnection openPinned(Mode mode, String url, ValidationResult vr, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        if (mode != Mode.SAFE) {
            return openDirect(url, connectTimeoutMs, readTimeoutMs);
        }

        PinnedTarget t = (vr != null ? vr.pinned : null);
        if (t == null) {
            // defensive: should have been pinned during validateUrlForMode
            URI uri = URI.create(url.trim());
            String scheme = uri.getScheme();
            String host = uri.getHost();
            String asciiHost = IDN.toASCII(host, IDN.ALLOW_UNASSIGNED).toLowerCase(Locale.ROOT);
            ValidationResult pinnedVr = validateAndPinSafe(uri, scheme, asciiHost);
            if (!pinnedVr.allowed || pinnedVr.pinned == null) throw new IllegalArgumentException(pinnedVr.reason);
            t = pinnedVr.pinned;
        }
        HttpURLConnection conn = (HttpURLConnection) t.connectUrl.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        // IMPORTANT: do NOT follow redirects here. If redirect support is added later,
        // each Location hop must be re-validated (including DNS pinning) before connecting.
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("User-Agent", "owasp-lab-ssrf");
        conn.setRequestProperty("Host", t.originalHost);

        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            final String tlsHost = t.originalHost;
            https.setSSLSocketFactory(new SniSslSocketFactory(HttpsURLConnection.getDefaultSSLSocketFactory(), tlsHost));
            https.setHostnameVerifier((ignored, session) ->
                    HttpsURLConnection.getDefaultHostnameVerifier().verify(tlsHost, session));
        }

        return conn;
    }

    private HttpURLConnection openDirect(String url, int connectTimeoutMs, int readTimeoutMs) throws Exception {
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(connectTimeoutMs);
        conn.setReadTimeout(readTimeoutMs);
        conn.setInstanceFollowRedirects(false);
        conn.setRequestProperty("User-Agent", "owasp-lab-ssrf");
        return conn;
    }

    private static class SniSslSocketFactory extends SSLSocketFactory {
        private final SSLSocketFactory delegate;
        private final String sniHost;

        private SniSslSocketFactory(SSLSocketFactory delegate, String sniHost) {
            this.delegate = delegate;
            this.sniHost = sniHost;
        }

        private SSLSocket withSni(SSLSocket s) {
            SSLParameters p = s.getSSLParameters();
            p.setEndpointIdentificationAlgorithm("HTTPS");
            List<SNIServerName> names = Collections.singletonList(new SNIHostName(sniHost));
            p.setServerNames(names);
            s.setSSLParameters(p);
            return s;
        }

        @Override public String[] getDefaultCipherSuites() { return delegate.getDefaultCipherSuites(); }
        @Override public String[] getSupportedCipherSuites() { return delegate.getSupportedCipherSuites(); }

        @Override
        public java.net.Socket createSocket(java.net.Socket s, String host, int port, boolean autoClose) throws java.io.IOException {
            return withSni((SSLSocket) delegate.createSocket(s, host, port, autoClose));
        }

        @Override
        public java.net.Socket createSocket(String host, int port) throws java.io.IOException {
            return withSni((SSLSocket) delegate.createSocket(host, port));
        }

        @Override
        public java.net.Socket createSocket(String host, int port, java.net.InetAddress localHost, int localPort) throws java.io.IOException {
            return withSni((SSLSocket) delegate.createSocket(host, port, localHost, localPort));
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress host, int port) throws java.io.IOException {
            return withSni((SSLSocket) delegate.createSocket(host, port));
        }

        @Override
        public java.net.Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddress, int localPort) throws java.io.IOException {
            return withSni((SSLSocket) delegate.createSocket(address, port, localAddress, localPort));
        }
    }

    private static class HttpResponseSummary {
        boolean success;
        int statusCode;
        String bodyPreview;
        String error;
    }

    private HttpResponseSummary httpGetPinned(Mode mode, String url, ValidationResult vr, int connectTimeoutMs, int readTimeoutMs, int maxBodyChars) {
        HttpResponseSummary r = new HttpResponseSummary();
        HttpURLConnection conn = null;
        try {
            conn = openPinned(mode, url, vr, connectTimeoutMs, readTimeoutMs);
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
            String rawName = idx >= 0 ? path.substring(idx + 1) : path;
            // 仅用于回显，但仍做纵深防御：避免未来被用于落盘时产生路径/特殊字符问题
            String decoded;
            try {
                decoded = java.net.URLDecoder.decode(rawName, StandardCharsets.UTF_8.name());
            } catch (Exception ignore) {
                decoded = rawName;
            }
            String safeName = decoded.replaceAll("[^a-zA-Z0-9._-]", "_");
            if (safeName.isEmpty()) return "unnamed";
            if (safeName.length() > 120) safeName = safeName.substring(0, 120);
            return safeName;
        } catch (Exception e) {
            return "unknown";
        }
    }
}

