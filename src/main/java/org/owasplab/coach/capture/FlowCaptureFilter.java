package org.owasplab.coach.capture;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.sanitize.FlowSanitizer;
import org.owasplab.coach.store.FlowStore;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Component
public class FlowCaptureFilter extends OncePerRequestFilter{

    private final FlowStore flowStore;
    private final ObjectMapper objectMapper;
    private final FlowSanitizer sanitizer;

    public FlowCaptureFilter(FlowStore flowStore, ObjectMapper objectMapper, FlowSanitizer sanitizer){
        this.flowStore =flowStore;
        this.objectMapper = objectMapper;
        this.sanitizer = sanitizer;
    }
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null) return true;

        // 只采集 API,排除自己
        if (!uri.startsWith("/api/v1/")) return true;
        if (uri.startsWith("/api/v1/coach/")) return true;

        return false;
    }
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        long startNs =System.nanoTime();
        ContentCachingRequestWrapper wrappedReq = new ContentCachingRequestWrapper(request);
        ContentCachingResponseWrapper wrappedResp = new ContentCachingResponseWrapper(response);
        try {
            filterChain.doFilter(wrappedReq, wrappedResp);
        }finally {
            long durationMs =(System.nanoTime() -startNs) /1_000_000L;
            String method = wrappedReq.getMethod();
            String path = wrappedReq.getRequestURI();
            String query = wrappedReq.getQueryString();
            int status = wrappedResp.getStatus();
            long ts = System.currentTimeMillis();

            String sessionKey = resolveSessionKey(wrappedReq);

            // 仅提取 ApiResponse.meta.context（用于更稳定命中 spec）
            String metaContext = null;
            String respBody = null;
            try {
                byte[] body = wrappedResp.getContentAsByteArray();
                if (body != null && body.length > 0) {
                    String charset = wrappedResp.getCharacterEncoding();
                    if (charset == null || charset.trim().isEmpty()) charset = "UTF-8";
                    String text = new String(body, charset);
                    respBody = sanitizer.sanitizeBody(wrappedResp.getContentType(), text, 4096);
                    JsonNode root = objectMapper.readTree(text);
                    JsonNode meta = root.get("meta");
                    if (meta != null && !meta.isNull()) {
                        JsonNode ctx = meta.get("context");
                        if (ctx != null && !ctx.isNull()) metaContext = ctx.asText();
                    }
                }
            } catch (Exception ignore) {
                // ignore parse errors
            }

            // request headers/body（白名单 + 脱敏 + 截断）
            Map<String, String> rawHeaders = new LinkedHashMap<>();
            try {
                Enumeration<String> names = wrappedReq.getHeaderNames();
                while (names != null && names.hasMoreElements()) {
                    String n = names.nextElement();
                    rawHeaders.put(n, wrappedReq.getHeader(n));
                }
            } catch (Exception ignore) {
                // ignore
            }
            Map<String, String> reqHeaders = sanitizer.sanitizeHeaders(rawHeaders);

            String reqBody = null;
            try {
                byte[] body = wrappedReq.getContentAsByteArray();
                if (body != null && body.length > 0) {
                    String charset = wrappedReq.getCharacterEncoding();
                    if (charset == null || charset.trim().isEmpty()) charset = "UTF-8";
                    String raw = new String(body, charset);
                    reqBody = sanitizer.sanitizeBody(wrappedReq.getContentType(), raw, 4096);
                }
            } catch (Exception ignore) {
                // ignore
            }

            FlowRecord record = new FlowRecord(
                    UUID.randomUUID().toString(),
                    ts,
                    sessionKey,
                    method,
                    path,
                    query,
                    status,
                    durationMs,
                    metaContext,
                    reqHeaders,
                    reqBody,
                    respBody
            );
            flowStore.append(record);

            // VERY IMPORTANT: copy cached body back to real response
            wrappedResp.copyBodyToResponse();
        }
    }
    private static String resolveSessionKey(HttpServletRequest request){
        HttpSession session =request.getSession(false);
    if (session !=null) return session.getId();

    String ip = request.getRemoteAddr();
    if(ip ==null ||ip.trim().isEmpty()) ip ="unknown";
    return "anon:" + ip;
    }
}
