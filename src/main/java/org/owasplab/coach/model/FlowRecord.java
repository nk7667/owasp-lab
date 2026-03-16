package org.owasplab.coach.model;

import java.util.Map;

public class FlowRecord {
    private final String id;
    private final long ts;
    private final String sessionKey;
    private final String method;
    private final String path;
    private final int status;
    private final long durationMs;
    private final String query;
    private final String metaContext;
    private final Map<String, String> reqHeaders;
    private final String reqBody;
    private final String respBody;

    public FlowRecord(
            String id,
            long ts,
            String sessionKey,
            String method,
            String path,
            String query,
            int status,
            long durationMs,
            String metaContext,
            Map<String, String> reqHeaders,
            String reqBody,
            String respBody
    ) {
        this.id = id;
        this.ts = ts;
        this.sessionKey = sessionKey;
        this.method = method;
        this.path = path;
        this.query = query;
        this.status = status;
        this.durationMs = durationMs;
        this.metaContext = metaContext;
        this.reqHeaders = reqHeaders;
        this.reqBody = reqBody;
        this.respBody = respBody;
    }
    public String getId() { return id; }
    public long getTs() { return ts; }
    public String getSessionKey() { return sessionKey; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public int getStatus() { return status; }
    public long getDurationMs() { return durationMs; }
    public String getQuery() { return query; }
    public String getMetaContext() { return metaContext; }
    public Map<String, String> getReqHeaders() { return reqHeaders; }
    public String getReqBody() { return reqBody; }
    public String getRespBody() { return respBody; }
}
