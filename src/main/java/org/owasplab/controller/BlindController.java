package org.owasplab.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.blind.BlindBeaconEvent;
import org.owasplab.blind.BlindBeaconRequest;
import org.owasplab.blind.BlindBeaconStore;
import org.owasplab.coach.sanitize.FlowSanitizer;
import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/blind")
public class BlindController {
    private final BlindBeaconStore store;
    private final ObjectMapper objectMapper;
    private final FlowSanitizer sanitizer;

    public BlindController(BlindBeaconStore store, ObjectMapper objectMapper, FlowSanitizer sanitizer) {
        this.store = store;
        this.objectMapper = objectMapper;
        this.sanitizer = sanitizer;
    }

    @PostMapping("/beacon")
    public ResponseEntity<ApiResponse<Map<String, Object>>> beacon(
            HttpServletRequest request,
            @RequestBody(required = false) BlindBeaconRequest body
    ) {
        ApiMeta meta = new ApiMeta(
                "xss",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.oob,
                "CWE-79",
                "xss_blind_beacon_oob"
        );

        long ts = body != null && body.getTs() != null ? body.getTs() : System.currentTimeMillis();
        Long profileId = body == null ? null : body.getProfileId();
        String kind = safeTrim(body == null ? null : body.getKind(), 32);
        String view = safeTrim(body == null ? null : body.getView(), 64);
        String mode = safeTrim(body == null ? null : body.getMode(), 16);

        String payload = safeTrim(body == null ? null : body.getPayload(), 800);
        // 如果 payload 为空，就尝试把整包 request JSON 压成一条（用于教学观察）
        if (payload == null || payload.isEmpty()) {
            try {
                String json = objectMapper.writeValueAsString(body);
                payload = sanitizer.sanitizeBody("application/json", json, 800);
            } catch (Exception ignore) {
                payload = "";
            }
        }

        String sessionKey = null;
        try {
            sessionKey = request.getSession(true).getId();
        } catch (Exception ignore) {
            sessionKey = "no-session";
        }

        BlindBeaconEvent ev = new BlindBeaconEvent(
                UUID.randomUUID().toString(),
                ts,
                sessionKey,
                profileId,
                kind == null || kind.isEmpty() ? "beacon" : kind,
                view == null || view.isEmpty() ? "unknown" : view,
                mode == null ? "" : mode,
                payload == null ? "" : payload
        );
        store.append(ev);

        Map<String, Object> data = new HashMap<>();
        data.put("saved", true);
        data.put("event", ev);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @GetMapping("/recent")
    public ResponseEntity<ApiResponse<Map<String, Object>>> recent(
            @RequestParam(required = false) Long profileId,
            @RequestParam(required = false, defaultValue = "20") int limit
    ) {
        ApiMeta meta = new ApiMeta(
                "xss",
                Mode.NORMAL,
                Arrays.asList("testing_dast"),
                SignalChannel.oob,
                "CWE-79",
                "xss_blind_recent_oob"
        );

        List<BlindBeaconEvent> items = store.recent(profileId, limit);
        Map<String, Object> data = new HashMap<>();
        data.put("items", items);
        data.put("count", items == null ? 0 : items.size());
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    private static String safeTrim(String s, int maxLen) {
        if (s == null) return "";
        String t = s.trim();
        if (t.length() <= maxLen) return t;
        return t.substring(0, Math.max(0, maxLen));
    }
}

