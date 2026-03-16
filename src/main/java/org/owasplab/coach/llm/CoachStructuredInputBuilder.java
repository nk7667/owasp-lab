package org.owasplab.coach.llm;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.spec.CoachSpec;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 将（已脱敏的）flows + spec 摘要整理成固定 JSON 输入，供 LLM 使用。
 * 原则：只提供“教学需要的信号”，避免模型自行脑补 WAF/网关等不存在的组件。
 */
@Service
public class CoachStructuredInputBuilder {
    private final ObjectMapper objectMapper;

    public CoachStructuredInputBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String build(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        Map<String, Object> root = new LinkedHashMap<>();
        root.put("prompt", prompt);

        Map<String, Object> specPart = new LinkedHashMap<>();
        specPart.put("matchedContext", spec == null ? "unknown" : spec.getContext());
        specPart.put("title", spec == null ? null : spec.getTitle());
        specPart.put("goal", spec == null ? null : spec.getGoal());
        specPart.put("signals", spec == null ? Collections.emptyList() : nullToEmpty(spec.getSignals()));
        specPart.put("routeHints", spec == null ? Collections.emptyList() : nullToEmpty(spec.getRouteHints()));

        // 教学约束：模型要优先用 spec 提供的观测点/安全控制点，而不是自己脑补
        specPart.put("notices", spec == null ? Collections.emptyList() : nullToEmpty(spec.getNotices()));
        specPart.put("nextSteps", spec == null ? Collections.emptyList() : nullToEmpty(spec.getNextSteps()));
        specPart.put("whySafe", spec == null ? Collections.emptyList() : nullToEmpty(spec.getWhySafe()));
        specPart.put("allowedToTell", spec == null ? Collections.emptyList() : nullToEmpty(spec.getAllowedToTell()));
        specPart.put("acceptanceCriteria", spec == null ? Collections.emptyList() : nullToEmpty(spec.getAcceptanceCriteria()));
        specPart.put("doNotTell", spec == null ? Collections.emptyList() : nullToEmpty(spec.getDoNotTell()));

        if (spec != null && spec.getVuln() != null) {
            Map<String, Object> vuln = new LinkedHashMap<>();
            vuln.put("summary", spec.getVuln().getSummary());
            vuln.put("impact", nullToEmpty(spec.getVuln().getImpact()));
            vuln.put("whatToObserve", nullToEmpty(spec.getVuln().getWhatToObserve()));
            specPart.put("vuln", vuln);
        } else {
            specPart.put("vuln", null);
        }

        if (spec != null && spec.getSafe() != null) {
            Map<String, Object> safe = new LinkedHashMap<>();
            safe.put("summary", spec.getSafe().getSummary());
            safe.put("keyControls", nullToEmpty(spec.getSafe().getKeyControls()));
            specPart.put("safe", safe);
        } else {
            specPart.put("safe", null);
        }
        root.put("spec", specPart);

        List<Map<String, Object>> items = new ArrayList<>();
        if (flows != null) {
            for (FlowRecord f : flows) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("ts", f.getTs());
                m.put("method", f.getMethod());
                m.put("path", f.getPath());
                m.put("query", f.getQuery());
                m.put("status", f.getStatus());
                m.put("durationMs", f.getDurationMs());
                m.put("metaContext", f.getMetaContext());
                m.put("reqHeaders", f.getReqHeaders());
                m.put("reqBody", f.getReqBody());
                m.put("respBody", f.getRespBody());
                items.add(m);
            }
        }
        root.put("flows", items);

        try {
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return String.valueOf(root);
        }
    }

    private static List<String> nullToEmpty(List<String> xs) {
        return xs == null ? Collections.emptyList() : xs;
    }
}

