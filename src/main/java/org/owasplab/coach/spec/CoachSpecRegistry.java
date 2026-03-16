package org.owasplab.coach.spec;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.util.*;

/**
 * 从 classpath:coach/specs/*.json 加载关卡 spec。
 * MVP 目标：可在不暴露源码的前提下，为 coach/analyze 提供稳定、可复用的“关卡知识库”。
 */
@Service
public class CoachSpecRegistry {
    private static final Logger log = LoggerFactory.getLogger(CoachSpecRegistry.class);

    private final ObjectMapper objectMapper;

    private final Map<String, CoachSpec> byContext = new LinkedHashMap<>();

    public CoachSpecRegistry(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void load() throws IOException {
        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver();
        Resource[] resources = resolver.getResources("classpath:coach/specs/*.json");

        byContext.clear();
        for (Resource r : resources) {
            CoachSpec spec = objectMapper.readValue(r.getInputStream(), CoachSpec.class);
            String ctx = (spec == null ? null : spec.getContext());
            if (ctx == null || ctx.trim().isEmpty()) {
                throw new IllegalStateException("Spec context is empty: " + r.getFilename());
            }
            if (byContext.containsKey(ctx)) {
                throw new IllegalStateException("Duplicate spec context: " + ctx + " (" + r.getFilename() + ")");
            }
            byContext.put(ctx, spec);
        }

        log.info("[coach] Loaded specs: {}", byContext.keySet());
    }

    public Collection<CoachSpec> all() {
        return Collections.unmodifiableCollection(byContext.values());
    }

    public CoachSpec getByContext(String context) {
        return byContext.get(context);
    }

    /**
     * 根据请求 path 命中 spec（用于 MVP：尚未采集 ApiResponse.meta.context 时的兜底）。
     * 命中规则：path 与 spec.routeHints 任意一条完全相等。
     */
    public CoachSpec matchByPath(String path) {
        if (path == null) return null;
        for (CoachSpec spec : byContext.values()) {
            List<String> hints = spec.getRouteHints();
            if (hints == null) continue;
            for (String h : hints) {
                if (path.equals(h)) return spec;
            }
        }
        return null;
    }
}

