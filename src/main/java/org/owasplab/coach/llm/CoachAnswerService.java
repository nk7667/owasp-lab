package org.owasplab.coach.llm;

import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.spec.CoachSpec;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * 统一生成 /coach/analyze 的 answer。
 * - enabled=false: 模板/规则模式（但会用最近流量做“你刚刚做了什么”的上下文补全）
 * - enabled=true : 走 LlmClient（当前默认 stub）
 */
@Service
public class CoachAnswerService {
    private final CoachLlmProperties props;
    private final LlmClient stubClient;
    private final DashscopeOpenAiCompatibleClient dashscopeClient;
    private final CoachStructuredInputBuilder structuredInputBuilder;

    public CoachAnswerService(
            CoachLlmProperties props,
            StubLlmClient stubClient,
            DashscopeOpenAiCompatibleClient dashscopeClient,
            CoachStructuredInputBuilder structuredInputBuilder
    ) {
        this.props = props;
        this.stubClient = stubClient;
        this.dashscopeClient = dashscopeClient;
        this.structuredInputBuilder = structuredInputBuilder;
    }

    public String buildAnswer(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        if (props != null && props.isEnabled()) {
            String p = props.getProvider();
            String provider = p == null ? "" : p.trim().toLowerCase(Locale.ROOT);
            try {
                if ("dashscope".equals(provider) || "qwen".equals(provider) || "bailian".equals(provider) || "aliyun".equals(provider)) {
                    return dashscopeClient.analyze(prompt, flows, spec);
                }
                if ("stub".equals(provider) || provider.isEmpty()) {
                    return stubClient.analyze(prompt, flows, spec);
                }
                // 未识别 provider：回退 stub
                return stubClient.analyze(prompt, flows, spec);
            } catch (Exception e) {
                // LLM 失败时回退模板模式（不抛 500），避免影响教学流程
                String fallback = buildTemplateAnswer(prompt, flows, spec);
                return fallback + "\n\n（LLM 调用失败，已回退模板模式：" + safeMsg(e.getMessage()) + "）";
            }
        }
        return buildTemplateAnswer(prompt, flows, spec);
    }

    /**
     * 把 flows 整理成固定结构输入（只包含已脱敏字段），便于后续接入真正 LLM。
     */
    public String buildStructuredInputJson(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        return structuredInputBuilder.build(prompt, flows, spec);
    }

    private String buildTemplateAnswer(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        FlowRecord last = (flows == null || flows.isEmpty()) ? null : flows.get(0);
        StringBuilder sb = new StringBuilder();

        if (prompt != null && prompt.trim().length() > 0) {
            sb.append("你的问题：").append(prompt.trim()).append("\n\n");
        }

        sb.append("你刚刚做了什么：\n");
        if (last == null) {
            sb.append("- 未采集到最近流量：请先访问一次关卡接口后再分析。\n\n");
        } else {
            sb.append("- 接口：").append(nullToDash(last.getMethod())).append(" ").append(nullToDash(last.getPath()));
            if (last.getQuery() != null && last.getQuery().trim().length() > 0) sb.append("?").append(last.getQuery());
            sb.append("\n");
            sb.append("- 状态码：").append(last.getStatus()).append("\n");
            sb.append("- 耗时：").append(last.getDurationMs()).append("ms\n\n");
        }

        if (spec == null) {
            sb.append("注意事项：\n- 未命中关卡 spec：请先访问某个已支持关卡的接口后再分析。\n");
            return sb.toString();
        }

        sb.append("关卡：").append(spec.getContext()).append(" · ").append(nullToDash(spec.getTitle())).append("\n");
        if (spec.getGoal() != null && spec.getGoal().trim().length() > 0) {
            sb.append("目标：").append(spec.getGoal()).append("\n");
        }

        sb.append("\n注意事项：\n");
        for (String x : safeList(spec.getNotices())) sb.append("- ").append(x).append("\n");
        sb.append("\n下一步：\n");
        for (String x : safeList(spec.getNextSteps())) sb.append("- ").append(x).append("\n");
        sb.append("\n为什么 SAFE 挡住：\n");
        for (String x : safeList(spec.getWhySafe())) sb.append("- ").append(x).append("\n");

        return sb.toString();
    }

    private static List<String> safeList(List<String> xs) {
        return xs == null ? Collections.emptyList() : xs;
    }

    private static String nullToDash(String s) {
        return s == null ? "-" : s;
    }

    private static String safeMsg(String s) {
        if (s == null) return "unknown";
        s = s.replace("\n", " ").replace("\r", " ");
        if (s.length() > 180) s = s.substring(0, 180) + "...";
        return s;
    }
}

