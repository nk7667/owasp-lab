package org.owasplab.coach.llm;

import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.spec.CoachSpec;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 默认 stub：不调用外部模型，使用固定模板 + 简单启发式，把“最近一次操作”说清楚。
 */
@Service
public class StubLlmClient implements LlmClient {

    @Override
    public String analyze(String prompt, List<FlowRecord> flows, CoachSpec spec) {
        FlowRecord last = (flows == null || flows.isEmpty()) ? null : flows.get(0);

        StringBuilder sb = new StringBuilder();
        sb.append("AI Coach（stub）\n");

        if (prompt != null && prompt.trim().length() > 0) {
            sb.append("你的问题：").append(prompt.trim()).append("\n\n");
        }

        sb.append("你刚刚做了什么：\n");
        if (last == null) {
            sb.append("- 未采集到最近流量：请先访问一次关卡接口后再点击分析。\n\n");
        } else {
            sb.append("- 接口：").append(nullToDash(last.getMethod())).append(" ").append(nullToDash(last.getPath()));
            if (last.getQuery() != null && last.getQuery().trim().length() > 0) {
                sb.append("?").append(last.getQuery());
            }
            sb.append("\n");
            sb.append("- 状态码：").append(last.getStatus()).append("\n");
            sb.append("- 耗时：").append(last.getDurationMs()).append("ms\n");
            if (last.getMetaContext() != null && last.getMetaContext().trim().length() > 0) {
                sb.append("- metaContext：").append(last.getMetaContext()).append("\n");
            }
            sb.append("\n");
        }

        if (spec == null) {
            sb.append("命中关卡：unknown\n");
            sb.append("\n注意事项：\n- 未命中关卡 spec：请先访问已支持关卡接口，再分析。\n");
            return sb.toString();
        }

        sb.append("命中关卡：").append(spec.getContext()).append(" · ").append(nullToDash(spec.getTitle())).append("\n\n");

        // 结合 reqBody/query 的简单提示：说明“payload 影响点”
        String payloadHint = guessPayloadImpact(last);
        if (payloadHint != null) {
            sb.append("你现在的 payload 可能影响哪里：\n");
            sb.append("- ").append(payloadHint).append("\n\n");
        }

        sb.append("注意事项：\n");
        for (String x : safeList(spec.getNotices())) sb.append("- ").append(x).append("\n");
        sb.append("\n下一步：\n");
        for (String x : safeList(spec.getNextSteps())) sb.append("- ").append(x).append("\n");
        sb.append("\n为什么 SAFE 挡住：\n");
        for (String x : safeList(spec.getWhySafe())) sb.append("- ").append(x).append("\n");

        // 证据：仅展示已脱敏的头/body（短一点）
        if (last != null) {
            sb.append("\n证据（已脱敏）：\n");
            Map<String, String> headers = last.getReqHeaders();
            if (headers != null && !headers.isEmpty()) {
                sb.append("- reqHeaders: ").append(headers).append("\n");
            }
            if (last.getReqBody() != null && last.getReqBody().trim().length() > 0) {
                String body = last.getReqBody();
                if (body.length() > 240) body = body.substring(0, 240) + "...(truncated)";
                sb.append("- reqBody: ").append(body.replace("\n", " ")).append("\n");
            }
        }

        return sb.toString();
    }

    private static String guessPayloadImpact(FlowRecord last) {
        if (last == null) return null;
        String q = last.getQuery();
        String b = last.getReqBody();
        String merged = (q == null ? "" : q) + "\n" + (b == null ? "" : b);
        String s = merged.toLowerCase(Locale.ROOT);

        if (s.contains("'") && (s.contains(" or ") || s.contains("or%") || s.contains("1=1"))) {
            return "你输入的条件看起来在尝试把 WHERE 改成恒真（例如 1=1），从而影响认证或越权查询。";
        }
        if (s.contains("--") || s.contains("/*") || s.contains("%2d%2d")) {
            return "你在尝试用注释截断后续 SQL 条件（例如把密码校验截掉），重点观察响应里的 debug/sqlTemplate 或是否出现语法错误。";
        }
        if (s.contains("order") || s.contains("asc") || s.contains("desc")) {
            return "你的输入可能在影响 ORDER BY 的排序字段/方向，重点观察是否能通过字段注入改变排序或构造错误回显。";
        }
        if (s.contains("id=") || s.contains("union") || s.contains("select")) {
            return "你的输入可能在影响 ID 查询的条件或尝试 UNION 拼接，重点观察是否返回了非授权用户数据。";
        }
        return null;
    }

    private static List<String> safeList(List<String> xs) {
        return xs == null ? Collections.emptyList() : xs;
    }

    private static String nullToDash(String s) {
        return s == null ? "-" : s;
    }
}

