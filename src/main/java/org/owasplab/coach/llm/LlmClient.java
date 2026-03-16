package org.owasplab.coach.llm;

import org.owasplab.coach.model.FlowRecord;
import org.owasplab.coach.spec.CoachSpec;

import java.util.List;

public interface LlmClient {
    /**
     * 基于 prompt + 最近流量 + 命中 spec 给出结构化建议。
     * 注意：flows/reqBody/reqHeaders 已在采集阶段做了白名单+脱敏+截断，可直接使用。
     */
    String analyze(String prompt, List<FlowRecord> flows, CoachSpec spec);
}

