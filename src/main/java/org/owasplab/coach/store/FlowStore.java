package org.owasplab.coach.store;

import org.owasplab.coach.model.FlowRecord;

import java.util.List;

public interface FlowStore {
    void append(FlowRecord record);

    /**
     * 返回最近 limit 条（按时间倒序：最新在前）
     */
    List<FlowRecord> recent(String sessionKey, int limit);
}