package org.owasplab.core;

/**
 * SignalChannel 表示“观测/反馈通道”，用于描述攻击者如何从系统行为中获得信号。
 * - inband: 响应内容直接回显（可直接看到数据/结果）
 * - error_based: 通过错误回显/异常差异获得信息
 * - blind_boolean: 通过 true/false 响应差异推断
 * - time_based: 通过响应耗时差推断
 * - oob: Out-of-band 带外回连（DNS/HTTP 等）
 * - none: 不适用
 */
public enum SignalChannel {
    none,
    inband,
    error_based,
    blind_boolean,
    time_based,
    oob
}

