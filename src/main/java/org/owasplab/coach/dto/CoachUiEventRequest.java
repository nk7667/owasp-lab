package org.owasplab.coach.dto;

/**
 * 前端训练事件上报（最小字段集）。
 * 仅用于把“学员刚刚做了什么”写入 FlowStore，辅助 Coach 在 DOM XSS 等场景下不依赖 HTTP 流量也能给出贴近反馈。
 */
public class CoachUiEventRequest {
    private String context;
    private String mode;
    private String target;
    private String focus;
    private String input;
    private Long ts;
    /** 可选，如命令执行关的 weakLevel，便于 Coach 按关卡区分 */
    private Integer weakLevel;

    public CoachUiEventRequest() {}

    public String getContext() { return context; }
    public void setContext(String context) { this.context = context; }

    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }

    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }

    public String getFocus() { return focus; }
    public void setFocus(String focus) { this.focus = focus; }

    public String getInput() { return input; }
    public void setInput(String input) { this.input = input; }

    public Long getTs() { return ts; }
    public void setTs(Long ts) { this.ts = ts; }

    public Integer getWeakLevel() { return weakLevel; }
    public void setWeakLevel(Integer weakLevel) { this.weakLevel = weakLevel; }
}

