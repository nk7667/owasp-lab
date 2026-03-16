package org.owasplab.coach.spec;

import java.util.List;

/**
 * CoachSpec 表示“关卡规格说明”（spec），来源于 resources/coach/specs/*.json。
 * 目标：不暴露源码的前提下，让教练模块/LLM 理解每一关的教学目标、观测点与修复点。
 *
 * 注意：为了兼容 Jackson 反序列化，类与嵌套类都保留无参构造 + getter/setter。
 */
public class CoachSpec {
    private String context;
    private String title;
    private String goal;

    private Vuln vuln;
    private Safe safe;

    private List<String> signals;
    private List<String> routeHints;

    private List<String> notices;
    private List<String> nextSteps;
    private List<String> whySafe;

    private List<String> allowedToTell;
    private List<String> acceptanceCriteria;
    private List<String> doNotTell;
    /**
     * 可选：引用资料（有些 spec 会包含），用于内部追溯，不一定对学员展示。
     */
    private List<String> references;

    public CoachSpec() {}

    public String getContext() { return context; }
    public void setContext(String context) { this.context = context; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getGoal() { return goal; }
    public void setGoal(String goal) { this.goal = goal; }

    public Vuln getVuln() { return vuln; }
    public void setVuln(Vuln vuln) { this.vuln = vuln; }

    public Safe getSafe() { return safe; }
    public void setSafe(Safe safe) { this.safe = safe; }

    public List<String> getSignals() { return signals; }
    public void setSignals(List<String> signals) { this.signals = signals; }

    public List<String> getRouteHints() { return routeHints; }
    public void setRouteHints(List<String> routeHints) { this.routeHints = routeHints; }

    public List<String> getNotices() { return notices; }
    public void setNotices(List<String> notices) { this.notices = notices; }

    public List<String> getNextSteps() { return nextSteps; }
    public void setNextSteps(List<String> nextSteps) { this.nextSteps = nextSteps; }

    public List<String> getWhySafe() { return whySafe; }
    public void setWhySafe(List<String> whySafe) { this.whySafe = whySafe; }

    public List<String> getAllowedToTell() { return allowedToTell; }
    public void setAllowedToTell(List<String> allowedToTell) { this.allowedToTell = allowedToTell; }

    public List<String> getAcceptanceCriteria() { return acceptanceCriteria; }
    public void setAcceptanceCriteria(List<String> acceptanceCriteria) { this.acceptanceCriteria = acceptanceCriteria; }

    public List<String> getDoNotTell() { return doNotTell; }
    public void setDoNotTell(List<String> doNotTell) { this.doNotTell = doNotTell; }

    public List<String> getReferences() { return references; }
    public void setReferences(List<String> references) { this.references = references; }

    public static class Vuln {
        private String summary;
        private List<String> impact;
        private List<String> whatToObserve;

        public Vuln() {}

        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }

        public List<String> getImpact() { return impact; }
        public void setImpact(List<String> impact) { this.impact = impact; }

        public List<String> getWhatToObserve() { return whatToObserve; }
        public void setWhatToObserve(List<String> whatToObserve) { this.whatToObserve = whatToObserve; }
    }

    public static class Safe {
        private String summary;
        private List<String> keyControls;

        public Safe() {}

        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }

        public List<String> getKeyControls() { return keyControls; }
        public void setKeyControls(List<String> keyControls) { this.keyControls = keyControls; }
    }
}

