package org.owasplab.core;

import java.util.List;

public class ApiMeta {
    //<!--打标五维度 -->
    private String module;
    private Mode mode;
    private List<String> sdlPhases;
    private SignalChannel signalChannel;
    private String cwe;
    /**
     * 业务/漏洞场景上下文（variant/context），用于细分同一 module 下的不同关卡/位置。
     * 例如：where_login_bypass、order_by、where_id、like_search 等。
     */
    private String context;

    public ApiMeta() {}//无参构造函数

    public ApiMeta(String module, Mode mode, List<String> sdlPhases, SignalChannel signalChannel, String cwe) {
        this(module, mode, sdlPhases, signalChannel, cwe, "none");
    }

    public ApiMeta(String module, Mode mode, List<String> sdlPhases, SignalChannel signalChannel, String cwe, String context) {
        this.module = module;
        this.mode = mode;
        this.sdlPhases = sdlPhases;
        this.signalChannel = signalChannel;
        this.cwe = cwe;
        this.context = context;
    }
    public String getModule() {return module;}
    public void setModule(String module) {this.module = module;}

    public Mode getMode() {return mode;}
    public void setMode(Mode mode) {this.mode = mode;}

    public List<String> getSdlPhases() {return sdlPhases;}
    public void setSdlPhases(List<String> sdlPhases) {this.sdlPhases = sdlPhases;}

    public SignalChannel getSignalChannel() { return signalChannel; }
    public void setSignalChannel(SignalChannel signalChannel) { this.signalChannel = signalChannel; }

    public String getCwe() { return cwe; }
    public void setCwe(String cwe) { this.cwe = cwe; }

    public String getContext() { return context; }
    public void setContext(String context) { this.context = context; }
}
