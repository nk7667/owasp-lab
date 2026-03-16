package org.owasplab.coach.llm;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "coach.llm")
public class CoachLlmProperties {
    /**
     * 是否启用 LLM 模式（默认 false，先走模板/规则模式）。
     */
    private boolean enabled = false;

    /**
     * provider 标识：stub / openai / 兼容网关等（当前仅支持 stub）。
     */
    private String provider = "stub";

    /**
     * OpenAI 兼容 API Key（建议通过环境变量注入，不要写入仓库）。
     * 例如 DashScope/百炼：sk-***
     */
    private String apiKey;

    /**
     * OpenAI 兼容 baseUrl（不含 /chat/completions 也可）。
     * DashScope 中国站（兼容模式）：https://dashscope.aliyuncs.com/compatible-mode/v1
     */
    private String baseUrl = "https://dashscope.aliyuncs.com/compatible-mode/v1";

    /**
     * 模型 ID，例如：qwen-plus / qwen-max / qwen-turbo 等。
     */
    private String model = "qwen-plus";

    /**
     * 温度（可选）。
     */
    private Double temperature = 0.2;

    /**
     * 最大输出 token（可选）。
     */
    private Integer maxTokens = 900;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public Double getTemperature() {
        return temperature;
    }

    public void setTemperature(Double temperature) {
        this.temperature = temperature;
    }

    public Integer getMaxTokens() {
        return maxTokens;
    }

    public void setMaxTokens(Integer maxTokens) {
        this.maxTokens = maxTokens;
    }
}

