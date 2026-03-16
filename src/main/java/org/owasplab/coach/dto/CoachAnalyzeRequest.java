package org.owasplab.coach.dto;

public class CoachAnalyzeRequest {
    private String prompt;
    private Integer limit;

    public String getPrompt() { return prompt; }
    public void setPrompt(String prompt) { this.prompt = prompt; }

    public Integer getLimit() { return limit; }
    public void setLimit(Integer limit) { this.limit = limit; }
}