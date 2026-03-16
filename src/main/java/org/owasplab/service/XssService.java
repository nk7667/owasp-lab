package org.owasplab.service;

import org.owasplab.core.Mode;

import java.util.Map;

public interface XssService {
    Map<String, Object> searchRender(Mode mode, String context, String input);

    /**
     * 企业化：搜索结果接口（Reflected 场景）
     * 输入是正常的 q（关键词），输出是正常的业务字段（高亮 HTML、空状态文案、分享链接、埋点配置等）。
     */
    Map<String, Object> searchResults(Mode mode, String q, String target, int weakLevel);

    Map<String, Object> commentSubmit(Mode mode, String author, String content, String website, int weakLevel);

    Map<String, Object> commentList(Mode mode, int weakLevel);

    /**
     * 训练辅助：删除单条评论（按 id）。
     * 目的：方便反复练习/复现，不用手动清库。
     */
    Map<String, Object> commentDelete(Mode mode, long id, int weakLevel);

    /**
     * 训练辅助：清空全部评论。
     */
    Map<String, Object> commentClear(Mode mode, int weakLevel);

    Map<String, Object> adminReview(Mode mode, int weakLevel);
}