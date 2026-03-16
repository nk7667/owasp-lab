package org.owasplab.service;

import org.owasplab.core.Mode;
import org.owasplab.entity.Comment;
import org.owasplab.repository.CommentRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.net.URI;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.time.LocalDateTime;
import java.net.URLEncoder;

@Service
public class XssServiceImpl implements XssService {

    private final CommentRepository commentRepository;

    public XssServiceImpl(CommentRepository commentRepository) {
        this.commentRepository = commentRepository;
    }

    @Override
    public Map<String, Object> searchRender(Mode mode, String context, String input) {
        String raw = input == null ? "" : input;
        String ctx = context == null ? "html" : context.trim().toLowerCase();

        String render;
        switch (mode) {
            case SAFE:
                render = safeByContext(ctx, raw);
                break;
            case WEAK: // WEAK：错误修复示例（可绕过）
                // searchRender 是老接口：暂不引入 weakLevel，默认使用 WEAK-1
                render = weakFixExample(ctx, raw, 1);
                break;
            case VULN:
            default:
                render = raw;
        }

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "search");
        out.put("type", "reflected");
        out.put("context", ctx);
        out.put("input", raw);
        out.put("render", render);
        return out;
    }

    @Override
    public Map<String, Object> searchResults(Mode mode, String q, String target, int weakLevel) {
        String rawQ = q == null ? "" : q;
        String focus = normalizeFocus(target);
        boolean focusAll = "all".equals(focus);
        int wl = normalizeWeakLevel(weakLevel);

        // 企业化字段：搜索页常见的 3 个落点
        // 1) HTML 高亮/空状态（会进 innerHTML）
        // 2) 分享链接 href（URL 上下文）
        // 3) 埋点/配置（JS 字符串上下文）
        String highlightHtml;
        String emptyStateHtml;
        String shareHref;
        String analyticsConfigJs;

        // 先按 mode 生成“完整的企业化落点”（真实系统里往往是同一个 q 流入多个字段）
        if (mode == Mode.SAFE) {
            String safeHtml = HtmlUtils.htmlEscape(rawQ);
            highlightHtml = "<mark>" + safeHtml + "</mark>";
            emptyStateHtml = "未找到与 <b>" + safeHtml + "</b> 相关的结果";

            // URL：严格只允许 http/https，否则降级为 "#"
            // 这里将 share 链接构造成“企业常见分享 URL”，并对 q 做最小 URL 编码（仅演示）
            String candidate = "https://intra.example.local/search?q=" + urlEncodeQuery(rawQ);
            shareHref = allowHttpUrlOrHash(candidate);

            // JS 字符串上下文：正确的 JS string escaping
            String safeJs = escapeJsString(rawQ);
            analyticsConfigJs = "{ \"event\": \"search\", \"q\": \"" + safeJs + "\" }";
        } else if (mode == Mode.WEAK) {
            // WEAK：错误修复/弱防护（仍可绕过）
            // 典型：只替换 <script / javascript:，不处理事件属性/引号闭合/模板字符串等
            String weak = weakFixExample("html", rawQ, wl);
            highlightHtml = "<mark>" + weak + "</mark>";
            emptyStateHtml = "未找到与 <b>" + weak + "</b> 相关的结果";

            String weakHref = "https://intra.example.local/search?q=" + weak;
            weakHref = weakFixExample("url", weakHref, wl);
            shareHref = weakHref;

            // 错误做法：把 HTML 弱清洗的结果直接放进 JS 字符串
            analyticsConfigJs = "{ \"event\": \"search\", \"q\": \"" + weak + "\" }";
        } else {
            // VULN：原始漏洞（直接拼接）
            highlightHtml = "<mark>" + rawQ + "</mark>";
            emptyStateHtml = "未找到与 <b>" + rawQ + "</b> 相关的结果";
            shareHref = "https://intra.example.local/search?q=" + rawQ;
            analyticsConfigJs = "{ \"event\": \"search\", \"q\": \"" + rawQ + "\" }";
        }

        // 为了学习体验：默认“一次只练一个落点（一个 sink）”，避免 payload 在多个区域同时触发导致因果定位困难。
        // 这里在服务端把“非目标落点”强制降级为 SAFE（即使前端误渲染，也不会产生混叠信号）。
        if (!focusAll) {
            if (!"html".equals(focus)) {
                String safeHtml = HtmlUtils.htmlEscape(rawQ);
                highlightHtml = "<mark>" + safeHtml + "</mark>";
                emptyStateHtml = "未找到与 <b>" + safeHtml + "</b> 相关的结果";
            }
            if (!"attr".equals(focus)) {
                shareHref = allowHttpUrlOrHash("https://intra.example.local/search?q=" + urlEncodeQuery(rawQ));
            }
            if (!"js".equals(focus)) {
                analyticsConfigJs = "{ \"event\": \"search\", \"q\": \"" + escapeJsString(rawQ) + "\" }";
            }
        }

        // 伪造一些“正常”搜索结果，snippet 里包含高亮片段（真实企业搜索常见）
        List<Map<String, Object>> items = new ArrayList<>();
        if (rawQ.trim().isEmpty()) {
            // 空关键字：给一点默认内容
            items.add(item(1, "企业知识库：安全编码指南", "建议搜索关键字，例如：XSS / SQLi / CSP"));
            items.add(item(2, "FAQ：如何提交工单", "输入关键字将会在结果中高亮显示"));
        } else {
            // 只在 focus=html 或 focus=all 时，把高亮片段作为“HTML 上下文 sink”暴露出来；
            // 其他 focus 下，snippet 强制做 HTML 转义，避免学员误以为自己在练 URL/JS，却被 HTML 落点抢跑触发。
            if (focusAll || "html".equals(focus)) {
                items.add(item(1, "搜索结果示例：与关键字相关的文档", "命中片段：" + highlightHtml));
                items.add(item(2, "搜索结果示例：内部公告", "你搜索的是：" + highlightHtml));
            } else {
                String safeText = HtmlUtils.htmlEscape(rawQ);
                items.add(item(1, "搜索结果示例：与关键字相关的文档", "命中片段：" + safeText));
                items.add(item(2, "搜索结果示例：内部公告", "你搜索的是：" + safeText));
            }
        }

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "search");
        out.put("type", "reflected");
        out.put("q", rawQ);
        out.put("target", focus);
        out.put("items", items);
        out.put("count", items.size());
        out.put("highlightHtml", highlightHtml);
        out.put("emptyStateHtml", emptyStateHtml);
        out.put("shareHref", shareHref);
        out.put("analyticsConfig", analyticsConfigJs);

        // 给前端/coach 用的“落点说明”（不要求学员输入 context 参数，减少题目感）
        List<Map<String, Object>> sinks = new ArrayList<>();
        sinks.add(kv("context", "html", "sink", "innerHTML", "field", "highlightHtml/emptyStateHtml"));
        sinks.add(kv("context", "attr", "sink", "href", "field", "shareHref"));
        sinks.add(kv("context", "js", "sink", "jsString", "field", "analyticsConfig"));
        out.put("sinks", sinks);

        return out;
    }

    @Override
    public Map<String, Object> commentSubmit(Mode mode, String author, String content, String website, int weakLevel) {
        String a = author == null ? "anonymous" : author;
        String c = content == null ? "" : content;
        String w = website == null ? "" : website;
        int wl = normalizeWeakLevel(weakLevel);

        // 企业化：入库建议存“原文”（便于审计/回溯），渲染时再决定 VULN/WEAK/SAFE
        // 这里为了教学对照，仍返回“本次在当前 mode 下的预览渲染结果”，但不改变存储内容。
        Comment saved = commentRepository.save(new Comment(a, c, w, LocalDateTime.now()));

        Map<String, Object> preview = renderCommentForMode(mode, saved, wl);

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "comment");
        out.put("type", "stored");
        out.put("savedId", saved.getId());
        out.put("preview", preview);
        return out;
    }

    @Override
    public Map<String, Object> commentList(Mode mode, int weakLevel) {
        int wl = normalizeWeakLevel(weakLevel);
        List<Comment> all = commentRepository.findAll();
        List<Map<String, Object>> items = new ArrayList<>();
        for (Comment c : all) {
            items.add(renderCommentForMode(mode, c, wl));
        }

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "comment");
        out.put("type", "stored");
        out.put("items", items);
        out.put("count", items.size());
        return out;
    }

    @Override
    public Map<String, Object> adminReview(Mode mode, int weakLevel) {
        // 企业化：管理员审核页（高权限查看触发链路）
        // 这里复用 commentList，但强调 sink=innerHTML（预览富文本/评论内容）
        Map<String, Object> out = commentList(mode, weakLevel);
        out.put("biz", "admin");
        out.put("type", "stored");
        out.put("view", "review");
        return out;
    }

    @Override
    public Map<String, Object> commentDelete(Mode mode, long id, int weakLevel) {
        long before = commentRepository.count();
        boolean existed = false;
        boolean deleted = false;
        try {
            existed = commentRepository.existsById(id);
            if (existed) {
                commentRepository.deleteById(id);
                deleted = true;
            }
        } catch (Exception ignore) {
            // 对教学靶场：删除失败不抛异常，避免影响主流程
        }
        long after = commentRepository.count();

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "comment_admin");
        out.put("op", "delete");
        out.put("id", id);
        out.put("existed", existed);
        out.put("deleted", deleted);
        out.put("countBefore", before);
        out.put("countAfter", after);
        return out;
    }

    @Override
    public Map<String, Object> commentClear(Mode mode, int weakLevel) {
        long before = commentRepository.count();
        boolean cleared = false;
        try {
            commentRepository.deleteAll();
            cleared = true;
        } catch (Exception ignore) {
        }
        long after = commentRepository.count();

        Map<String, Object> out = new HashMap<>();
        out.put("biz", "comment_admin");
        out.put("op", "clear");
        out.put("cleared", cleared);
        out.put("countBefore", before);
        out.put("countAfter", after);
        return out;
    }

    private static String safeByContext(String ctx, String s) {
        switch (ctx) {
            case "js":
                // JS 字符串上下文：做 JS string escaping（不是 htmlEscape）
                return escapeJsString(s);
            case "url":
                // URL 上下文：协议白名单（http/https），否则降级为 "#"
                return allowHttpUrlOrHash(s);
            case "attr":
            case "html":
            default:
                // HTML/Attr：基础 HTML 转义
                return HtmlUtils.htmlEscape(s);
        }
    }

    private static String weakFixExample(String ctx, String s, int weakLevel) {
        // WEAK 的目的：模拟“错误修复”，不是防住一切
        // weakLevel=1/2：用于展示“弱修复家族”
        String c = ctx == null ? "" : ctx.trim().toLowerCase();
        int wl = normalizeWeakLevel(weakLevel);
        String x = s == null ? "" : s;

        // A1：HTML 内容上下文（innerHTML）
        if ("html".equals(c)) {
            if (wl == 1) {
                // WEAK-1：黑名单示例（只挡 <script / javascript:）
                x = x.replaceAll("(?i)<\\s*script", "<scr_ipt");
                x = x.replaceAll("(?i)javascript\\s*:", "");
                return x;
            }
            // WEAK-2：富文本弱清洗（只挡 script/style，不清事件属性/协议/其它载体）
            x = x.replaceAll("(?i)<\\s*script", "<scr_ipt");
            x = x.replaceAll("(?i)<\\s*style", "<st_y_le");
            return x;
        }

        // A2：属性/URL 上下文（href）
        if ("url".equals(c) || "attr".equals(c)) {
            if (wl == 1) {
                // WEAK-1：只移除 javascript: 字面量（无协议白名单/无规范化）
                return x.replaceAll("(?i)javascript\\s*:", "");
            }
            // WEAK-2：顺序/规范化错误示例——先做字符串替换，再 decode（多重编码可“复活”危险 scheme）
            String t = x.replaceAll("(?i)javascript\\s*:", "");
            return urlDecodeOnce(t);
        }

        // A3：JS 字符串上下文（错误示例保持单一：复用 HTML 弱处理结果）
        if ("js".equals(c)) {
            return weakFixExample("html", x, 1);
        }

        // fallback：按 html 处理
        return weakFixExample("html", x, wl);
    }

    private static int normalizeWeakLevel(int weakLevel) {
        return weakLevel >= 2 ? 2 : 1;
    }

    private static String urlDecodeOnce(String s) {
        if (s == null) return "";
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (Exception ignore) {
            return s;
        }
    }

    private static String escapeJsString(String s) {
        if (s == null) return "";
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("'", "\\'")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    private static String allowHttpUrlOrHash(String s) {
        if (s == null) return "#";
        String t = s.trim();
        if (t.isEmpty()) return "#";
        try {
            URI u = URI.create(t);
            String scheme = u.getScheme();
            if (scheme == null) return "#";
            String lower = scheme.toLowerCase();
            if ("http".equals(lower) || "https".equals(lower)) return t;
            return "#";
        } catch (Exception ignore) {
            return "#";
        }
    }

    private static Map<String, Object> item(int id, String title, String snippet) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", id);
        m.put("title", title);
        m.put("snippet", snippet);
        return m;
    }

    private static Map<String, Object> kv(String k1, Object v1, String k2, Object v2, String k3, Object v3) {
        Map<String, Object> m = new HashMap<>();
        m.put(k1, v1);
        m.put(k2, v2);
        m.put(k3, v3);
        return m;
    }

    private static String urlEncodeQuery(String s) {
        if (s == null) return "";
        try {
            return URLEncoder.encode(s, "UTF-8");
        } catch (Exception ignore) {
            return "";
        }
    }
    private static String normalizeFocus(String target) {
        if (target == null) return "html";
        String t = target.trim().toLowerCase();
        switch (t) {
            case "all":
            case "html":
            case "attr":
            case "js":
                return t;
            case "url": // 兼容旧命名：href 落点本质是 HTML 属性上下文
                return "attr";
            default:
                return "html";
        }
    }

    private static Map<String, Object> renderCommentForMode(Mode mode, Comment c, int weakLevel) {
        String author = c == null ? "" : String.valueOf(c.getAuthor());
        String content = c == null ? "" : String.valueOf(c.getContent());
        String website = c == null ? "" : String.valueOf(c.getWebsite());

        String renderedAuthor;
        String renderedContent;
        String renderedWebsiteHref;

        if (mode == Mode.SAFE) {
            renderedAuthor = HtmlUtils.htmlEscape(author);
            renderedContent = HtmlUtils.htmlEscape(content);
            renderedWebsiteHref = allowHttpUrlOrHash(website);
        } else if (mode == Mode.WEAK) {
            renderedAuthor = weakFixExample("html", author, weakLevel);
            renderedContent = weakFixExample("html", content, weakLevel);
            // 错误修复：只挡 javascript:，仍可能被 data:/大小写/空白变体绕过（留作后续升级点）
            renderedWebsiteHref = weakFixExample("url", website, weakLevel);
        } else {
            renderedAuthor = author;
            renderedContent = content;
            renderedWebsiteHref = website;
        }

        Map<String, Object> m = new HashMap<>();
        m.put("id", c == null ? null : c.getId());
        m.put("author", renderedAuthor);
        m.put("content", renderedContent);
        m.put("websiteHref", renderedWebsiteHref);
        m.put("createdAt", c == null ? null : c.getCreatedAt());
        return m;
    }
}