package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.owasplab.entity.Profile;
import org.owasplab.repository.ProfileRepository;
import org.owasplab.service.XssService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/xss")
public class XssController {

    private final XssService xssService;
    private final ProfileRepository profileRepository;

    public XssController(XssService xssService, ProfileRepository profileRepository) {
        this.xssService = xssService;
        this.profileRepository = profileRepository;
    }

    @GetMapping("/{mode}/search/render")
    public ResponseEntity<ApiResponse<Map<String, Object>>> searchRender(
            @PathVariable String mode,
            @RequestParam(defaultValue = "html") String context,
            @RequestParam(defaultValue = "") String input
    ) {
        Mode m = resolveMode(mode);

        // 让 “context/sink/mode” 可观测、可写文章、可给 coach
        String sink = sinkOfContext(context);
        // 关卡 ID（context）应稳定：不要把 mode 拼进 context，mode 已在 meta.mode 里
        String metaCtx = String.format("xss_reflected_search_%s_%s",
                safeLower(context), sink);

        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = xssService.searchRender(m, context, input);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    /**
     * 企业化：搜索结果（Reflected 场景）
     * 注入点不再是“render”字段，而是隐藏在正常业务字段：高亮 HTML / 空状态 / 分享链接 / 埋点配置。
     */
    @GetMapping("/{mode}/search/results")
    public ResponseEntity<ApiResponse<Map<String, Object>>> searchResults(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "html") String target,
            @RequestParam(required = false, defaultValue = "1") int weakLevel
    ) {
        Mode m = resolveMode(mode);

        // 为学习体验：默认一次只练一个落点（target=html/url/js），也支持 target=all（真实混合流）
        String t = safeLower(target);
        String sink;
        String ctx;
        if ("url".equals(t) || "attr".equals(t)) {
            ctx = "attr";
            sink = "href";
        } else if ("js".equals(t)) {
            ctx = "js";
            sink = "jsString";
        } else if ("all".equals(t)) {
            ctx = "multi";
            sink = "multi";
        } else {
            ctx = "html";
            sink = "innerHTML";
        }

        String metaCtx = String.format("xss_reflected_search_%s_%s", ctx, sink);
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = new HashMap<>(xssService.searchResults(m, q, target, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @PostMapping("/{mode}/comment/submit")
    public ResponseEntity<ApiResponse<Map<String, Object>>> commentSubmit(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "1") int weakLevel,
            @RequestBody Map<String, String> body
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_stored_comment_html_innerHTML";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        String author = body == null ? null : body.get("author");
        String content = body == null ? null : body.get("content");
        String website = body == null ? null : body.get("website");

        Map<String, Object> data = new HashMap<>(xssService.commentSubmit(m, author, content, website, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @GetMapping("/{mode}/comment/list")
    public ResponseEntity<ApiResponse<Map<String, Object>>> commentList(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "1") int weakLevel
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_stored_comment_html_innerHTML";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = new HashMap<>(xssService.commentList(m, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @PostMapping("/{mode}/comment/delete")
    public ResponseEntity<ApiResponse<Map<String, Object>>> commentDelete(
            @PathVariable String mode,
            @RequestParam long id,
            @RequestParam(required = false, defaultValue = "1") int weakLevel
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_stored_comment_admin_delete";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = new HashMap<>(xssService.commentDelete(m, id, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @PostMapping("/{mode}/comment/clear")
    public ResponseEntity<ApiResponse<Map<String, Object>>> commentClear(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "1") int weakLevel
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_stored_comment_admin_clear";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = new HashMap<>(xssService.commentClear(m, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    @GetMapping("/{mode}/admin/review")
    public ResponseEntity<ApiResponse<Map<String, Object>>> adminReview(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "1") int weakLevel
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_stored_admin_html_innerHTML";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        Map<String, Object> data = new HashMap<>(xssService.adminReview(m, weakLevel));
        data.put("weakLevel", weakLevel);
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    /**
     * Blind · Profile（提交端）
     * - 分离“用户提交页”和“后台预览页”，便于理解“盲打的执行发生在后台页面”。
     * - 这里仅负责把用户输入存起来，供后台页读取并渲染。
     */
    @PostMapping("/{mode}/profile/submit")
    public ResponseEntity<ApiResponse<Map<String, Object>>> profileSubmit(
            @PathVariable String mode,
            @RequestBody Map<String, String> body
    ) {
        Mode m = resolveMode(mode);
        String metaCtx = "xss_blind_profile_submit";
        ApiMeta meta = new ApiMeta(
                "xss",
                m,
                Arrays.asList("requirements", "coding_sast", "testing_dast"),
                SignalChannel.inband,
                "CWE-79",
                metaCtx
        );

        String nickname = "";
        String bio = "";
        if (body != null) {
            String n = body.get("nickname");
            String b = body.get("bio");
            nickname = n == null ? "" : n.trim();
            bio = b == null ? "" : b;
        }
        if (nickname.isEmpty()) nickname = "匿名";

        Profile p = profileRepository.save(new Profile(nickname, bio, LocalDateTime.now()));
        Map<String, Object> data = new HashMap<>();
        data.put("profileId", p.getId());
        data.put("nickname", p.getNickname());
        return ResponseEntity.ok(ApiResponse.ok(data, meta));
    }

    /**
     * Blind · Profile（后台预览页）
     * 说明：这是一个 HTML 页面（给 iframe 加载），它会把“用户提交的 bio”渲染到页面里。
     * - VULN：直接拼接 innerHTML
     * - SAFE：做 HTML escape（等价于把输入当成纯文本挂载）
     * 前端会把 iframe sandbox 设为 allow-scripts + allow-same-origin，使其更像真实后台页。
     */
    @GetMapping(value = "/{mode}/profile/admin/view", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> profileAdminView(
            @PathVariable String mode,
            @RequestParam long id
    ) {
        Mode m = resolveMode(mode);

        Optional<Profile> opt = profileRepository.findById(id);
        String nickname = opt.map(Profile::getNickname).orElse("（不存在）");
        String bioRaw = opt.map(Profile::getBio).orElse("");

        String renderedBio;
        if (m == Mode.SAFE) {
            renderedBio = htmlEscape(bioRaw);
        } else {
            renderedBio = bioRaw == null ? "" : bioRaw;
        }

        String safeNickname = htmlEscape(nickname);
        String safeCreatedAt = htmlEscape(opt.map(p -> String.valueOf(p.getCreatedAt())).orElse(""));
        String view = "xss_blind_profile_admin_view";
        String beaconJson = "{"
                + "\"kind\":\"render\","
                + "\"view\":\"" + view + "\","
                + "\"profileId\":" + id + ","
                + "\"mode\":\"" + (m == null ? "" : m.name()) + "\","
                + "\"ts\":" + System.currentTimeMillis()
                + "}";

        String html = ""
                + "<!doctype html><html><head><meta charset=\"utf-8\"/>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                + "<title>Admin · Profile Review</title>"
                + "<style>"
                + "body{margin:0;background:#0b1220;color:#e6edf3;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}"
                + ".wrap{max-width:980px;margin:20px auto;padding:0 16px}"
                + ".card{background:#121a2a;border:1px solid #2d3a4d;border-radius:12px;padding:16px}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + ".row{display:flex;gap:12px;flex-wrap:wrap;align-items:baseline}"
                + ".k{color:#8b9cb3}"
                + ".v{color:#e6edf3}"
                + ".bio{margin-top:12px;padding:12px;border-radius:10px;background:#0f1419;border:1px solid #2d3a4d;min-height:120px;white-space:normal;word-break:break-word}"
                + ".hr{height:1px;background:#223047;margin:12px 0}"
                + "</style></head><body>"
                + "<div class=\"wrap\">"
                + "<div class=\"card\">"
                + "<div class=\"muted\">Blind · Profile · Admin View (sandbox allow-same-origin) · build=owasp-lab-blind-profile-v1</div>"
                + "<div class=\"hr\"></div>"
                + "<div class=\"row\"><span class=\"k\">ID</span><span class=\"v\">" + id + "</span>"
                + "<span class=\"k\">昵称</span><span class=\"v\">" + safeNickname + "</span>"
                + "<span class=\"k\">创建</span><span class=\"v\">" + safeCreatedAt + "</span>"
                + "<span class=\"k\">模式</span><span class=\"v\">" + (m == null ? "" : m.name()) + "</span>"
                + "</div>"
                + "<div class=\"bio\" id=\"bio\">"
                + renderedBio
                + "</div>"
                + "</div>"
                + "</div>"
                + "<script>"
                + "(function(){"
                + "try{"
                + "var body=" + beaconJson + ";"
                + "fetch('/api/v1/blind/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).catch(function(){});"
                + "}catch(e){}"
                + "})();"
                + "</script>"
                + "</body></html>";

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    /**PostMessage XSS，源码片段意图（XSS-Sec）：iframe 允许 data:；父页面监听 message 并 innerHTML 写入
     * - 漏洞点：source=postMessage(e.data) -> sink=innerHTML（缺少 origin 校验 + 不安全 DOM 写入）
     *
     * 学习目标：DOM 链路/跨窗口信任边界，默认单落点可定位（只突出 innerHTML 一个 sink）。
     */
    @GetMapping(value = "/{mode}/dom/postmessage/page", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> domPostMessagePage(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "") String keyword,
            @RequestParam(required = false, defaultValue = "1") int weakLevel,
            @RequestParam(required = false, defaultValue = "1") int simulate
    ) {
        Mode m = resolveMode(mode);
        int wl = weakLevel >= 2 ? 2 : 1;
        boolean sim = simulate != 0;

        // XSS-Sec Level16：阻断 javascript: scheme（不要全局替换，避免破坏 keyword 里的教学 payload）
        // simulate=1 时：keyword 用作“消息内容”，不要再把它当 iframe src（否则 '<img...>' 会导致脚本异常/中断）
        String iframeUrl = sim ? "" : (keyword == null ? "" : keyword.trim());
        String lower = iframeUrl.toLowerCase(Locale.ROOT);
        if (lower.startsWith("javascript:")) iframeUrl = "";
        // 注意：这里的 iframe src 是给 JS 代码赋值（f.src = '...'），不能做 HTML 转义；
        // 否则会把 data: URL 里的 <script> 破坏为 &lt;script&gt;，导致 payload 不执行。
        String iframeSrc = iframeUrl;

        // 生成统一的 handler（用于真实 postMessage 与 simulate 路径），避免字符串 replace 拼函数体导致脚本静默失败
        String handlerBody;
        if (m == Mode.SAFE) {
            handlerBody = ""
                    + "  var isSim = !!(e && e.__sim === true);\n"
                    + "  var f = window.__labFrame;\n"
                    + "  if (!isSim) {\n"
                    + "    if (!f || e.source !== f.contentWindow) return;\n"
                    + "  }\n"
                    + "  if (e.origin !== window.location.origin) return;\n"
                    + "  var d = e.data;\n"
                    + "  if (typeof d !== 'string') return;\n"
                    + "  var msg = d;\n"
                    + "  var out = document.getElementById('out');\n"
                    + "  if (!out) return;\n"
                    + "  out.textContent = 'Received: ' + msg;\n";
        } else if (m == Mode.WEAK) {
            if (wl == 2) {
                handlerBody = ""
                        + "  var isSim = !!(e && e.__sim === true);\n"
                        + "  var f = window.__labFrame;\n"
                        + "  if (!isSim) {\n"
                        + "    if (!f || e.source !== f.contentWindow) return;\n"
                        + "  }\n"
                        + "  if (e.origin !== 'null') return;\n"
                        + "  var d = e.data;\n"
                        + "  if (typeof d !== 'string') return;\n"
                        + "  var msg = d;\n"
                        + "  var out = document.getElementById('out');\n"
                        + "  if (!out) return;\n"
                        + "  var re = /<\\s*script\\b|javascript\\s*:/i;\n"
                        + "  if (re.test(msg)) {\n"
                        + "    out.textContent = '🛇 Malicious content detected! (WEAK-2 blacklist hit)';\n"
                        + "    return;\n"
                        + "  }\n"
                        + "  out.innerHTML = 'Received: ' + msg;\n";
            } else {
                handlerBody = ""
                        + "  var isSim = !!(e && e.__sim === true);\n"
                        + "  var f = window.__labFrame;\n"
                        + "  if (!isSim) {\n"
                        + "    if (!f || e.source !== f.contentWindow) return;\n"
                        + "  }\n"
                        + "  if (e.origin !== 'null') return;\n"
                        + "  var d = e.data;\n"
                        + "  if (typeof d !== 'string') return;\n"
                        + "  var msg = d;\n"
                        + "  var out = document.getElementById('out');\n"
                        + "  if (!out) return;\n"
                        + "  out.innerHTML = 'Received: ' + msg;\n";
            }
        } else {
            handlerBody = ""
                    + "  var isSim = !!(e && e.__sim === true);\n"
                    + "  var f = window.__labFrame;\n"
                    + "  if (!isSim) {\n"
                    + "    if (!f || e.source !== f.contentWindow) return;\n"
                    + "  }\n"
                    + "  var d = e.data;\n"
                    + "  if (typeof d !== 'string') return;\n"
                    + "  var msg = d;\n"
                    + "  var out = document.getElementById('out');\n"
                    + "  if (!out) return;\n"
                    + "  out.innerHTML = 'Received: ' + msg;\n";
        }

        String iframeSrcJs = iframeSrc.isEmpty() ? "about:blank" : iframeSrc;
        String iframeSrcJsEsc = jsSingleQuoteEscape(iframeSrcJs);
        String kwMsg = keyword == null ? "" : keyword;
        // message 走 JS 单引号字符串：不做 HTML escape（否则会破坏教学 payload）
        String kwMsgJs = jsSingleQuoteEscape(kwMsg);

        String html = ""
                + "<!doctype html><meta charset=\"utf-8\">"
                + "<title>PostMessage Preview</title>"
                + "<style>"
                + "body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}"
                + ".box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;margin-bottom:12px;background:#161f2e}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + "input{width:100%;padding:10px;border-radius:8px;border:1px solid #2d3a4d;background:#0b1020;color:#e6edf3}"
                + "iframe{width:100%;height:120px;border:1px solid #2d3a4d;border-radius:8px;background:#0b1020}"
                + "</style>"
                + "<div class=\"box\">"
                + "<div class=\"muted\">迁移：XSS-Sec Level16（data: iframe → postMessage → parent innerHTML） · build=owasp-lab-l16-v4</div>"
                + "<div id=\"out\" style=\"margin-top:8px\">Waiting for messages from iframe...</div>"
                + "<div style=\"margin-top:10px\">"
                + "<button type=\"button\" id=\"selftest\" style=\"padding:6px 10px;border-radius:8px;border:1px solid #2d3a4d;background:#0b1020;color:#e6edf3;cursor:pointer;pointer-events:auto\">自测：直接写入 out</button>"
                + "<button type=\"button\" id=\"runKw\" style=\"margin-left:8px;padding:6px 10px;border-radius:8px;border:1px solid #2d3a4d;background:#0b1020;color:#e6edf3;cursor:pointer;pointer-events:auto\">运行：用 keyword 作为消息</button>"
                + "</div>"
                + "</div>"
                // 关键：先注册监听器，再创建 iframe，避免 data: 过快执行导致 message 丢失
                + "<script>"
                + "  (function(){\n"
                + "    function __handleMessage(e){\n"
                + "      try {\n"
                + handlerBody
                + "      } catch(ex) {}\n"
                + "    }\n"
                + "    window.__handleMessage = __handleMessage;\n"
                + "    window.addEventListener('message', function(e){ __handleMessage(e); });\n"
                + "    var btn = document.getElementById('selftest');\n"
                + "    if (btn) {\n"
                + "      btn.addEventListener('click', function(){\n"
                + "        var el = document.getElementById('out');\n"
                + "        if (el) el.textContent = 'Selftest clicked @ ' + new Date().toISOString();\n"
                + "        var demo = '<img src=x onerror=\"if(!this.dataset.f){this.dataset.f=1;document.getElementById(`out`).textContent=`Selftest XSS executed (l16-v4)`}\" >';\n"
                + "        if (el) el.innerHTML = 'Received: ' + demo;\n"
                + "      });\n"
                + "    }\n"
                + "    var btn2 = document.getElementById('runKw');\n"
                + "    if (btn2) {\n"
                + "      btn2.addEventListener('click', function(){\n"
                + "        var f = window.__labFrame;\n"
                + "        var origin = " + (m == Mode.SAFE ? "window.location.origin" : "'null'") + ";\n"
                + "        var e = { __sim: true, origin: origin, source: f ? f.contentWindow : null, data: '" + kwMsgJs + "' };\n"
                + "        __handleMessage(e);\n"
                + "      });\n"
                + "    }\n"
                + "    var box = document.getElementById('frameBox');\n"
                + "    if (box) {\n"
                + "      var f = document.createElement('iframe');\n"
                + "      f.id = 'labFrame';\n"
                + "      f.sandbox = 'allow-scripts allow-modals';\n"
                + "      window.__labFrame = f;\n"
                + "      f.src = '" + iframeSrcJsEsc + "';\n"
                + "      box.appendChild(f);\n"
                + "      var out = document.getElementById('out');\n"
                + "      if (out) out.textContent = 'Waiting for messages from iframe...';\n"
                + "    }\n"
                + "    if (" + (sim ? "true" : "false") + ") {\n"
                + "      // 默认自动跑一遍 keyword（simulate 路径不依赖 iframe ready；重试会造成同一次预览多次触发）\n"
                + "      try {\n"
                + "        var b = document.getElementById('runKw');\n"
                + "        if (b) b.click();\n"
                + "      } catch(e) {}\n"
                + "    }\n"
                + "  })();\n"
                + "</script>"
                + "<div class=\"box\">"
                + "<div class=\"muted\">Iframe Container（输入作为 iframe src；已做 JS 字符串转义，不破坏 data: 内容）</div>"
                + "<div id=\"frameBox\"></div>"
                + "</div>"
                ;

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    /**
     * CSP Bypass（同源 JSONP gadget）
     *
     * - 页面：反射 keyword 到 HTML（XSS 点），但 CSP 禁止 inline script
     * - Gadget：同源 JSONP 端点 callback 未严格校验，script-src 'self' 允许加载同源脚本
     */
    @GetMapping(value = "/{mode}/csp/jsonp", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> cspJsonpPage(
            @PathVariable String mode,
            @RequestParam(required = false, defaultValue = "") String keyword,
            @RequestParam(required = false) String callback,
            @RequestParam(required = false, defaultValue = "1") int weakLevel,
            HttpServletRequest request
    ) {
        Mode m = resolveMode(mode);
        int wl = weakLevel >= 2 ? 2 : 1;

        // JSONP 分支：同一路径模拟 ?callback=... 返回 JS
        if (callback != null) {
            String cb = callback;
            if (m == Mode.WEAK) {
                if (wl == 2) {
                    // WEAK-2：宽松 allowlist（为了“兼容 bracket 访问”而引入风险）
                    // 允许 ns.fn 和 ns['x'] 形式，但没有约束 [] 内表达式，仍可被 window['al'+'ert'] 等利用（参考 XSS-Sec 绕过思路）
                    if (!cb.matches("^[a-zA-Z_$][0-9a-zA-Z_$]*(\\\\.[a-zA-Z_$][0-9a-zA-Z_$]*)*(\\\\[[^\\\\]]+\\\\])*$")) {
                        cb = "cb";
                    }
                } else {
                    // WEAK-1：错误修复示例——只做关键字替换（可被 window['al'+'ert'] 等绕过）
                    cb = cb.replaceAll("(?i)alert", "blocked");
                    cb = cb.replaceAll("(?i)document\\s*\\.\\s*cookie", "document.blocked");
                }
            } else if (m == Mode.SAFE) {
                // SAFE：避免 JSONP callback 被当作“可控代码片段”
                // - 仅允许固定回调名 cb（或你也可以扩展为 allowlist 集合）
                // - 其余全部收敛到 cb，避免调用 alert / window[...] 等任意全局对象
                if (!"cb".equals(cb)) cb = "cb";
            }
            String js = cb + "({\"status\":\"ok\",\"time\":\"" + System.currentTimeMillis() + "\"});";
            return ResponseEntity.ok()
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .contentType(MediaType.valueOf("application/javascript; charset=utf-8"))
                    .body(js);
        }

        // 页面分支：严格 CSP（禁用 inline），但允许同源外部脚本
        // 同时加 report-uri，把 CSP 的“缓解效果/违规信号”写入后端形成可观测闭环
        //
        // WEAK-2：新增一个并行 weak 分支（来自 XSS-Sec note.md）：
        // 错误地把“调试 token/追踪字段”（例如 token）拼接进 report-uri，且不做编码/拒绝 ';'，导致可用分号注入新指令。
        // 为了更真实：这里不在函数签名里显式声明 token 参数，而是直接从 request 里取。
        String csp;
        if (m == Mode.WEAK && wl == 2) {
            String t = request == null ? "" : request.getParameter("token");
            if (t == null) t = "";
            csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /api/v1/security/csp/report?token=" + t + ";";
        } else {
            csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /api/v1/security/csp/report;";
        }

        String render;
        if (m == Mode.SAFE) {
            render = "Results for: " + htmlEscape(keyword);
        } else {
            // VULN：直接反射
            render = "Results for: " + (keyword == null ? "" : keyword);
        }

        String html = ""
                + "<!doctype html><meta charset=\"utf-8\">"
                + "<title>CSP + JSONP</title>"
                + "<style>"
                + "body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}"
                + ".box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;margin-bottom:12px;background:#161f2e}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + "</style>"
                + "<div class=\"box\">"
                + "<div class=\"muted\">迁移：XSS-Sec Level17（CSP 禁 inline；同源 JSONP 作为 gadget） · build=owasp-lab-l17-v2</div>"
                + "<div class=\"muted\" style=\"margin-top:6px\">CSP: <code style=\"color:#c6d3e5\">" + htmlEscape(csp) + "</code></div>"
                + "<div style=\"margin-top:8px\">" + render + "</div>"
                + "</div>"
                + "<div class=\"box\">"
                + "<div class=\"muted\">提示：同源 JSONP 端点：<code>?callback=test</code></div>"
                + "</div>";

        return ResponseEntity.ok()
                .header("Content-Security-Policy", csp)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    /**
     * 迁移自 XSS-Sec-main Level 26：Canonical Link XSS（ENT_COMPAT/单引号未转义）
     *
     * - 漏洞点：把“当前 URL（含 query）”拼进 <link rel="canonical" href='...'> 的单引号属性里
     * - 错误修复素材：转义顺序/解码次数不当，会把 %27 还原成 ' 再次出现（逃逸）
     */
    @GetMapping(value = "/{mode}/seo/canonical", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> seoCanonical(
            @PathVariable String mode,
            HttpServletRequest request
    ) {
        Mode m = resolveMode(mode);

        String raw = request.getRequestURI();
        if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
            raw = raw + "?" + request.getQueryString();
        }

        // 迁移自 XSS-Sec Level26：先 urldecode，再做“错误的转义参数选择”
        // 关键点：如果不 decode，%27 永远不会变成 '，就无法触发“单引号属性逃逸”。
        String decodedRaw;
        try {
            decodedRaw = URLDecoder.decode(raw, "UTF-8");
        } catch (Exception ignore) {
            decodedRaw = raw;
        }

        // 构造“当前 URL”（简化：同源 + 当前路径）
        String currentUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + decodedRaw;

        String canonicalHref;
        if (m == Mode.SAFE) {
            // SAFE：不拼 query（或白名单参数）；并进行完整属性转义（含引号）
            String safePathOnly = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort()
                    + request.getRequestURI();
            canonicalHref = htmlAttrEscapeAllQuotes(safePathOnly);
        } else if (m == Mode.WEAK) {
            // WEAK：错误修复示例——先做“半吊子转义”（不含单引号），再做 decode，导致 %27 还原成 '
            String halfEscaped = htmlAttrEscape(currentUrl);
            try {
                canonicalHref = htmlAttrEscape(URLDecoder.decode(halfEscaped, "UTF-8"));
            } catch (Exception ignore) {
                canonicalHref = htmlAttrEscape(halfEscaped);
            }
        } else {
            // VULN：属性用单引号包裹，但转义不处理单引号（模拟 ENT_COMPAT）
            canonicalHref = htmlAttrEscape(currentUrl);
        }

        String html = ""
                + "<!doctype html><meta charset=\"utf-8\">"
                + "<title>Canonical Link</title>"
                + "<link rel=\"canonical\" href='" + canonicalHref + "'>"
                + "<style>"
                + "body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}"
                + ".box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;margin-bottom:12px;background:#161f2e}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + "code{color:#c6d3e5}"
                + "</style>"
                + "<div class=\"box\">"
                + "<div class=\"muted\">迁移：XSS-Sec Level26（canonical 单引号属性逃逸：查看页面源代码） · build=owasp-lab-l26-v2</div>"
                + "<div style=\"margin-top:8px\">这个页面会根据“当前 URL（含 query）”生成 canonical。请查看源代码中的 <code>&lt;link rel=\"canonical\" ...&gt;</code></div>"
                + "<div style=\"margin-top:8px\"><a id=\"canonGo\" href=\"#\" style=\"color:#38bdf8\">触发（debug）</a></div>"
                + "</div>"
                + "<script>"
                + "(function(){"
                + "  var link = document.querySelector('link[rel=\"canonical\"]');"
                + "  var go = document.getElementById('canonGo');"
                + "  if (go && link) {"
                + "    try { go.setAttribute('href', link.getAttribute('href') || '#'); } catch(e) {}"
                + "    var oc = link.getAttribute('onclick');"
                + "    if (oc) { try { go.setAttribute('onclick', oc); } catch(e) {} }"
                + "  }"
                + "  if (go && link && link.getAttribute('onclick')) {"
                + "    setTimeout(function(){"
                + "      try {"
                + "        var ev = new MouseEvent('click', { bubbles: true, cancelable: true, view: window });"
                + "        go.dispatchEvent(ev);"
                + "      } catch(e) { try{ link.click(); }catch(e2){} }"
                + "    }, 50);"
                + "  }"
                + "})();"
                + "</script>";

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    private static Mode resolveMode(String mode) {
        if (mode == null) return Mode.VULN;
        switch (mode.trim().toLowerCase()) {
            case "safe":
                return Mode.SAFE;
            case "weak": // WEAK
                return Mode.WEAK;
            case "vuln":
            default:
                return Mode.VULN;
        }
    }

    private static String sinkOfContext(String context) {
        String c = safeLower(context);
        switch (c) {
            case "attr":
                return "inputValue";
            case "url":
                return "href";
            case "js":
                return "jsString";
            case "html":
            default:
                return "innerHTML";
        }
    }

    private static String safeLower(String s) {
        return s == null ? "" : s.trim().toLowerCase();
    }

    /**
     * HTML 文本转义（用于 SAFE 的“显示文本”）。
     */
    private static String htmlEscape(String s) {
        if (s == null) return "";
        return s
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    /**
     * 属性转义（故意不转义单引号），用来模拟 XSS-Sec Level26 的 ENT_COMPAT 类错误。
     * - 会转义：& < > "
     * - 不转义：'
     */
    private static String htmlAttrEscape(String s) {
        if (s == null) return "";
        return s
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    /**
     * 严格属性转义（包含单引号）。
     */
    private static String htmlAttrEscapeAllQuotes(String s) {
        return htmlEscape(s);
    }

    /**
     * 用于 JS 单引号字符串字面量的最小转义（Level16：f.src = '...'）。
     * 不做 HTML 转义，避免破坏 data: URL 内容。
     */
    private static String jsSingleQuoteEscape(String s) {
        if (s == null) return "";
        return s
                .replace("\\", "\\\\")
                .replace("'", "\\'")
                .replace("\r", "")
                .replace("\n", "");
    }
}