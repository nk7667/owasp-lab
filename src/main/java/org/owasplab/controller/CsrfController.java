package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.owasplab.dto.LoginRequest;
import org.owasplab.entity.User;
import org.owasplab.repository.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.SecureRandom;
import java.util.*;

@RestController
@RequestMapping("/api/v1/csrf")
public class CsrfController {
    private static final String SESSION_USER_ID = "userId";
    private static final String SESSION_USERNAME = "username";
    private static final String SESSION_ROLE = "role";
    private static final String SESSION_CSRF_TOKEN = "csrfToken";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    public CsrfController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private static ApiMeta meta(Mode mode, SignalChannel ch, String context) {
        return new ApiMeta("csrf", mode, Arrays.asList("requirements", "coding_sast", "testing_dast"), ch, "CWE-352", context);
    }

    private static void attachSessionUser(HttpServletRequest request, User user) {
        HttpSession session = request.getSession(true);
        session.setAttribute(SESSION_USER_ID, user.getId());
        session.setAttribute(SESSION_USERNAME, user.getUsername());
        session.setAttribute(SESSION_ROLE, user.getRole());
    }

    private static Long sessionUserId(HttpServletRequest request) {
        if (request == null) return null;
        HttpSession s = request.getSession(false);
        if (s == null) return null;
        Object v = s.getAttribute(SESSION_USER_ID);
        if (v instanceof Number) return ((Number) v).longValue();
        return null;
    }

    private static String sessionUsername(HttpServletRequest request) {
        if (request == null) return null;
        HttpSession s = request.getSession(false);
        if (s == null) return null;
        Object v = s.getAttribute(SESSION_USERNAME);
        return v == null ? null : String.valueOf(v);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<Map<String, Object>>> login(@RequestBody LoginRequest req, HttpServletRequest request) {
        ApiMeta m = meta(Mode.NORMAL, SignalChannel.none, "csrf_login_session");
        String username = req == null ? null : req.getUsername();
        String password = req == null ? null : req.getPassword();
        if (username == null || username.trim().isEmpty()) {
            return ResponseEntity.ok(ApiResponse.fail("用户名不能为空", m));
        }
        Optional<User> opt = userRepository.findByUsername(username.trim());
        if (!opt.isPresent()) return ResponseEntity.ok(ApiResponse.fail("登录失败", m));
        User u = opt.get();
        if (password == null) password = "";
        if (!passwordEncoder.matches(password, u.getPassword())) {
            return ResponseEntity.ok(ApiResponse.fail("登录失败", m));
        }
        attachSessionUser(request, u);
        Map<String, Object> data = new HashMap<>();
        data.put("userId", u.getId());
        data.put("username", u.getUsername());
        data.put("role", u.getRole());
        return ResponseEntity.ok(ApiResponse.ok(data, m));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Map<String, Object>>> logout(HttpServletRequest request) {
        ApiMeta m = meta(Mode.NORMAL, SignalChannel.none, "csrf_logout_session");
        HttpSession s = request == null ? null : request.getSession(false);
        if (s != null) s.invalidate();
        Map<String, Object> data = new HashMap<>();
        data.put("success", true);
        return ResponseEntity.ok(ApiResponse.ok(data, m));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<Map<String, Object>>> me(HttpServletRequest request) {
        ApiMeta m = meta(Mode.NORMAL, SignalChannel.none, "csrf_me_session");
        Map<String, Object> data = new HashMap<>();
        data.put("userId", sessionUserId(request));
        data.put("username", sessionUsername(request));
        return ResponseEntity.ok(ApiResponse.ok(data, m));
    }

    /**
     * Low（无防护）：仿 DVWA low：GET 参数一致即可改密（无 token 校验）。
     * 说明：这里保留 GET，是为了在现代浏览器 SameSite=Lax 下仍能演示“跨站诱导 → 状态改变”。
     */
    @GetMapping("/low/password/change")
    public ResponseEntity<ApiResponse<Map<String, Object>>> lowChangePassword(
            HttpServletRequest request,
            @RequestParam(required = false, name = "password_new") String passwordNew,
            @RequestParam(required = false, name = "password_conf") String passwordConf,
            @RequestParam(required = false, name = "Change") String change
    ) {
        ApiMeta m = meta(Mode.VULN, SignalChannel.inband, "csrf_low_get_change_password");
        Long uid = sessionUserId(request);
        if (uid == null) return ResponseEntity.ok(ApiResponse.fail("not logged in", m));
        if (change == null) return ResponseEntity.ok(ApiResponse.fail("missing Change param", m));
        if (passwordNew == null) passwordNew = "";
        if (passwordConf == null) passwordConf = "";
        if (!passwordNew.equals(passwordConf)) {
            return ResponseEntity.ok(ApiResponse.fail("passwords did not match", m));
        }
        Optional<User> opt = userRepository.findById(uid);
        if (!opt.isPresent()) return ResponseEntity.ok(ApiResponse.fail("user not found", m));
        User u = opt.get();
        u.setPassword(passwordEncoder.encode(passwordNew));
        userRepository.save(u);
        Map<String, Object> data = new HashMap<>();
        data.put("changed", true);
        data.put("username", u.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(data, m));
    }

    /**
     * High（有 token）：仿 DVWA high，但更贴现实：
     * - 改密动作用 POST
     * - token 支持 header + body（JSON）
     * - token 绑定 session 且轮转
     * 重要：High 本身可防“外站直接伪造”，但若存在 XSS（同源执行），token 可被读取并用于同源请求链。
     */
    @PostMapping("/high/password/change")
    public ResponseEntity<ApiResponse<Map<String, Object>>> highChangePassword(
            HttpServletRequest request,
            @RequestHeader(value = "user-token", required = false) String tokenHeader,
            @RequestHeader(value = "x-csrf-token", required = false) String xCsrfHeader,
            @RequestBody(required = false) Map<String, Object> body
    ) {
        ApiMeta m = meta(Mode.WEAK, SignalChannel.inband, "csrf_high_post_change_password_token");
        Long uid = sessionUserId(request);
        if (uid == null) return ResponseEntity.ok(ApiResponse.fail("not logged in", m));

        Object tokenBodyObj = body == null ? null : body.get("user_token");
        String tokenBody = tokenBodyObj == null ? null : String.valueOf(tokenBodyObj);
        String token = firstNonEmpty(tokenHeader, xCsrfHeader, tokenBody);
        String expected = sessionToken(request);
        if (!safeEquals(token, expected)) {
            rotateSessionToken(request);
            return ResponseEntity.ok(ApiResponse.fail("csrf token error", m));
        }

        Object pnObj = body == null ? null : body.get("password_new");
        Object pcObj = body == null ? null : body.get("password_conf");
        String passwordNew = pnObj == null ? null : String.valueOf(pnObj);
        String passwordConf = pcObj == null ? null : String.valueOf(pcObj);
        if (passwordNew == null) passwordNew = "";
        if (passwordConf == null) passwordConf = "";
        if (!passwordNew.equals(passwordConf)) {
            rotateSessionToken(request);
            return ResponseEntity.ok(ApiResponse.fail("passwords did not match", m));
        }

        Optional<User> opt = userRepository.findById(uid);
        if (!opt.isPresent()) {
            rotateSessionToken(request);
            return ResponseEntity.ok(ApiResponse.fail("user not found", m));
        }
        User u = opt.get();
        u.setPassword(passwordEncoder.encode(passwordNew));
        userRepository.save(u);

        rotateSessionToken(request);
        Map<String, Object> data = new HashMap<>();
        data.put("changed", true);
        data.put("username", u.getUsername());
        return ResponseEntity.ok(ApiResponse.ok(data, m));
    }

    /**
     * High 表单页（victim 内网页面）：页面里会发放 token（隐藏字段），供正常表单/JS 提交使用。
     * 注意：此页面里预留了一个“提示文本 hint”的渲染点；你将用它作为反射型 XSS 注入点（同源执行链）。
     * 我会保持该渲染点默认安全（escape），到“漏洞利用关键点”再停下来让你手敲改成不安全拼接。
     */
    @GetMapping(value = "/high/password/page", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> highPasswordPage(
            HttpServletRequest request,
            @RequestParam(required = false, defaultValue = "") String hint
    ) {
        Long uid = sessionUserId(request);
        String username = sessionUsername(request);
        if (uid == null) {
            return ResponseEntity.status(401)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .contentType(MediaType.TEXT_HTML)
                    .body("<!doctype html><html><body style='font-family:system-ui'>not logged in</body></html>");
        }

        String token = rotateSessionToken(request);

        // 这里是“反射点”——默认做 escape（安全）。
        // 你要做 high 关的 XSS 链时，会把这里改成“不 escape 直接插入”，形成同源执行入口。
        String renderedHint = htmlEscape(hint);

        String html = ""
                + "<!doctype html><html><head><meta charset=\"utf-8\"/>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                + "<title>CSRF · High · Change Password</title>"
                + "<style>"
                + "body{margin:0;background:#0b1220;color:#e6edf3;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}"
                + ".wrap{max-width:980px;margin:20px auto;padding:0 16px}"
                + ".card{background:#121a2a;border:1px solid #2d3a4d;border-radius:12px;padding:16px}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + "input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2d3a4d;background:#0f1419;color:#e6edf3}"
                + "button{padding:10px 12px;border-radius:10px;border:1px solid #2d3a4d;background:#0ea5e9;color:#081018;font-weight:700;cursor:pointer}"
                + ".row{display:grid;grid-template-columns:1fr 1fr;gap:12px}"
                + "@media (max-width:720px){.row{grid-template-columns:1fr}}"
                + ".hint{margin-top:10px;padding:10px 12px;border-radius:10px;border:1px solid #2d3a4d;background:#0f1419}"
                + ".code{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;color:#c6d3e5}"
                + "</style></head><body>"
                + "<div class=\"wrap\"><div class=\"card\">"
                + "<div class=\"muted\">CSRF · High（token + rotate） · build=owasp-lab-csrf-high-v1</div>"
                + "<h3 style=\"margin:10px 0 6px\">Change password (user: " + htmlEscape(username) + ")</h3>"
                + "<div class=\"muted\">token 会轮转；提交时需要在 header 或 body 携带 user_token。</div>"
                + "<div class=\"hint\" id=\"hintBox\">" + renderedHint + "</div>"
                + "<form id=\"f\" style=\"margin-top:12px\">"
                + "<div class=\"row\">"
                + "<div><div class=\"muted\" style=\"margin:6px 0\">New password</div><input name=\"password_new\" autocomplete=\"off\"/></div>"
                + "<div><div class=\"muted\" style=\"margin:6px 0\">Confirm new password</div><input name=\"password_conf\" autocomplete=\"off\"/></div>"
                + "</div>"
                + "<input type=\"hidden\" name=\"user_token\" value=\"" + htmlEscape(token) + "\"/>"
                + "<div style=\"margin-top:12px\"><button type=\"submit\">Change (POST+token)</button></div>"
                + "</form>"
                + "<div id=\"out\" class=\"code\" style=\"margin-top:12px\"></div>"
                + "<script>"
                + "(function(){"
                + "var f=document.getElementById('f');"
                + "var out=document.getElementById('out');"
                + "f.addEventListener('submit', function(ev){"
                + "  ev.preventDefault();"
                + "  var fd=new FormData(f);"
                + "  var body={password_new:fd.get('password_new')||'',password_conf:fd.get('password_conf')||'',user_token:fd.get('user_token')||''};"
                + "  fetch('/api/v1/csrf/high/password/change', {"
                + "    method:'POST',"
                + "    headers:{'Content-Type':'application/json','user-token': String(fd.get('user_token')||'')},"
                + "    body: JSON.stringify(body)"
                + "  }).then(function(r){return r.json();}).then(function(j){"
                + "    try{ out.textContent = JSON.stringify(j,null,2);}catch(e){}"
                + "  }).catch(function(e){ out.textContent = String(e);});"
                + "});"
                + "})();"
                + "</script>"
                + "</div></div></body></html>";

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    /**
     * Low 的“victim 页面”（用于浏览器访问/演示 GET 改密链路）。
     * 注意：真正被 CSRF 利用的是 /low/password/change 的 GET 行为（无 token）。
     */
    @GetMapping(value = "/low/password/page", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> lowPasswordPage(HttpServletRequest request) {
        Long uid = sessionUserId(request);
        String username = sessionUsername(request);
        if (uid == null) {
            return ResponseEntity.status(401)
                    .header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .contentType(MediaType.TEXT_HTML)
                    .body("<!doctype html><html><body style='font-family:system-ui'>not logged in</body></html>");
        }

        String html = ""
                + "<!doctype html><html><head><meta charset=\"utf-8\"/>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                + "<title>CSRF · Low · Change Password</title>"
                + "<style>"
                + "body{margin:0;background:#0b1220;color:#e6edf3;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial}"
                + ".wrap{max-width:980px;margin:20px auto;padding:0 16px}"
                + ".card{background:#121a2a;border:1px solid #2d3a4d;border-radius:12px;padding:16px}"
                + ".muted{color:#8b9cb3;font-size:12px}"
                + "input{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #2d3a4d;background:#0f1419;color:#e6edf3}"
                + "button{padding:10px 12px;border-radius:10px;border:1px solid #2d3a4d;background:#f59e0b;color:#081018;font-weight:700;cursor:pointer}"
                + ".row{display:grid;grid-template-columns:1fr 1fr;gap:12px}"
                + "@media (max-width:720px){.row{grid-template-columns:1fr}}"
                + "</style></head><body>"
                + "<div class=\"wrap\"><div class=\"card\">"
                + "<div class=\"muted\">CSRF · Low（no defense） · build=owasp-lab-csrf-low-v1</div>"
                + "<h3 style=\"margin:10px 0 6px\">Change password (user: " + htmlEscape(username) + ")</h3>"
                + "<div class=\"muted\">危险点：GET 改状态 + 无 token 校验。</div>"
                + "<form action=\"/api/v1/csrf/low/password/change\" method=\"GET\" style=\"margin-top:12px\">"
                + "<div class=\"row\">"
                + "<div><div class=\"muted\" style=\"margin:6px 0\">New password</div><input name=\"password_new\" autocomplete=\"off\"/></div>"
                + "<div><div class=\"muted\" style=\"margin:6px 0\">Confirm new password</div><input name=\"password_conf\" autocomplete=\"off\"/></div>"
                + "</div>"
                + "<input type=\"hidden\" name=\"Change\" value=\"Change\"/>"
                + "<div style=\"margin-top:12px\"><button type=\"submit\">Change (GET)</button></div>"
                + "</form>"
                + "</div></div></body></html>";

        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    private String sessionToken(HttpServletRequest request) {
        if (request == null) return null;
        HttpSession s = request.getSession(false);
        if (s == null) return null;
        Object v = s.getAttribute(SESSION_CSRF_TOKEN);
        return v == null ? null : String.valueOf(v);
    }

    private String rotateSessionToken(HttpServletRequest request) {
        HttpSession s = request.getSession(true);
        String t = randomHex(16);
        s.setAttribute(SESSION_CSRF_TOKEN, t);
        return t;
    }

    private String randomHex(int bytes) {
        byte[] b = new byte[Math.max(1, bytes)];
        secureRandom.nextBytes(b);
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static String firstNonEmpty(String... xs) {
        if (xs == null) return "";
        for (String x : xs) {
            if (x == null) continue;
            String t = x.trim();
            if (!t.isEmpty()) return t;
        }
        return "";
    }

    private static boolean safeEquals(String a, String b) {
        if (a == null || b == null) return false;
        // constant-time-ish compare
        int n = Math.max(a.length(), b.length());
        int r = 0;
        for (int i = 0; i < n; i++) {
            char ca = i < a.length() ? a.charAt(i) : 0;
            char cb = i < b.length() ? b.charAt(i) : 0;
            r |= (ca ^ cb);
        }
        return r == 0 && a.length() == b.length();
    }

    private static String htmlEscape(String s) {
        if (s == null) return "";
        return s
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}

