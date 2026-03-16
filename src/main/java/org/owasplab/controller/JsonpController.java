package org.owasplab.controller;

import org.owasplab.entity.User;
import org.owasplab.repository.UserRepository;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/jsonp")
public class JsonpController {

    // 复用 CsrfController 中写入 session 的键名
    private static final String SESSION_USER_ID = "userId";

    private final UserRepository userRepository;

    public JsonpController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private static Long sessionUserId(HttpServletRequest request) {
        if (request == null) return null;
        HttpSession s = request.getSession(false);
        if (s == null) return null;
        Object v = s.getAttribute(SESSION_USER_ID);
        if (v instanceof Number) return ((Number) v).longValue();
        return null;
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }

    /**
     * VULN：不安全 JSONP
     * - 返回与当前登录 session 绑定的真实用户信息
     * - 任何来源都可以通过 callback 跨域获取
     */
    @GetMapping(value = "/userinfo-vuln", produces = MediaType.APPLICATION_JSON_VALUE)
    public String userInfoVuln(
            @RequestParam(name = "callback", required = false) String callback,
            HttpServletRequest request
    ) {
        Long uid = sessionUserId(request);
        if (uid == null) {
            String anon = "{\"error\":\"not_logged_in\"}";
            if (callback == null || callback.trim().isEmpty()) {
                return anon;
            }
            return callback.trim() + "(" + anon + ");";
        }

        Optional<User> opt = userRepository.findById(uid);
        if (!opt.isPresent()) {
            String err = "{\"error\":\"user_not_found\"}";
            if (callback == null || callback.trim().isEmpty()) {
                return err;
            }
            return callback.trim() + "(" + err + ");";
        }

        User u = opt.get();
        // 这里用 email / role，而不是不存在的 phone
        String json = String.format(
                "{\"uid\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\"}",
                u.getId(),
                escapeJson(u.getUsername()),
                escapeJson(u.getEmail()),
                escapeJson(u.getRole())
        );

        if (callback == null || callback.trim().isEmpty()) {
            // 没有 callback：返回纯 JSON，方便 curl/浏览器调试
            return json;
        }

        // VULN：不校验 callback，直接拼接 JSONP
        return callback.trim() + "(" + json + ");";
    }

    /**
     * SAFE：敏感数据接口不再支持 JSONP，只返回纯 JSON。
     */
    @GetMapping(value = "/userinfo-safe", produces = MediaType.APPLICATION_JSON_VALUE)
    public String userInfoSafe(HttpServletRequest request) {
        Long uid = sessionUserId(request);
        if (uid == null) {
            return "{\"error\":\"not_logged_in\"}";
        }
        Optional<User> opt = userRepository.findById(uid);
        if (!opt.isPresent()) {
            return "{\"error\":\"user_not_found\"}";
        }
        User u = opt.get();
        return String.format(
                "{\"uid\":%d,\"username\":\"%s\",\"email\":\"%s\",\"role\":\"%s\"}",
                u.getId(),
                escapeJson(u.getUsername()),
                escapeJson(u.getEmail()),
                escapeJson(u.getRole())
        );
    }

    /**
     * SAFE（演示安全使用 JSONP）：
     * - 仅返回公开数据
     * - 对 callback 做白名单校验
     */
    @GetMapping(value = "/public-news-jsonp", produces = MediaType.APPLICATION_JSON_VALUE)
    public String publicNewsJsonp(
            @RequestParam(name = "callback", required = false) String callback
    ) {
        String json = "{\"items\":[{\"title\":\"公开新闻 A\"},{\"title\":\"公开新闻 B\"}]}";

        if (callback == null || callback.trim().isEmpty()) {
            return json;
        }

        String trimmed = callback.trim();
        if (!trimmed.matches("^[A-Za-z0-9_\\.]{1,32}$")) {
            return json;
        }

        return trimmed + "(" + json + ");";
    }
}