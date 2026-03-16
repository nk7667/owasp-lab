package org.owasplab.controller;

import org.owasplab.core.ApiMeta;
import org.owasplab.core.ApiResponse;
import org.owasplab.core.Mode;
import org.owasplab.core.SignalChannel;
import org.owasplab.dto.LoginRequest;
import org.owasplab.entity.User;
import org.owasplab.security.LoginLockService;
import org.owasplab.service.SqliService;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import javax.servlet.http.HttpSession;
import static org.owasplab.core.ApiResponse.ok;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
@RestController
@RequestMapping("/api/v1/sqli")
public class SqliController {

    private final SqliService sqliService;
    private static final Logger log = LoggerFactory.getLogger(SqliController.class);
    public SqliController(SqliService sqliService, LoginLockService loginLockService) {
        this.sqliService = sqliService;
        this.loginLockService = loginLockService;
    }
    private static final Long DEFAULT_SCOPE_USER_ID = 2L;

    private static ApiMeta vulnMeta(SignalChannel ch, String context) {
        return new ApiMeta("sqli", Mode.VULN, Arrays.asList("coding_sast", "testing_dast"), ch, "CWE-89", context);
    }
    private static ApiMeta safeMeta(SignalChannel ch, String context) {
        return new ApiMeta("sqli", Mode.SAFE, Arrays.asList("coding_sast", "testing_dast"), ch, "CWE-89", context);
    }
    private static Map<String, Object> toUserData(User user) {
        Map<String, Object> data = new HashMap<>();
        data.put("username", user.getUsername());
        data.put("email", user.getEmail());
        data.put("role", user.getRole());
        return data;
    }
    private static void attachSessionUser(HttpServletRequest request, User user) {
        HttpSession session = request.getSession(true);
        session.setAttribute("userId", user.getId());
        session.setAttribute("username", user.getUsername());
        session.setAttribute("role", user.getRole());
    }
    private static Map<String, Object> toUserDetailData(User user) {
        Map<String, Object> data = new HashMap<>();
        data.put("id", user.getId());
        data.put("username", user.getUsername());
        data.put("email", user.getEmail());
        data.put("role", user.getRole());
        return data;
    }
    private static Map<String, Object> wrapDebug(Map<String, Object> debug) {
        Map<String, Object> data = new HashMap<>();
        data.put("debug", debug);
        return data;
    }
    // 用户列表回显字段：id/username/email/role（用于 ORDER BY 关卡的“排序可视化”）
    private final LoginLockService loginLockService;
    private static String safeLogValue(String s) {
        if (s == null) return "null";
        return s.replace("\n", "\\n").replace("\r", "\\r");
    }

    @PostMapping("/vuln/login")
    public ApiResponse<Map<String, Object>> vulnLogin(@RequestBody LoginRequest req,HttpServletRequest request) {
        String ctx = "where_login_bypass";
        String username = req.getUsername();
        String logUsername = safeLogValue(username);
        String ip = request.getRemoteAddr();
        try {
            ApiMeta meta = vulnMeta(SignalChannel.inband, ctx);
            User user = sqliService.loginVuln(username, req.getPassword());
            if (user == null) {
                log.warn("AUTH_LOGIN_FAIL mode=VULN ctx={} username={} ip={}", ctx, logUsername, ip);
                return ApiResponse.fail("登陆失败", meta);
            }
            attachSessionUser(request, user);
            Map<String, Object> data = toUserData(user);
            log.info("AUTH_LOGIN_SUCCESS mode=VULN ctx={} username={} ip={}", ctx, logUsername, ip);
            return ApiResponse.ok(data, meta);

        } catch (Exception e) {

            Map<String, Object> debug = new HashMap<>();
            debug.put("sql",
                    "SELECT * FROM users WHERE username ='" + req.getUsername()
                            + "' AND password ='" + req.getPassword() + "'"
            );
            Map<String, Object> data = new HashMap<>();
            data.put("debug", debug);
            log.error("AUTH_LOGIN_ERROR mode=VULN ctx={} username={} ip={} ex={}",
                    ctx, logUsername, ip, e.getClass().getName());
            return ApiResponse.fail("SQL 执行失败: " + e.getMessage(), data, vulnMeta(SignalChannel.error_based, ctx));
        }
    }

    @PostMapping("/safe/login")
    public ApiResponse<Map<String, Object>> safeLogin(@RequestBody LoginRequest req,HttpServletRequest request) {
        String ctx = "where_login_bypass";
        try{

            ApiMeta meta = safeMeta(SignalChannel.inband, ctx);
            String username = req.getUsername();
            String logUsername =safeLogValue(username);
            String ip =request.getRemoteAddr();

            if (loginLockService.isLocked(username)) {
                Map<String, Object> debug = new HashMap<>();
                debug.put("locked", true);
                debug.put("retryAfterSeconds", loginLockService.retryAfterSeconds(username));
                debug.put("failCount", loginLockService.getFailCount(username));
                // 对外 message 仍然统一“登陆失败”，避免账号枚举
                log.warn("AUTH_LOGIN_LOCKED mode=SAFE ctx={} logUsername={} ip={}", ctx, logUsername, ip);
                return ApiResponse.fail("登陆失败", wrapDebug(debug), meta);
            }
            User user = sqliService.loginSafe(username, req.getPassword());
            if (user == null) {
                int failCount = loginLockService.onFailure(username);
                Map<String,Object>debug=new HashMap<>();
                debug.put("failCount", failCount);
                debug.put("locked", loginLockService.isLocked(username));
                debug.put("retryAfterSeconds", loginLockService.retryAfterSeconds(username));
                log.warn("AUTH_LOGIN_FAIL mode=SAFE ctx={} logUsername={} ip={}", ctx, logUsername, ip);
                return ApiResponse.fail("登陆失败", wrapDebug(debug), meta);
            }
            loginLockService.onSuccess(username);
            attachSessionUser(request, user);
            Map<String, Object> data = toUserData(user);
            log.info("AUTH_LOGIN_SUCCESS mode=SAFE ctx={} username={} ip={}", ctx, logUsername, ip);
            return ApiResponse.ok(data, meta);
        }catch (Exception e) {
            Map<String, Object> debug = new HashMap<>();
            debug.put("sqlTemplate", "SELECT * FROM users WHERE username = ?1");
            Map<String, Object> params = new HashMap<>();
            params.put("username", req.getUsername());
            params.put("password", "<redacted>");
            params.put("passwordLength", req.getPassword() == null ? 0 : req.getPassword().length());
            debug.put("params", params);

            return ApiResponse.fail("SQL 执行失败", wrapDebug(debug), safeMeta(SignalChannel.error_based, ctx));
        }
    }

    @GetMapping("/vuln/users/detail")
    public ApiResponse<Map<String, Object>> getUserVuln(
        @RequestParam String id,
        @RequestHeader(value = "X-User-Id", required = false) Long scopeUserId) {

    Long scope = (scopeUserId == null ? DEFAULT_SCOPE_USER_ID : scopeUserId);
    String ctx = "where_id_authz";

    try {
        ApiMeta meta = vulnMeta(SignalChannel.inband, ctx);
        User user = sqliService.getUserByIdVuln(id, scope);
        if (user == null) return ApiResponse.fail("not found", meta);

        Map<String, Object> data = toUserDetailData(user);

        Map<String, Object> debug = new HashMap<>();
        debug.put("sql", "SELECT * FROM users WHERE id = " + id + " AND id = " + scope);
        debug.put("scopeUserId", scope);
        data.put("debug", debug);

        return ok(data, meta);
    } catch (Exception e) {
        Map<String, Object> debug = new HashMap<>();
        debug.put("sql", "SELECT * FROM users WHERE id = " + id + " AND id = " + scope);
        debug.put("scopeUserId", scope);
        Map<String, Object> data = new HashMap<>();
        data.put("debug", debug);
        return ApiResponse.fail("SQL 执行失败: " + e.getMessage(), data, vulnMeta(SignalChannel.error_based, ctx));
    }
    }

    @GetMapping("/safe/users/detail")
    public ApiResponse<Map<String, Object>> getUserSafe(
        @RequestParam Long id,
        @RequestHeader(value = "X-User-Id", required = false) Long scopeUserId) {

    Long scope = (scopeUserId == null ? DEFAULT_SCOPE_USER_ID : scopeUserId);
    String ctx = "where_id_authz";

    // SAFE：先做业务鉴权（只能查自己）
    if (!scope.equals(id)) {
        return ApiResponse.fail("forbidden: only self is allowed (scopeUserId=" + scope + ")", safeMeta(SignalChannel.inband, ctx));
    }

    try {
        ApiMeta meta = safeMeta(SignalChannel.inband, ctx);
        User user = sqliService.getUserByIdSafe(id, scope);
        if (user == null) return ApiResponse.fail("not found", meta);

        Map<String, Object> data = toUserDetailData(user);
        Map<String, Object> debug = new HashMap<>();
        debug.put("sqlTemplate", "SELECT * FROM users WHERE id = ?1 AND id = ?2");

        Map<String, Object> params = new HashMap<>();
        params.put("requestedId", id);
        params.put("scopeUserId", scope);
        debug.put("params", params);

        data.put("debug", debug);

        return ok(data, meta);

    } catch (Exception e) {
        Map<String, Object> debug = new HashMap<>();
        debug.put("sqlTemplate", "SELECT * FROM users WHERE id = ?1 AND id = ?2");
        Map<String, Object> params = new HashMap<>();
        params.put("requestedId", id);
        params.put("scopeUserId", scope);
        debug.put("params", params);
        return ApiResponse.fail("SQL 执行失败", wrapDebug(debug), safeMeta(SignalChannel.error_based, ctx));
    }
    }

    @GetMapping("/vuln/users/list")
    public ApiResponse<Map<String, Object>> listUsersVuln(
            @RequestParam(required = false, defaultValue = "id") String sortField,
            @RequestParam(required = false, defaultValue = "asc") String sortOrder) {
        String ctx = "order_by_limit";
        try {
            List<Map<String,Object>> items = sqliService.listUsersVuln(sortField, sortOrder);
            Map<String, Object> debug = new HashMap<>();
            Map<String, Object> data = new HashMap<>();

            debug.put("sql", "SELECT id, username, email, role FROM users WHERE role = 'user' ORDER BY " + sortField + " " + sortOrder + " LIMIT 3");
            data.put("items", items);
            data.put("debug", debug);

            return ok(data, vulnMeta(SignalChannel.inband, ctx));
        } catch (Exception e) {
            Map<String, Object> debug = new HashMap<>();
            debug.put("sql", "SELECT id, username, email, role FROM users WHERE role = 'user' ORDER BY " + sortField + " " + sortOrder + " LIMIT 3");
            Map<String, Object> data = new HashMap<>();
            data.put("debug", debug);
            return ApiResponse.fail("SQL 执行失败: " + e.getMessage(), data, vulnMeta(SignalChannel.error_based, ctx));
        }
    }

    @GetMapping("/safe/users/list")
    public ApiResponse<Map<String, Object>> listUsersSafe(
            @RequestParam(required = false, defaultValue = "1") String sortField,
            @RequestParam(required = false, defaultValue = "asc") String sortOrder) {
        String ctx = "order_by_limit";
        try {
            List<Map<String,Object>> items = sqliService.listUsersSafe(sortField, sortOrder);

            Map<String, Object> debug = new HashMap<>();
            Map<String, Object> data = new HashMap<>();
            debug.put("sqlTemplate", "SELECT * FROM users WHERE role='user' ORDER BY <whitelist_column> <whitelist_direction> LIMIT 3");
            debug.put("sortField", sortField);
            debug.put("sortOrder", sortOrder);
            data.put("items", items);
            data.put("debug", debug);
            return ok(data, safeMeta(SignalChannel.inband, ctx));
        } catch (Exception e) {
            Map<String, Object> debug = new HashMap<>();
            debug.put("sqlTemplate", "SELECT * FROM users WHERE role='user' ORDER BY <whitelist_column> <whitelist_direction> LIMIT 3");
            debug.put("sortField", sortField);
            debug.put("sortOrder", sortOrder);
            Map<String, Object> data = new HashMap<>();
            data.put("debug", debug);
            return ApiResponse.fail("SQL 执行失败", data, safeMeta(SignalChannel.error_based, ctx));
        }
    }
    /** 新闻嵌套关卡：UNION 跨表回显 */
    @GetMapping("/vuln/news/union/search")
    public ApiResponse<Map<String, Object>> vulnNewsUnionSearch(
            @RequestParam(required = false,defaultValue = "")String q
    ){
        String ctx ="news_union_users";
        ApiMeta meta =vulnMeta(SignalChannel.inband,ctx);

        Map<String,Object> data =new HashMap<>();
        try{
            // 不返回错误细节
            List<Map<String,Object>> items =sqliService.newsUnionSearchVuln(q);
            data.put("items",items);
            data.put("count", items ==null ?0 : items.size());
            return ApiResponse.ok(data,meta);
        }catch (Exception ignore){
            String logQ = safeLogValue(q);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            log.info("[news_union_users] swallow error (vuln). q='{}', ex={}", logQ, ignore.toString());
            // 吞错 + 固定结构 + 200
            data.put("items", Collections.emptyList());
            data.put("count", 0);
            return  ApiResponse.ok(data,meta);
        }
    }
    @GetMapping("/safe/news/union/search")
    public ApiResponse<Map<String, Object>> safeNewsUnionSearch(
            @RequestParam(required = false, defaultValue = "") String q
    ) {
        String ctx = "news_union_users";
        ApiMeta meta = safeMeta(SignalChannel.inband, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsUnionSearchSafe(q);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ApiResponse.ok(data, meta);
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            log.info("[news_union_users] swallow error (safe). q='{}', ex={}", logQ, ignore.toString());
            // 同样吞错，避免多余信号
            data.put("items", Collections.emptyList());
            data.put("count", 0);
            return ApiResponse.ok(data, meta);
        }
    }

    /** 新闻搜索（难度2）：结构位表达式注入（titleExpr），q 参数化 */
    @GetMapping("/vuln/news/adv/search")
    public ApiResponse<Map<String, Object>> vulnNewsAdvSearch(
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "raw") String titleMode,
            @RequestParam(required = false) String titleExpr
    ) {
        String ctx = "news_adv_func_view";
        ApiMeta meta = vulnMeta(SignalChannel.inband, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsAdvSearchVuln(q, titleMode, titleExpr);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ApiResponse.ok(data, meta);
        } catch (Exception ignore) {
            // 吞错 + 固定结构 + 200（前端不显式提示，抓包/日志排查）
            String logQ = safeLogValue(q);
            String logMode = safeLogValue(titleMode);
            String logExpr = safeLogValue(titleExpr);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            if (logMode.length() > 200) logMode = logMode.substring(0, 200) + "...";
            if (logExpr.length() > 200) logExpr = logExpr.substring(0, 200) + "...";
            log.info("[news_adv_func_view] swallow error (vuln). q='{}', titleMode='{}', titleExpr='{}', ex={}",
                    logQ, logMode, logExpr, ignore.toString());

            data.put("items", Collections.emptyList());
            data.put("count", 0);
            return ApiResponse.ok(data, meta);
        }
    }

    /** 新闻搜索（难度2 SAFE）：q 参数化；titleMode 白名单映射；不接收任意 titleExpr */
    @GetMapping("/safe/news/adv/search")
    public ApiResponse<Map<String, Object>> safeNewsAdvSearch(
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "raw") String titleMode
    ) {
        String ctx = "news_adv_func_view";
        ApiMeta meta = safeMeta(SignalChannel.inband, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsAdvSearchSafe(q, titleMode);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ApiResponse.ok(data, meta);
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            String logMode = safeLogValue(titleMode);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            if (logMode.length() > 200) logMode = logMode.substring(0, 200) + "...";
            log.info("[news_adv_func_view] swallow error (safe). q='{}', titleMode='{}', ex={}",
                    logQ, logMode, ignore.toString());

            data.put("items", Collections.emptyList());
            data.put("count", 0);
            return ApiResponse.ok(data, meta);
        }
    }
    @GetMapping("/vuln/news/boolean/probe")
    public ResponseEntity<ApiResponse<Map<String, Object>>> vulnNewsBooleanProbe(
            @RequestParam(required = false, defaultValue = "") String q, 
            @RequestParam(required = false, defaultValue = "1=0") String filterExpr,
            HttpServletRequest request
    ) {
        String ctx = "news_boolean_users_probe";
        ApiMeta meta = vulnMeta(SignalChannel.blind_boolean, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsBooleanProbeVuln(q, filterExpr);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            String logProbe = safeLogValue(filterExpr);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            if (logProbe.length() > 200) logProbe = logProbe.substring(0, 200) + "...";
            log.info("[news_boolean_users_probe] swallow error (vuln). q='{}', probe='{}', ex={}", logQ, logProbe, ignore.toString());

            List<Map<String, Object>> baseItems = sqliService.newsTimeProbeSafe(q);
            data.put("items", baseItems);
            data.put("count", baseItems == null ? 0 : baseItems.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        }
    }
    @GetMapping("/safe/news/boolean/probe")
    public ResponseEntity<ApiResponse<Map<String, Object>>> safeNewsBooleanProbe(
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "created_at") String sortField,
            @RequestParam(required = false, defaultValue = "desc") String sortOrder,
            HttpServletRequest request
    ) {
        String ctx = "news_boolean_users_probe";
        ApiMeta meta = safeMeta(SignalChannel.blind_boolean, ctx);

        // 生产语义：草稿可见性只由会话角色决定
        HttpSession session = request == null ? null : request.getSession(false);
        String role = session == null ? null : (String) session.getAttribute("role");
        boolean isAdmin = role != null && "admin".equalsIgnoreCase(role.trim());

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsBooleanProbeSafe(q, sortField, sortOrder, isAdmin);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            String logKey = safeLogValue(sortField);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            if (logKey.length() > 200) logKey = logKey.substring(0, 200) + "...";
            log.info("[news_boolean_users_probe] swallow error (safe). q='{}', probeKey='{}', ex={}", logQ, logKey, ignore.toString());

            List<Map<String, Object>> baseItems = sqliService.newsTimeProbeSafe(q);
            data.put("items", baseItems);
            data.put("count", baseItems == null ? 0 : baseItems.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        }
    }
    @GetMapping("/vuln/news/time/probe")
    public ResponseEntity<ApiResponse<Map<String, Object>>> vulnNewsTimeProbe(
            @RequestParam(required = false, defaultValue = "") String q,
            @RequestParam(required = false, defaultValue = "1=0") String filterExpr,
            HttpServletRequest request
    ) {
        String ctx = "news_time_users_probe";
        ApiMeta meta = vulnMeta(SignalChannel.time_based, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsTimeProbeVuln(q, filterExpr);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            String logProbe = safeLogValue(filterExpr);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            if (logProbe.length() > 200) logProbe = logProbe.substring(0, 200) + "...";
            log.info("[news_time_users_probe] swallow error (vuln). q='{}', probe='{}', ex={}", logQ, logProbe, ignore.toString());

            List<Map<String, Object>> baseItems = sqliService.newsTimeProbeSafe(q);
            data.put("items", baseItems);
            data.put("count", baseItems == null ? 0 : baseItems.size());
            return ResponseEntity.ok(ApiResponse.ok(data, meta));
        }
    }
    @GetMapping("/safe/news/time/probe")
    public ApiResponse<Map<String, Object>> safeNewsTimeProbe(
            @RequestParam(required = false, defaultValue = "") String q
    ) {
        String ctx = "news_time_users_probe";
        ApiMeta meta = safeMeta(SignalChannel.time_based, ctx);

        Map<String, Object> data = new HashMap<>();
        try {
            List<Map<String, Object>> items = sqliService.newsTimeProbeSafe(q);
            data.put("items", items);
            data.put("count", items == null ? 0 : items.size());
            return ApiResponse.ok(data, meta);
        } catch (Exception ignore) {
            String logQ = safeLogValue(q);
            if (logQ.length() > 200) logQ = logQ.substring(0, 200) + "...";
            log.info("[news_time_users_probe] swallow error (safe). q='{}', ex={}", logQ, ignore.toString());

            List<Map<String, Object>> baseItems = sqliService.newsTimeProbeSafe(q);
            data.put("items", baseItems);
            data.put("count", baseItems == null ? 0 : baseItems.size());
            return ApiResponse.ok(data, meta);
        }
    }
}
