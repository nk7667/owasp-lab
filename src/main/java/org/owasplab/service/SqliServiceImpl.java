package org.owasplab.service;

import org.owasplab.entity.User;
import org.owasplab.mapper.SqliMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * SQL 注入靶场：全部通过 MyBatis 执行。
 * VULN 使用 XML 中 ${} 拼接（可注入），SAFE 使用 #{} 或 Java 白名单后传入安全字符串。
 */
@Service
public class SqliServiceImpl implements SqliService {

    private final SqliMapper sqliMapper;
    private final PasswordEncoder passwordEncoder;

    public SqliServiceImpl(SqliMapper sqliMapper, PasswordEncoder passwordEncoder) {
        this.sqliMapper = sqliMapper;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public User loginVuln(String username, String password) {
        return sqliMapper.selectUserByLoginVuln(username, password);
    }

    @Override
    public User loginSafe(String username, String password) {
        User u = sqliMapper.selectUserByUsername(username);
        if (u == null) return null;
        if (!passwordEncoder.matches(password, u.getPassword())) return null;
        return u;
    }

    @Override
    public User getUserByIdVuln(String requestedId, Long scopeUserId) {
        return sqliMapper.selectUserByIdVuln(requestedId, scopeUserId);
    }

    @Override
    public User getUserByIdSafe(Long requestedId, Long scopeUserId) {
        return sqliMapper.selectUserByIdSafe(requestedId, scopeUserId);
    }

    @Override
    public List<Map<String, Object>> listUsersVuln(String sortField, String sortOrder) {
        if (sortField == null || sortField.trim().isEmpty()) sortField = "id";
        if (sortOrder == null || sortOrder.trim().isEmpty()) sortOrder = "asc";
        List<Map<String, Object>> list = sqliMapper.listUsersVuln(sortField, sortOrder);
        return list != null ? list : Collections.emptyList();
    }

    @Override
    public List<Map<String, Object>> listUsersSafe(String sortField, String sortOrder) {
        String column = "id";
        if (sortField != null) {
            switch (sortField.trim()) {
                case "1": column = "id"; break;
                case "2": column = "username"; break;
                case "3": column = "email"; break;
                case "4": column = "role"; break;
                default: column = "id";
            }
        }
        String direction = "asc";
        if (sortOrder != null && "desc".equalsIgnoreCase(sortOrder.trim())) direction = "desc";
        List<Map<String, Object>> list = sqliMapper.listUsersSafe(column, direction);
        return list != null ? list : Collections.emptyList();
    }

    @Override
    public List<Map<String, Object>> newsUnionSearchVuln(String q) {
        if (q == null) q = "";
        List<Map<String, Object>> list = sqliMapper.newsUnionSearchVuln(q);
        return list != null ? list : Collections.emptyList();
    }

    @Override
    public List<Map<String, Object>> newsUnionSearchSafe(String q) {
        if (q == null) q = "";
        String searchQ = "%" + q + "%";
        List<Map<String, Object>> list = sqliMapper.newsUnionSearchSafe(searchQ);
        return list != null ? list : Collections.emptyList();
    }

    @Override
    public List<Map<String, Object>> newsAdvSearchVuln(String q, String titleMode, String acctTsExpr) {
        if (q == null) q = "";
        String safeTitleExpr = resolveTitleExprFromMode(titleMode);
        String tsExpr = (acctTsExpr == null || acctTsExpr.trim().isEmpty())
                ? "TIMESTAMP '2000-01-01 00:00:00'" : acctTsExpr.trim();
        String searchQ = "%" + q + "%";
        try {
            List<Map<String, Object>> list = sqliMapper.newsAdvSearchVuln(searchQ, safeTitleExpr, tsExpr);
            return list != null ? list : Collections.emptyList();
        } catch (Exception ignore) {
            return sqliMapper.queryPublicNewsByTitleLike(searchQ);
        }
    }

    @Override
    public List<Map<String, Object>> newsAdvSearchSafe(String q, String titleMode) {
        if (q == null) q = "";
        String safeTitleExpr = resolveTitleExprFromMode(titleMode);
        String searchQ = "%" + q + "%";
        List<Map<String, Object>> list = sqliMapper.newsAdvSearchSafe(searchQ, safeTitleExpr);
        return list != null ? list : Collections.emptyList();
    }

    @Override
    public List<Map<String, Object>> newsBooleanProbeVuln(String q, String probe) {
        if (q == null) q = "";
        if (probe == null) probe = "1=0";
        String searchQ = "%" + q + "%";
        try {
            List<Map<String, Object>> list = sqliMapper.newsBooleanProbeVuln(searchQ, probe);
            return list != null ? list : Collections.emptyList();
        } catch (Exception ignore) {
            return sqliMapper.queryPublicNewsByTitleLike(searchQ);
        }
    }

    @Override
    public List<Map<String, Object>> newsBooleanProbeSafe(String q, String sortField, String sortOrder, boolean isAdmin) {
        if (q == null) q = "";
        String visibility = isAdmin ? "1=1" : "is_public = true";
        String column = "created_at";
        if (sortField != null) {
            switch (sortField.trim().toLowerCase()) {
                case "created_at":
                case "createdat": column = "created_at"; break;
                case "title": column = "title"; break;
                case "id": column = "id"; break;
                default: column = "created_at";
            }
        }
        String direction = "desc";
        if (sortOrder != null && "asc".equalsIgnoreCase(sortOrder.trim())) direction = "asc";
        String searchQ = "%" + q + "%";
        try {
            List<Map<String, Object>> list = sqliMapper.newsBooleanProbeSafe(visibility, searchQ, column, direction);
            return list != null ? list : Collections.emptyList();
        } catch (Exception ignore) {
            return sqliMapper.queryPublicNewsByTitleLike(searchQ);
        }
    }

    @Override
    public List<Map<String, Object>> newsTimeProbeVuln(String q, String probe) {
        if (q == null) q = "";
        if (probe == null) probe = "1=0";
        boolean condTrue = false;
        try {
            Integer r = sqliMapper.probeExistsVuln(probe);
            condTrue = r != null && r == 1;
        } catch (Exception ignore) {
            condTrue = false;
        }
        if (condTrue) {
            try {
                Thread.sleep(1200);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        }
        String searchQ = "%" + q + "%";
        try {
            List<Map<String, Object>> list = sqliMapper.queryPublicNewsByTitleLike(searchQ);
            return list != null ? list : Collections.emptyList();
        } catch (Exception ignore) {
            return Collections.emptyList();
        }
    }

    @Override
    public List<Map<String, Object>> newsTimeProbeSafe(String q) {
        if (q == null) q = "";
        String searchQ = "%" + q + "%";
        List<Map<String, Object>> list = sqliMapper.queryPublicNewsByTitleLike(searchQ);
        return list != null ? list : Collections.emptyList();
    }

    private static String resolveTitleExprFromMode(String titleMode) {
        if (titleMode == null) return "title";
        switch (titleMode.trim().toLowerCase()) {
            case "raw":
            case "title": return "title";
            case "lower": return "LOWER(title)";
            case "upper": return "UPPER(title)";
            default: return "title";
        }
    }
}
