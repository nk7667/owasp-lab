package org.owasplab.mapper;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.owasplab.entity.User;

import java.util.List;
import java.util.Map;

/**
 * SQL 注入靶场：VULN 用 ${} 拼接（可注入），SAFE 用 #{} 或白名单后拼接。
 * 数据库继续使用 H2，与 JPA 共用同一 DataSource。
 */
@Mapper
public interface SqliMapper {

    /** VULN：字符串拼接，存在注入。多行时 MyBatis 返回首行 */
    User selectUserByLoginVuln(@Param("username") String username, @Param("password") String password);

    /** SAFE：按用户名查，密码在 Java 侧用 PasswordEncoder 校验 */
    User selectUserByUsername(@Param("username") String username);

    /** VULN：id 拼接 */
    User selectUserByIdVuln(@Param("requestedId") String requestedId, @Param("scopeUserId") Long scopeUserId);

    /** SAFE：参数化 */
    User selectUserByIdSafe(@Param("requestedId") Long requestedId, @Param("scopeUserId") Long scopeUserId);

    /** VULN：ORDER BY 拼接 */
    List<Map<String, Object>> listUsersVuln(@Param("sortField") String sortField, @Param("sortOrder") String sortOrder);

    /** SAFE：列与排序方向已在 Java 白名单，仅传安全字符串 */
    List<Map<String, Object>> listUsersSafe(@Param("column") String column, @Param("direction") String direction);

    /** VULN：LIKE 拼接 */
    List<Map<String, Object>> newsUnionSearchVuln(@Param("q") String q);

    /** SAFE：LIKE 参数化（传入 "%" + q + "%"） */
    List<Map<String, Object>> newsUnionSearchSafe(@Param("searchQ") String searchQ);

    /** VULN：acctTsExpr 拼接进结构位 */
    List<Map<String, Object>> newsAdvSearchVuln(
            @Param("searchQ") String searchQ,
            @Param("safeTitleExpr") String safeTitleExpr,
            @Param("acctTsExpr") String acctTsExpr);

    /** SAFE：仅 safeTitleExpr（白名单）、searchQ 参数化 */
    List<Map<String, Object>> newsAdvSearchSafe(
            @Param("searchQ") String searchQ,
            @Param("safeTitleExpr") String safeTitleExpr);

    /** VULN：probe 拼接进 EXISTS */
    List<Map<String, Object>> newsBooleanProbeVuln(@Param("searchQ") String searchQ, @Param("probe") String probe);

    /** SAFE：visibility/column/direction 白名单，searchQ 参数化 */
    List<Map<String, Object>> newsBooleanProbeSafe(
            @Param("visibility") String visibility,
            @Param("searchQ") String searchQ,
            @Param("column") String column,
            @Param("direction") String direction);

    /** VULN：probe 拼接，用于时间盲注判断（返回 1/0） */
    Integer probeExistsVuln(@Param("probe") String probe);

    /** 公开新闻列表（参数化），供 SAFE 与回退使用 */
    List<Map<String, Object>> queryPublicNewsByTitleLike(@Param("searchQ") String searchQ);
}
