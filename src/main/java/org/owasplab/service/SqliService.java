package org.owasplab.service;

import org.owasplab.entity.User;

import java.util.Map;
import java.util.List;

public interface SqliService {
    /*** 登录关卡，使用字符串拼接 SQL，存在注入、参数化查询或 Repository*/
    User loginVuln(String username, String password);
    User loginSafe(String username, String password);
    /*** id关卡，使用字符串拼接 SQL，存在注入、参数化查询或 Repository*/
    User getUserByIdVuln(String requestedId, Long scopeUserId);
    User getUserByIdSafe(Long requestedId, Long scopeUserId);
    /*** orderby关卡：排序参数直接拼进 ORDER BY，存在注入。sortField/sortOrder 白名单映射，不拼进 SQL。*/
    List<Map<String, Object>> listUsersVuln(String sortField, String sortOrder);
    List<Map<String, Object>> listUsersSafe(String sortField, String sortOrder);
    /** 新闻嵌套关卡：UNION 跨表回显 */
    List<Map<String, Object>> newsUnionSearchVuln(String q);
    List<Map<String, Object>> newsUnionSearchSafe(String q);
    /** 新闻搜索（难度2）：q 参数化；VULN 允许 titleExpr 进入 SELECT 结构位；titleMode 白名单映射 */
    List<Map<String, Object>> newsAdvSearchVuln(String q, String titleMode, String acctTsExpr);
    List<Map<String, Object>> newsAdvSearchSafe(String q, String titleMode);
    /** 新闻布尔盲注：q 参数化VULN 直拼 probe 进 EXISTS(users) 形成 one-bit 信号 vs sortField/sortOrder 白名单（结构位收回）
     * - 草稿可见性由服务端session决定 */
    List<Map<String, Object>> newsBooleanProbeVuln(String q, String probe);
    List<Map<String, Object>> newsBooleanProbeSafe(String q, String sortField, String sortOrder, boolean isAdmin);
    /** 新闻（时间盲注）：q 参数化；VULN 直拼 probe真时触发 CALL SLEEP(ms) ；不接收任意 probe；禁止用户驱动延迟 */
    List<Map<String, Object>> newsTimeProbeVuln(String q, String probe);
    List<Map<String, Object>> newsTimeProbeSafe(String q);
}
