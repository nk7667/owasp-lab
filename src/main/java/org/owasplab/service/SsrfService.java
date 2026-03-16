package org.owasplab.service;

import org.owasplab.core.Mode;

import java.util.Map;

/**
 * SSRF 靶场服务：URL 获取等，支持 VULN / WEAK / SAFE 三种模式及多级 WEAK。
 */
public interface SsrfService {

    /**
     * 请求用户指定的 URL 并返回响应摘要。
     * @param mode      VULN=无校验, WEAK=弱过滤, SAFE=白名单+IP 黑名单
     * @param url       用户输入的 URL
     * @param weakLevel WEAK 模式下的过滤等级 1–5
     * @return 包含 requested_url, status_code, response_body/error, blocked_reason 等
     */
    Map<String, Object> fetchUrl(Mode mode, String url, int weakLevel);

    /*** 图片代理场景：后端代表前端去抓取图片。*/
    Map<String, Object> proxyImage(Mode mode, String imageUrl, int weakLevel);

    /*** 文件下载场景：后端根据用户给出的 URL 对文件进行探测。*/
    Map<String, Object> downloadFile(Mode mode, String fileUrl, int weakLevel);
}
