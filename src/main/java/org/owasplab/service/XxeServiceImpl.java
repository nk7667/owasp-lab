package org.owasplab.service;

import org.springframework.stereotype.Service;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;

@Service
public class XxeServiceImpl implements XxeService {

    @Override
    public Map<String, Object> parseVuln(String xmlContent) {
        Map<String, Object> result = new HashMap<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            //  不安全：默认配置
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                    new InputSource(new StringReader(xmlContent))
            );
            String name = getDomText(doc, "name");
            String email = getDomText(doc, "email");
            result.put("parser", "vulnerableDocumentBuilder");
            result.put("name", name);
            result.put("email", email);
            result.put("success", true);
        } catch (Exception e) {
            result.put("parser", "vulnerableDocumentBuilder");
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    @Override
    public Map<String, Object> parseSafe(String xmlContent) {
        Map<String, Object> result = new HashMap<>();
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // 安全配置
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                    new InputSource(new StringReader(xmlContent))
            );
            String name = getDomText(doc, "name");
            String email = getDomText(doc, "email");
            result.put("parser", "safeDocumentBuilder");
            result.put("name", name);
            result.put("email", email);
            result.put("success", true);
        } catch (Exception e) {
            result.put("parser", "safeDocumentBuilder");
            result.put("success", false);
            result.put("error", e.getMessage());
        }
        return result;
    }

    @Override
    public Map<String, Object> getInfo() {
        Map<String, Object> result = new HashMap<>();
        // 简要说明与分类，配合前端 XxeLab.jsx 的 info 卡片
        result.put("description", "XXE（XML External Entity）利用解析器对外部实体的支持，在解析 XML 时访问 file:// 或 http(s):// 等 URI，从而实现文件读取、SSRF 或拒绝服务（DoS）。本关基于 JAXP DocumentBuilderFactory，对比 VULN 默认配置与 SAFE 显式禁用 DTD/外部实体的差异。");

        Map<String, Object> attackTypes = new HashMap<>();
        attackTypes.put("file_read", "通过 SYSTEM \"file:///path\" 实体把服务器本地文件内容注入到 XML 节点中，例如 &xxe; 出现在 <name> 或 <email> 中。");
        attackTypes.put("ssrf", "通过 SYSTEM \"http://host:port/path\" 让解析器在服务器侧主动发起 HTTP/HTTPS 请求，可打内网服务或模拟云元数据端点。");
        attackTypes.put("dos", "通过 Billion Laughs 等递归实体膨胀攻击占用大量 CPU/内存，造成拒绝服务。");
        result.put("attack_types", attackTypes);

        Map<String, String> payloads = new HashMap<>();
        payloads.put("file_read",
                "<?xml version=\"1.0\"?>\n" +
                "<!DOCTYPE note [\n" +
                "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n" +
                "]>\n" +
                "<user>\n" +
                "  <name>&xxe;</name>\n" +
                "  <email>test@example.com</email>\n" +
                "</user>");
        payloads.put("ssrf",
                "<?xml version=\"1.0\"?>\n" +
                "<!DOCTYPE note [\n" +
                "  <!ENTITY xxe SYSTEM \"http://127.0.0.1:8081/api/v1/ssrf/internal/metadata\">\n" +
                "]>\n" +
                "<user>\n" +
                "  <name>&xxe;</name>\n" +
                "  <email>test@example.com</email>\n" +
                "</user>");
        payloads.put("billion_laughs",
                "<?xml version=\"1.0\"?>\n" +
                "<!DOCTYPE lolz [\n" +
                "  <!ENTITY lol \"lol\">\n" +
                "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">\n" +
                "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;\">\n" +
                "]>\n" +
                "<data>&lol3;</data>");
        result.put("test_payloads", payloads);

        return result;
    }

    private String getDomText(org.w3c.dom.Document doc, String tagName) {
        NodeList list = doc.getElementsByTagName(tagName);
        if (list.getLength() == 0) return null;
        return list.item(0).getTextContent();
    }
}