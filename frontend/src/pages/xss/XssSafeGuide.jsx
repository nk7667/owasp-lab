import { Card, Col, Row, Typography, Tag, Collapse } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

export default function XssSafeGuide() {
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <SafetyCertificateOutlined /> XSS SAFE 实现总览
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        本页结合靶场现有代码，总结反射型 / 存储型 / DOM 型 XSS 在 SAFE 模式下是如何修复的。
        重点不是“多做几层替换”，而是：<Text strong style={{ color: '#e6edf3' }}>识别上下文（HTML / 属性 / JS / URL）+ 选对安全 API</Text>。
      </Paragraph>

      <Row gutter={16}>
        <Col xs={24} lg={12}>
          <Card
            title="反射型 · 搜索页（XssReflected）"
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', marginBottom: 16 }}
          >
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13 }}>
              搜索结果 SAFE 的核心在 <Text code>Mode.SAFE</Text> 分支下，针对不同上下文做不同处理：
            </Paragraph>
            <ul style={{ color: '#c6d3e5', fontSize: 13, paddingLeft: 18 }}>
              <li>
                <Text strong>HTML 文本（高亮/空状态）</Text>：
                使用 <Text code>HtmlUtils.htmlEscape(rawQ)</Text> 将搜索词做 HTML 实体编码，再拼进模板：
              </li>
            </ul>
            <pre style={{ background: '#0b1020', color: '#c6d3e5', padding: 10, borderRadius: 8, fontSize: 12 }}>
{`// SAFE：HTML 内容上下文
String safeHtml = HtmlUtils.htmlEscape(rawQ);
highlightHtml = "<mark>" + safeHtml + "</mark>";
emptyStateHtml = "未找到与 <b>" + safeHtml + "</b> 相关的结果";`}
            </pre>
            <ul style={{ color: '#c6d3e5', fontSize: 13, paddingLeft: 18, marginTop: 8 }}>
              <li>
                <Text strong>URL / href</Text>：
                先用 <Text code>urlEncodeQuery</Text> 编码参数，再通过 <Text code>allowHttpUrlOrHash</Text> 做协议白名单（仅 http/https），否则降级为
                <Text code>#</Text>：
              </li>
            </ul>
            <pre style={{ background: '#0b1020', color: '#c6d3e5', padding: 10, borderRadius: 8, fontSize: 12 }}>
{`String candidate = "https://intra.example.local/search?q=" + urlEncodeQuery(rawQ);
shareHref = allowHttpUrlOrHash(candidate);`}
            </pre>
            <ul style={{ color: '#c6d3e5', fontSize: 13, paddingLeft: 18, marginTop: 8 }}>
              <li>
                <Text strong>JS 字符串</Text>：
                使用 <Text code>escapeJsString</Text> 对反斜杠/引号/换行做 JS string escaping，构造埋点配置：
              </li>
            </ul>
            <pre style={{ background: '#0b1020', color: '#c6d3e5', padding: 10, borderRadius: 8, fontSize: 12 }}>
{`String safeJs = escapeJsString(rawQ);
analyticsConfigJs = "{ \\"event\\\": \\"search\\", \\"q\\\": \\"" + safeJs + "\\" }";`}
            </pre>
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13, marginTop: 8 }}>
              对照 VULN：直接把 <Text code>rawQ</Text> 拼进 HTML/URL/JS；SAFE 版本则分别用
              <Text code>HtmlUtils.htmlEscape</Text>、<Text code>allowHttpUrlOrHash</Text>、<Text code>escapeJsString</Text> 对应不同上下文。
            </Paragraph>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card
            title="存储型 · 评论 & 管理页（XssStored）"
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', marginBottom: 16 }}
          >
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13 }}>
              评论入库时保留原文，SAFE 只体现在<strong>渲染路径</strong>：<Text code>renderCommentForMode</Text>。
            </Paragraph>
            <pre style={{ background: '#0b1020', color: '#c6d3e5', padding: 10, borderRadius: 8, fontSize: 12 }}>
{`if (mode == Mode.SAFE) {
    renderedAuthor = HtmlUtils.htmlEscape(author);
    renderedContent = HtmlUtils.htmlEscape(content);
    renderedWebsiteHref = allowHttpUrlOrHash(website);
} else if (mode == Mode.WEAK) {
    // 弱修复示例...
} else {
    // VULN：原样输出
}`}
            </pre>
            <ul style={{ color: '#c6d3e5', fontSize: 13, paddingLeft: 18, marginTop: 8 }}>
              <li>
                评论内容 / 昵称：统一走 <Text code>HtmlUtils.htmlEscape</Text>，前端用 <Text code>innerHTML</Text> 渲染也安全，因为输入已经被当成文本。
              </li>
              <li>
                个人主页链接：通过 <Text code>allowHttpUrlOrHash</Text> 只保留 http/https，其他协议（如
                <Text code>javascript:</Text>/<Text code>data:</Text>) 一律退化成 <Text code>#</Text>。
              </li>
            </ul>
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13, marginTop: 8 }}>
              管理员审核页前端在 SAFE 模式下，还会用 DOM API 再走一遍协议白名单（<Text code>new URL()</Text> + protocol 检查），而不是直接信任
              <Text code>href</Text> 字符串。
            </Paragraph>
          </Card>
        </Col>
      </Row>

      <Row gutter={16}>
        <Col xs={24} lg={12}>
          <Card
            title="Blind Profile · 后台预览（XssController.profileAdminView）"
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', marginBottom: 16 }}
          >
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13 }}>
              盲打 Profile 的 SAFE 逻辑体现在后端直出 HTML 页面时，对昵称和 bio 的处理：
            </Paragraph>
            <pre style={{ background: '#0b1020', color: '#c6d3e5', padding: 10, borderRadius: 8, fontSize: 12 }}>
{`String renderedBio;
if (m == Mode.SAFE) {
    renderedBio = htmlEscape(bioRaw);
} else {
    renderedBio = bioRaw == null ? "" : bioRaw;
}

String safeNickname = htmlEscape(nickname);
String safeCreatedAt = htmlEscape(...);`}
            </pre>
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13, marginTop: 8 }}>
              这里的 <Text code>htmlEscape</Text> 是控制器里自定义的完整 HTML 编码（包含单引号），确保服务端模板里的
              <Text code>renderedBio</Text>/<Text code>safeNickname</Text> 都只会作为文本挂在页面上。
            </Paragraph>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card
            title="DOM XSS · SAFE 总结（XssDom）"
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', marginBottom: 16 }}
          >
            <Paragraph style={{ color: '#8b9cb3', fontSize: 13 }}>
              DOM 场景下，SAFE 的关键不在后端，而在前端 JS 的「信任边界 + sink 替换」：
            </Paragraph>
            <ul style={{ color: '#c6d3e5', fontSize: 13, paddingLeft: 18 }}>
              <li>
                PostMessage Lab 中 SAFE 模式：
                <Text code>e.origin === window.location.origin</Text> +
                <Text code>e.source === iframe.contentWindow</Text> +
                <Text code>out.textContent = ...</Text>（不再用 <Text code>innerHTML</Text>）。
              </li>
              <li>
                CSP + JSONP Lab 中 SAFE 模式：callback 收敛为固定 <Text code>cb</Text>，不允许任意函数名，避免“把数据当代码”。
              </li>
              <li>
                Canonical Lab 中 SAFE 模式：不拼不可信 query；属性值使用完整 <Text code>htmlAttrEscapeAllQuotes</Text>，避免单引号逃逸。
              </li>
            </ul>
            <Collapse
              size="small"
              style={{ marginTop: 8, background: '#0b1020', border: '1px solid #2d3a4d' }}
              items={[
                {
                  key: 'dom-safe',
                  label: '一句话 SAFE 模板',
                  children: (
                    <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.7 }}>
                      <div>
                        1）<Text strong>只信任对的来源</Text>：origin / source / callback 等做白名单校验；
                      </div>
                      <div>
                        2）<Text strong>用对的 sink</Text>：大部分场景用 textContent / setAttribute / 安全 URL API，避免 innerHTML/document.write；
                      </div>
                      <div>
                        3）<Text strong>富文本另开治理链路</Text>：如本项目中的 <Text code>sanitizeToSafeHtml</Text> +{' '}
                        <Text code>&lt;SafeHtml /&gt;</Text>。
                      </div>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>

      <Card
        title="小结：SAFE 的三个关键点"
        style={{ background: '#111827', border: '1px solid #374151', marginTop: 8 }}
      >
        <ul style={{ color: '#e5e7eb', fontSize: 13, paddingLeft: 18, marginBottom: 0 }}>
          <li>
            <Tag color="blue">1</Tag> <Text strong>按上下文编码</Text>：HTML → <Text code>HtmlUtils.htmlEscape</Text> /
            <Text code>htmlEscape</Text>；URL → 协议白名单 + URL 解析；JS → <Text code>escapeJsString</Text>。
          </li>
          <li>
            <Tag color="blue">2</Tag> <Text strong>不把数据当代码</Text>：不把用户输入拼进 script、JSONP callback、内联事件等执行位置。
          </li>
          <li>
            <Tag color="blue">3</Tag> <Text strong>渲染时再决定 SAFE</Text>：存储保留原文，渲染根据 mode 选择 VULN / WEAK / SAFE 分支，这也是你靶场里
            <Text code>renderCommentForMode</Text> 的设计初衷。
          </li>
        </ul>
      </Card>
    </div>
  );
}

