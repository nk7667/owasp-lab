import { useEffect, useState } from 'react';
import { Alert, Button, Card, Col, Input, Row, Space, Typography } from 'antd';

const { Title, Paragraph, Text } = Typography;
const { TextArea } = Input;

const DEFAULT_XML = `<?xml version="1.0"?>
<user>
  <name>Alice</name>
  <email>alice@example.com</email>
</user>`;

// 前端兜底 payload，保证一键填充在 /info 未返回或结构异常时仍可用
const FALLBACK_PAYLOADS = {
  file_read: `<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`,
  ssrf: `<?xml version="1.0"?>
<!DOCTYPE note [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8000/xxe-test">
]>
<user>
  <name>&xxe;</name>
  <email>test@example.com</email>
</user>`,
  billion_laughs: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">
]>
<data>&lol2;</data>`,
};

export default function XxeLab() {
  const [mode, setMode] = useState('vuln'); // 'vuln' | 'safe'
  const [xml, setXml] = useState(DEFAULT_XML);
  const [info, setInfo] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetch('/api/v1/xxe/info')
      .then((res) => res.json())
      .then(setInfo)
      .catch(() => {});
  }, []);

  const currentEndpoint = mode === 'vuln' ? '/api/v1/xxe/parse-vuln' : '/api/v1/xxe/parse-safe';

  const runParse = async () => {
    setLoading(true);
    setResult(null);
    try {
      const resp = await fetch(currentEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ xml }),
      });
      const data = await resp.json();
      setResult({ ok: resp.ok, data });
    } catch (e) {
      setResult({ ok: false, data: { error: String(e) } });
    } finally {
      setLoading(false);
    }
  };

  const loadPayload = (key) => {
    const payload =
      (info && info.test_payloads && typeof info.test_payloads[key] === 'string')
        ? info.test_payloads[key]
        : FALLBACK_PAYLOADS[key];
    if (typeof payload === 'string') {
      setXml(payload);
    }
  };

  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        XXE · XML 外部实体注入实验
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 16 }}>
        通过同一份 XML，在
        <Text strong style={{ color: '#e6edf3' }}> VULN（未禁用外部实体） </Text>
        和
        <Text strong style={{ color: '#e6edf3' }}> SAFE（禁用 DTD / 外部实体） </Text>
        两种解析方式下的差异，理解 XXE 如何实现
        <Text strong> 文件读取 / SSRF / DoS </Text>
        以及如何修复。
      </Paragraph>

      <Row gutter={16} align="stretch">
        <Col xs={24} lg={14}>
          <Card
            variant="outlined"
            style={{ width: '100%', marginBottom: 16 }}
            title={
              <Space>
                <span style={{ color: '#8b9cb3', fontSize: 13 }}>XML 输入 &amp; 解析模式</span>
              </Space>
            }
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, width: '100%' }}>
              <Alert
                type={mode === 'vuln' ? 'error' : 'success'}
                showIcon
                style={{ background: '#020617', border: '1px solid #1f2933' }}
                title={
                  <Space>
                    <span style={{ color: '#e6edf3' }}>
                      当前模式：
                      <Text strong type={mode === 'vuln' ? 'danger' : 'success'}>
                        {mode === 'vuln'
                          ? ' VULN · 默认解析器（可能触发 XXE）'
                          : ' SAFE · 禁用 DTD / 外部实体'}
                      </Text>
                    </span>
                    <Button
                      size="small"
                      type={mode === 'vuln' ? 'primary' : 'default'}
                      onClick={() => setMode('vuln')}
                    >
                      VULN
                    </Button>
                    <Button
                      size="small"
                      type={mode === 'safe' ? 'primary' : 'default'}
                      onClick={() => setMode('safe')}
                    >
                      SAFE
                    </Button>
                  </Space>
                }
              />

              <Text style={{ color: '#94a3b8', fontSize: 13 }}>待解析的 XML：</Text>
              <TextArea
                rows={14}
                value={xml}
                onChange={(e) => setXml(e.target.value)}
                spellCheck={false}
                style={{
                  fontFamily: 'SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace',
                  fontSize: 12,
                  background: '#020617',
                  color: '#e5e7eb',
                  borderRadius: 8,
                }}
              />

              <Space>
                <Button type="primary" loading={loading} onClick={runParse}>
                  发送到后端解析（/api/v1/xxe/{mode === 'vuln' ? 'parse-vuln' : 'parse-safe'})
                </Button>
                <Button
                  onClick={() => {
                    setXml(DEFAULT_XML);
                    setResult(null);
                  }}
                >
                  重置为普通 XML
                </Button>
              </Space>
            </div>
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card
            variant="outlined"
            style={{ width: '100%', marginBottom: 16 }}
            title={<span style={{ color: '#8b9cb3', fontSize: 13 }}>常见攻击类型 &amp; 示例 Payload</span>}
          >
            {info ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, width: '100%' }}>
                <Text style={{ color: '#94a3b8', fontSize: 13 }}>
                  {info.description ||
                    'XXE 通过外部实体在解析 XML 时访问 file:// / http:// 等 URI，实现文件读取或 SSRF。'}
                </Text>
                {info.attack_types && (
                  <ul style={{ paddingLeft: 18, marginBottom: 4, color: '#94a3b8', fontSize: 13 }}>
                    <li>文件读取：{info.attack_types.file_read}</li>
                    <li>SSRF / 外带：{info.attack_types.ssrf}</li>
                    <li>拒绝服务：{info.attack_types.dos}</li>
                  </ul>
                )}
                <Space size={6} wrap>
                  <Button size="small" onClick={() => loadPayload('file_read')}>
                    一键填充 · 文件读取 payload
                  </Button>
                  <Button size="small" onClick={() => loadPayload('ssrf')}>
                    一键填充 · SSRF / OOB payload
                  </Button>
                  <Button size="small" onClick={() => loadPayload('billion_laughs')}>
                    一键填充 · DoS（Billion Laughs）
                  </Button>
                </Space>
              </div>
            ) : (
              <Text type="secondary" style={{ fontSize: 13 }}>
                正在加载 XXE 说明...
              </Text>
            )}
          </Card>

          <Card
            variant="outlined"
            style={{ width: '100%' }}
            title={<span style={{ color: '#8b9cb3', fontSize: 13 }}>解析结果（后端返回）</span>}
          >
            {result ? (
              <pre
                style={{
                  margin: 0,
                  maxHeight: 260,
                  overflow: 'auto',
                  background: '#020617',
                  borderRadius: 8,
                  padding: 12,
                  fontSize: 12,
                  color: '#e5e7eb',
                  border: '1px solid #1f2933',
                }}
              >
                {JSON.stringify(result.data, null, 2)}
              </pre>
            ) : (
              <Text type="secondary" style={{ fontSize: 12 }}>
                还没有发起解析请求。你可以先点击上方按钮填充 payload，再选择 VULN/SAFE 模式进行对比。
              </Text>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}

