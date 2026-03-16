import { Alert, Button, Card, Form, Input, Row, Col, Space, Typography, Tag, Collapse } from 'antd';
import { GlobalOutlined, CodeOutlined, CloudServerOutlined, LinkOutlined } from '@ant-design/icons';
import { useState } from 'react';
import { ssrfApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import { reportCoachUi } from '../xss/_shared/coachUi';
import DarkSelect from '../../components/DarkSelect';

const { Title, Paragraph, Text } = Typography;

const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN（原始漏洞）' },
  { value: 'weak', label: 'WEAK（错误修复）' },
  { value: 'safe', label: 'SAFE（正确修复）' },
];

const WEAK_LEVEL_OPTIONS = [
  { value: 1, label: 'WEAK-1：只拦 localhost / 127.0.0.1' },
  { value: 2, label: 'WEAK-2：解析 IP 并黑名单内网网段' },
  { value: 3, label: 'WEAK-3：仅允许 http/https 协议' },
  { value: 4, label: 'WEAK-4：组合过滤，仍可被编码/重定向绕过' },
  { value: 5, label: 'WEAK-5：更严格黑名单，演示进阶绕过' },
];

const PAYLOAD_SUGGESTIONS = {
  1: [
    {
      kind: '基础 · 本机管理端口',
      expect: '尝试访问本机服务，例如 Spring Boot 管理端口或 H2 控制台。',
      value: 'http://127.0.0.1:8081/actuator/health',
    },
    {
      kind: '短写 · 127.1 绕过',
      expect: '使用 127.1 而不是 127.0.0.1 绕过只拦字符串的过滤。',
      value: 'http://127.1:8081/api/v1/ssrf/internal/metadata',
    },
  ],
  2: [
    {
      kind: '云元数据（模拟）',
      expect: '通过本机回环访问靶场内置的“元数据”接口，模拟云环境 SSRF。',
      value: 'http://127.0.0.1:8081/api/v1/ssrf/internal/metadata',
    },
    {
      kind: '十进制 IP 表示',
      expect: '用十进制 2130706433 表示 127.0.0.1，考察是否只在字符串层面过滤。',
      value: 'http://2130706433:8081/api/v1/ssrf/internal/metadata',
    },
  ],
  3: [
    {
      kind: 'file 协议读取本地文件',
      expect: '在 VULN 模式下尝试 file:// 读取本地文件（仅教学环境使用）。',
      value: 'file:///etc/hosts',
    },
    {
      kind: '外网 → 内网重定向',
      expect: '利用重定向把请求从外网跳转到内网，考察是否只验证首个 URL。',
      value: 'http://httpbin.org/redirect-to?url=http://127.0.0.1:8081/api/v1/ssrf/internal/metadata',
    },
  ],
  4: [
    {
      kind: '内网 HTTP 服务探测',
      expect: '尝试枚举不同端口，模拟内网端口扫描型 SSRF。',
      value: 'http://127.0.0.1:8081/health',
    },
  ],
  5: [
    {
      kind: '正常外部 API（白名单）',
      expect: '访问安全白名单中的外部 API，观察 SAFE 模式下的正常行为。',
      value: 'https://api.github.com/users/octocat',
    },
  ],
};

export default function SsrfFetch() {
  const [mode, setMode] = useState('vuln');
  const [weakLevel, setWeakLevel] = useState(1);
  const [url, setUrl] = useState('http://127.0.0.1:8081/api/v1/ssrf/internal/metadata');
  const { loading, result, run } = useRequestRunner();

  const handleFetch = async () => {
    try {
      await run('ssrf_fetch', () => ssrfApi.fetch(mode, url, weakLevel));
      reportCoachUi({
        context: `ssrf_fetch_${mode}`,
        mode,
        focus: 'execute',
        input: url,
        extras: { weakLevel },
      });
    } catch (e) {
      // 靶场：忽略前端错误处理，结果统一通过 result 展示
    }
  };

  const currentSuggestions = PAYLOAD_SUGGESTIONS[weakLevel] || [];
  const data = result?.data?.data;

  return (
    <div style={{ maxWidth: 1440, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <GlobalOutlined /> SSRF - URL 获取实验
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        模拟常见“URL 代理 / 抓取”功能：用户输入任意 URL，服务器在后台发起请求并返回结果。
        如果该功能没有做好限制，就可能被攻击者用来访问本机/内网服务、云元数据端点，甚至读取本地文件。
      </Paragraph>

      <Row gutter={16} align="stretch">
        <Col xs={24} lg={16} style={{ display: 'flex' }}>
          <Card
            title={
              <Space>
                <LinkOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>测试界面</span>
              </Space>
            }
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <Alert
              type="info"
              showIcon
              message="场景：URL 抓取 / 预览服务"
              description="很多系统会提供一个“抓取网页内容”的功能，例如富文本预览、URL 分享卡片等。如果直接把用户输入的 URL 拿去请求，就可能形成 SSRF。"
              style={{ marginBottom: 12, background: 'rgba(56, 189, 248, 0.06)', border: '1px solid #2d3a4d' }}
            />

            <Form layout="vertical">
              <Row gutter={16}>
                <Col span={8}>
                  <Form.Item label="模式选择">
                    <DarkSelect
                      value={mode}
                      onChange={setMode}
                      options={MODE_OPTIONS}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>

                <Col span={8}>
                  <Form.Item label="弱级别（WEAK 模式）">
                    <DarkSelect
                      value={weakLevel}
                      onChange={setWeakLevel}
                      options={WEAK_LEVEL_OPTIONS}
                      style={{ width: '100%' }}
                      disabled={mode !== 'weak'}
                    />
                  </Form.Item>
                </Col>

                <Col span={8}>
                  <Form.Item label="目标 URL">
                    <Input
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      placeholder="输入要抓取的 URL，例如 http://127.0.0.1:8081/..."
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
              </Row>

              <Form.Item>
                <Button
                  type="primary"
                  onClick={handleFetch}
                  loading={loading}
                  icon={<CodeOutlined />}
                  style={{ width: 160 }}
                >
                  发起服务器请求
                </Button>
              </Form.Item>
            </Form>

            {data && (
              <div style={{ marginTop: 16 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  响应结果
                </Text>
                <div
                  style={{
                    marginTop: 8,
                    padding: 12,
                    borderRadius: 8,
                    background: '#0b1020',
                    border: '1px solid #2d3a4d',
                  }}
                >
                  <Space direction="vertical" size={8} style={{ width: '100%' }}>
                    {'status_code' in data && (
                      <div>
                        <Text strong style={{ color: '#e6edf3' }}>
                          状态码：
                        </Text>
                        <Tag
                          color={data.status_code >= 200 && data.status_code < 400 ? 'green' : 'red'}
                          style={{ marginLeft: 8 }}
                        >
                          {data.status_code}
                        </Tag>
                      </div>
                    )}

                    {data.blocked_reason && (
                      <Alert
                        type="warning"
                        showIcon
                        message="请求被拦截"
                        description={data.blocked_reason}
                        style={{ background: '#0f1419', border: '1px solid #2d3a4d' }}
                      />
                    )}

                    {data.error && !data.blocked_reason && (
                      <Alert
                        type="error"
                        showIcon
                        message="请求失败"
                        description={data.error}
                        style={{ background: '#0f1419', border: '1px solid #2d3a4d' }}
                      />
                    )}

                    {data.response_body && (
                      <div>
                        <Text strong style={{ color: '#e6edf3' }}>
                          响应内容预览：
                        </Text>
                        <pre
                          style={{
                            background: '#0f1419',
                            color: '#8b9cb3',
                            padding: 12,
                            borderRadius: 6,
                            marginTop: 8,
                            fontSize: 13,
                            lineHeight: 1.4,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                            border: '1px solid #2d3a4d',
                          }}
                        >
                          {data.response_body}
                        </pre>
                      </div>
                    )}
                  </Space>
                </div>
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={8} style={{ display: 'flex' }}>
          <Card
            title={<span style={{ color: '#e6edf3' }}>Security Coach</span>}
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.7 }}>
              <div>当前练习点：</div>
              <div>类型：SSRF 服务端请求伪造</div>
              <div>场景：URL 抓取 / 预览服务</div>
              <div>模式：{mode.toUpperCase()}</div>
            </div>

            <div style={{ marginTop: 12 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                你的输入会被插入到这里：
              </Text>
              <div
                style={{
                  marginTop: 8,
                  padding: 12,
                  borderRadius: 10,
                  background: '#0b1020',
                  border: '1px solid #2d3a4d',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                  fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                }}
              >
                fetchUrl({url})
              </div>
            </div>

            <Collapse
              size="small"
              style={{ marginTop: 12, background: 'rgba(56, 189, 248, 0.04)', border: '1px solid #2d3a4d' }}
              items={[
                {
                  key: 'payloads',
                  label: '载荷建议（按 WEAK 级别调整）',
                  children: (
                    <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {currentSuggestions.map((p) => (
                        <Tag
                          key={p.kind}
                          title={p.expect}
                          color="blue"
                          style={{
                            cursor: 'pointer',
                            fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                            maxWidth: '100%',
                            whiteSpace: 'normal',
                            wordBreak: 'break-word',
                            lineHeight: 1.25,
                            paddingBlock: 6,
                            paddingInline: 10,
                            marginInlineEnd: 0,
                          }}
                          onClick={() => {
                            setUrl(p.value);
                            reportCoachUi({
                              context: `ssrf_fetch_${mode}_payload_click`,
                              mode,
                              focus: 'payload_click',
                              input: p.value,
                              extras: { weakLevel },
                            });
                          }}
                        >
                          <div style={{ fontWeight: 600 }}>{p.kind}</div>
                          <div style={{ opacity: 0.92 }}>{p.value}</div>
                        </Tag>
                      ))}
                    </div>
                  ),
                },
                {
                  key: 'meta',
                  label: '元数据端点说明（模拟云环境）',
                  children: (
                    <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                      <div>
                        - 本靶场在 <code>/api/v1/ssrf/internal/metadata</code> 暴露了一个“仅本机可访问”的模拟元数据接口。
                      </div>
                      <div>
                        - 在 VULN 模式下，如果你能通过 <code>http://127.0.0.1:8081/...</code> 或十进制 IP 访问到这里，就说明存在 SSRF →
                        云元数据泄露风险。
                      </div>
                      <div>
                        - SAFE 模式应该禁止访问该端点：既不在域名白名单中，也解析为本地回环 IP。
                      </div>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}

