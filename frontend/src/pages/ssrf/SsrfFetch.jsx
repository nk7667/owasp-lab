import { Button, Card, Form, Input, Row, Col, Space, Typography, Tag } from 'antd';
import { GlobalOutlined, CodeOutlined, ReadOutlined } from '@ant-design/icons';
import { useState } from 'react';
import { ssrfApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import { reportCoachUi } from '../xss/_shared/coachUi';
import DarkSelect from '../../components/DarkSelect';
import { useNavigate } from 'react-router-dom';

const { Title, Text } = Typography;

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

export default function SsrfFetch() {
  const navigate = useNavigate();
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

  const data = result?.data?.data;

  return (
    <div style={{ maxWidth: 1440, width: '100%', margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
          <GlobalOutlined /> SSRF - URL 获取
        </Title>
        <Button size="small" icon={<ReadOutlined />} onClick={() => navigate('/ssrf/docs')}>
          说明
        </Button>
      </div>

      <Row gutter={16} align="stretch">
        <Col xs={24} style={{ display: 'flex' }}>
          <Card
            title={
              <Space>
                <span style={{ color: '#e6edf3' }}>测试界面</span>
              </Space>
            }
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
            extra={
              <Text type="secondary" style={{ fontSize: 12 }}>
                文档页包含模式差异、payload 示例与绕过点
              </Text>
            }
          >
            <Form layout="vertical">
              <Row gutter={16}>
                <Col span={mode === 'weak' ? 8 : 12}>
                  <Form.Item label="模式选择">
                    <DarkSelect
                      value={mode}
                      onChange={setMode}
                      options={MODE_OPTIONS}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>

                {mode === 'weak' && (
                  <Col span={8}>
                    <Form.Item label="弱级别（WEAK 模式）">
                      <DarkSelect
                        value={weakLevel}
                        onChange={setWeakLevel}
                        options={WEAK_LEVEL_OPTIONS}
                        style={{ width: '100%' }}
                      />
                    </Form.Item>
                  </Col>
                )}

                <Col span={mode === 'weak' ? 8 : 12}>
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
                    {typeof data.statusCode === 'number' && (
                      <div>
                        <Text strong style={{ color: '#e6edf3' }}>
                          状态码：
                        </Text>
                        <Tag
                          color={data.statusCode >= 200 && data.statusCode < 400 ? 'green' : 'red'}
                          style={{ marginLeft: 8 }}
                        >
                          {data.statusCode}
                        </Tag>
                      </div>
                    )}

                    {data.blockedReason && (
                      <div style={{ color: '#fbbf24' }}>
                        <Text strong style={{ color: '#e6edf3' }}>
                          拦截原因：
                        </Text>
                        <div style={{ marginTop: 4, color: '#8b9cb3' }}>{data.blockedReason}</div>
                      </div>
                    )}

                    {data.error && !data.blockedReason && (
                      <div style={{ color: '#fb7185' }}>
                        <Text strong style={{ color: '#e6edf3' }}>
                          请求失败：
                        </Text>
                        <div style={{ marginTop: 4, color: '#8b9cb3' }}>{data.error}</div>
                      </div>
                    )}

                    {data.bodyPreview && (
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
                          {data.bodyPreview}
                        </pre>
                      </div>
                    )}
                  </Space>
                </div>
              </div>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}

