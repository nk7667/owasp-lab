import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  Row,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd';
import { LinkOutlined, ReloadOutlined, RobotOutlined, SearchOutlined } from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import useRequestRunner from '../hooks/useRequestRunner';
import { coachApi } from '../utils/api';
import MetaTags from '../components/MetaTags';

const { Title, Text } = Typography;

function formatTs(ts) {
  if (!ts) return '-';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts);
  }
}

function jsonPretty(x) {
  try {
    return JSON.stringify(x ?? null, null, 2);
  } catch {
    return String(x);
  }
}

export default function Coach() {
  const recentRunner = useRequestRunner();
  const analyzeRunner = useRequestRunner();
  const llmCheckRunner = useRequestRunner();

  const [recentLimit, setRecentLimit] = useState(10);

  useEffect(() => {
    recentRunner.run('coachRecent', () => coachApi.recent(recentLimit));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const recentData = recentRunner.result?.data?.data;
  const recentItems = Array.isArray(recentData?.items) ? recentData.items : [];

  const columns = useMemo(
    () => [
      {
        title: '时间',
        dataIndex: 'ts',
        key: 'ts',
        width: 180,
        render: (v) => <span style={{ color: '#8b9cb3' }}>{formatTs(v)}</span>,
      },
      {
        title: '方法',
        dataIndex: 'method',
        key: 'method',
        width: 90,
        render: (v) => <Tag>{v}</Tag>,
      },
      {
        title: '路径',
        dataIndex: 'path',
        key: 'path',
        render: (v) => <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>{v}</span>,
      },
      {
        title: '状态码',
        dataIndex: 'status',
        key: 'status',
        width: 90,
        render: (v) => <Tag color={Number(v) >= 400 ? 'volcano' : 'green'}>{v}</Tag>,
      },
      {
        title: '耗时(ms)',
        dataIndex: 'durationMs',
        key: 'durationMs',
        width: 110,
        render: (v) => <span style={{ color: '#8b9cb3' }}>{v}</span>,
      },
      {
        title: 'context',
        dataIndex: 'metaContext',
        key: 'metaContext',
        width: 170,
        render: (v) => (v ? <Tag color="geekblue">{v}</Tag> : <Text type="secondary">-</Text>),
      },
    ],
    [],
  );

  const analysis = analyzeRunner.result?.data?.data?.analysis;
  const analysisAnswer = analysis?.answer;
  const analysisMarkdown = analysisAnswer ? String(analysisAnswer) : '';

  const llmCheck = llmCheckRunner.result?.data?.data?.check;
  const llmCheckOk = llmCheck?.ok;
  const llmCheckAttempted = llmCheck?.attempted;

  return (
    <div style={{ maxWidth: 1220 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 4 }}>
          AI Coach
        </Title>
        <Space size={8} wrap style={{ justifyContent: 'flex-end' }}>
          {llmCheckRunner.result && (
            <Tag color={llmCheckAttempted === false ? 'default' : llmCheckOk ? 'green' : 'volcano'}>
              {llmCheckAttempted === false ? 'LLM: 未检测/无需检测' : llmCheckOk ? 'LLM: 已连接' : 'LLM: 未连接'}
            </Tag>
          )}
          <Button
            size="small"
            icon={<LinkOutlined />}
            loading={llmCheckRunner.loading}
            onClick={() => llmCheckRunner.run('coachLlmCheck', () => coachApi.llmCheck())}
          >
            检查连接
          </Button>
        </Space>
      </div>
      <Text type="secondary" style={{ display: 'block', marginBottom: 10 }}>
        采集当前会话最近请求（已做 headers 白名单 + requestBody 脱敏），用于给出关卡化、结构化的练习建议。
      </Text>

      <div style={{ marginBottom: 8 }}>
        <MetaTags meta={recentRunner.result?.data?.meta ?? analyzeRunner.result?.data?.meta} />
      </div>

      <Row gutter={16} align="stretch">
        <Col xs={24} lg={16} style={{ display: 'flex' }}>
          <Card
            title={
              <Space wrap style={{ maxWidth: '100%' }}>
                <RobotOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>最近流量</span>
                {recentData?.sessionKey && <Tag color="blue">sessionKey: {recentData.sessionKey}</Tag>}
              </Space>
            }
            extra={
              <Space wrap style={{ justifyContent: 'flex-end' }}>
                <InputNumber
                  min={1}
                  max={20}
                  value={recentLimit}
                  onChange={(v) => setRecentLimit(v ?? 10)}
                  style={{ width: 92 }}
                />
                <Button
                  icon={<ReloadOutlined />}
                  loading={recentRunner.loading}
                  onClick={() => recentRunner.run('coachRecent', () => coachApi.recent(recentLimit))}
                >
                  刷新
                </Button>
              </Space>
            }
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <Alert
              type="info"
              showIcon
              title="展开一条记录可查看 query / reqHeaders / reqBody（已脱敏与截断）"
              style={{
                marginBottom: 12,
                background: 'rgba(56, 189, 248, 0.06)',
                border: '1px solid #2d3a4d',
              }}
            />

            <Table
              dataSource={recentItems}
              columns={columns}
              rowKey="id"
              className="compact-table"
              size="small"
              pagination={false}
              scroll={{ x: 'max-content' }}
              style={{ width: '100%' }}
              expandable={{
                expandedRowRender: (r) => (
                  <div style={{ display: 'grid', gap: 10, maxWidth: '100%' }}>
                    <div>
                      <Text type="secondary">query</Text>
                      <pre
                        style={{
                          margin: 0,
                          padding: 12,
                          background: '#0d1117',
                          border: '1px solid #2d3a4d',
                          overflow: 'auto',
                          maxWidth: '100%',
                        }}
                      >
                        {r.query ?? ''}
                      </pre>
                    </div>
                    <div>
                      <Text type="secondary">reqHeaders（allowlist）</Text>
                      <pre
                        style={{
                          margin: 0,
                          padding: 12,
                          background: '#0d1117',
                          border: '1px solid #2d3a4d',
                          overflow: 'auto',
                          maxWidth: '100%',
                        }}
                      >
                        {jsonPretty(r.reqHeaders)}
                      </pre>
                    </div>
                    <div>
                      <Text type="secondary">reqBody（masked）</Text>
                      <pre
                        style={{
                          margin: 0,
                          padding: 12,
                          background: '#0d1117',
                          border: '1px solid #2d3a4d',
                          overflow: 'auto',
                          maxWidth: '100%',
                        }}
                      >
                        {typeof r.reqBody === 'string' ? r.reqBody : jsonPretty(r.reqBody)}
                      </pre>
                    </div>
                    <div>
                      <Text type="secondary">respBody（masked）</Text>
                      <pre
                        style={{
                          margin: 0,
                          padding: 12,
                          background: '#0d1117',
                          border: '1px solid #2d3a4d',
                          overflow: 'auto',
                          maxWidth: '100%',
                        }}
                      >
                        {typeof r.respBody === 'string' ? r.respBody : jsonPretty(r.respBody)}
                      </pre>
                    </div>
                  </div>
                ),
              }}
            />
          </Card>
        </Col>

        <Col xs={24} lg={8} style={{ display: 'flex' }}>
          <Card
            title={
              <Space wrap style={{ maxWidth: '100%' }}>
                <SearchOutlined style={{ color: '#34d399' }} />
                <span style={{ color: '#e6edf3' }}>分析</span>
                {analysis?.matchedContext && <Tag color="geekblue">context: {analysis.matchedContext}</Tag>}
                {typeof analysis?.flowsUsed === 'number' && <Tag>flowsUsed: {analysis.flowsUsed}</Tag>}
              </Space>
            }
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <Form
              layout="vertical"
              initialValues={{ prompt: '', limit: 5 }}
              onFinish={(v) => analyzeRunner.run('coachAnalyze', () => coachApi.analyze(v.prompt, v.limit))}
            >
              <Form.Item name="prompt" label="提示词（可选）">
                <Input.TextArea
                  placeholder="例如：我刚刚在登录绕过卡住了，应该关注什么信号？"
                  autoSize={{ minRows: 3, maxRows: 6 }}
                />
              </Form.Item>
              <Form.Item name="limit" label="参考最近 N 条流量" rules={[{ required: true, message: '请输入 N' }]}>
                <InputNumber min={1} max={20} style={{ width: 120 }} />
              </Form.Item>
              <Form.Item style={{ marginBottom: 12 }}>
                <Button type="primary" htmlType="submit" loading={analyzeRunner.loading}>
                  开始分析
                </Button>
              </Form.Item>
            </Form>

            {analyzeRunner.result && (
              <>
                {!analyzeRunner.result.success && (
                  <Alert
                    type="error"
                    showIcon
                    title="分析失败"
                    style={{ marginBottom: 12, border: '1px solid #2d3a4d' }}
                  />
                )}

                <div style={{ marginBottom: 10 }}>
                  <Text strong style={{ color: '#e6edf3' }}>
                    输出（Markdown）
                  </Text>
                  {analysis?.title && (
                    <Text type="secondary" style={{ marginLeft: 8 }}>
                      {analysis.title}
                    </Text>
                  )}
                </div>

                {analysisAnswer ? (
                  <div
                    className="coach-markdown nice-scrollbar"
                    style={{
                      padding: 16,
                      background: '#0d1117',
                      border: '1px solid #2d3a4d',
                      borderRadius: 10,
                      overflow: 'auto',
                      maxHeight: 520,
                      color: '#8b9cb3',
                    }}
                  >
                    <ReactMarkdown remarkPlugins={[remarkGfm]}>
                      {analysisMarkdown}
                    </ReactMarkdown>
                  </div>
                ) : (
                  <pre
                    style={{
                      margin: 0,
                      padding: 16,
                      background: '#0d1117',
                      border: '1px solid #2d3a4d',
                      borderRadius: 8,
                      overflow: 'auto',
                      maxHeight: 520,
                      whiteSpace: 'pre-wrap',
                      color: '#8b9cb3',
                    }}
                  >
                    {jsonPretty(analyzeRunner.result.data)}
                  </pre>
                )}
              </>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
}

