import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Alert, Button, Card, Col, Collapse, Divider, Form, Input, InputNumber, Row, Select, Space, Table, Tag, Typography } from 'antd';
import { blindApi, xssApi } from '../../utils/api';
import { reportCoachUi } from './_shared/coachUi';

const { Text } = Typography;

const ALERT_DARK_BASE_STYLE = {
  background: '#0f1419',
  border: '1px solid #2d3a4d',
};

const PAYLOAD_ITEMS = [
  {
    kind: '对照（不执行）',
    value: 'hello blind profile',
  },
  {
    kind: '验证（自动触发 beacon）',
    value:
      `<img src=x onerror="fetch('/api/v1/blind/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profileId:+new URLSearchParams(location.search).get('id'),kind:'poc',view:'xss_blind_profile_admin_view',payload:'img-onerror',ts:Date.now()})})">`,
  },
  {
    kind: '验证（SVG onload）',
    value:
      `<svg onload="fetch('/api/v1/blind/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profileId:+new URLSearchParams(location.search).get('id'),kind:'poc',view:'xss_blind_profile_admin_view',payload:'svg-onload',ts:Date.now()})})"></svg>`,
  },
  {
    kind: '验证（点击触发）',
    value:
      `<a href="#" onclick="fetch('/api/v1/blind/beacon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profileId:+new URLSearchParams(location.search).get('id'),kind:'poc',view:'xss_blind_profile_admin_view',payload:'a-onclick',ts:Date.now()})});return false">点我触发 beacon</a>`,
  },
  {
    kind: '可见化（不靠事件）',
    value: `<img src=x onerror="try{var b=document.getElementById('bio');if(b){b.style.outline='2px solid #38bdf8';b.style.outlineOffset='2px'}}catch(e){}">`,
  },
];

export default function XssStoredProfileSubmit() {
  const navigate = useNavigate();
  const [form] = Form.useForm();
  const [mode, setMode] = useState('vuln');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [lastProfileId, setLastProfileId] = useState(() => {
    const v = window.localStorage.getItem('xss_blind_profile_lastId');
    return v ? Number(v) : null;
  });
  const [oobProfileId, setOobProfileId] = useState(() => {
    const v = window.localStorage.getItem('xss_blind_profile_lastId');
    return v ? Number(v) : null;
  });
  const [oobLoading, setOobLoading] = useState(false);
  const [oobErr, setOobErr] = useState('');
  const [oobItems, setOobItems] = useState([]);

  const context = 'xss_blind_profile_submit';

  const reportUi = (evt) => {
    reportCoachUi({
      context,
      mode,
      target: 'profile_submit',
      focus: evt?.focus || '',
      input: evt?.input || '',
    });
  };

  const onFinish = async (values) => {
    setSubmitting(true);
    setError('');
    const nickname = values?.nickname || '';
    const bio = values?.bio || '';
    reportUi({ focus: 'submit', input: `nickname=${nickname}\nbio=${bio}` });
    try {
      const resp = await xssApi.profileSubmit(mode, nickname, bio);
      const id = resp?.data?.data?.profileId;
      if (typeof id === 'number') {
        setLastProfileId(id);
        setOobProfileId(id);
        window.localStorage.setItem('xss_blind_profile_lastId', String(id));
      }
    } catch (e) {
      setError(e?.response?.data?.message || e?.message || '提交失败');
    } finally {
      setSubmitting(false);
    }
  };

  const refreshOob = async () => {
    if (!oobProfileId) return;
    setOobLoading(true);
    setOobErr('');
    try {
      const resp = await blindApi.recent(oobProfileId, 30);
      const items = resp?.data?.data?.items || [];
      setOobItems(Array.isArray(items) ? items : []);
    } catch (e) {
      setOobErr(e?.response?.data?.message || e?.message || '拉取 OOB 事件失败');
    } finally {
      setOobLoading(false);
    }
  };

  useEffect(() => {
    if (!oobProfileId) return;
    let alive = true;
    const tick = async () => {
      if (!alive) return;
      await refreshOob();
    };
    tick();
    const t = window.setInterval(tick, 1200);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [oobProfileId]);

  const quickGo = useMemo(() => {
    if (!lastProfileId) return null;
    return (
      <Space>
        <Button
          type="primary"
          onClick={() => navigate(`/xss/stored-profile-admin?id=${lastProfileId}&mode=${mode}`)}
        >
          打开后台预览（ID={lastProfileId}）
        </Button>
        <Button onClick={() => navigate('/xss/stored-profile-admin')}>进入后台页（手动选择 ID）</Button>
      </Space>
    );
  }, [lastProfileId, mode, navigate]);

  const oobColumns = [
    {
      title: '时间',
      dataIndex: 'ts',
      key: 'ts',
      width: 160,
      render: (v) => (v ? new Date(Number(v)).toLocaleTimeString() : '-'),
    },
    {
      title: 'kind',
      dataIndex: 'kind',
      key: 'kind',
      width: 120,
      render: (v) => <Tag color={v === 'poc' ? 'gold' : v === 'render' ? 'blue' : 'default'}>{v || '-'}</Tag>,
    },
    {
      title: 'view',
      dataIndex: 'view',
      key: 'view',
      width: 220,
      render: (v) => <Text style={{ color: '#8b9cb3' }}>{v || '-'}</Text>,
    },
    {
      title: 'payload',
      dataIndex: 'payload',
      key: 'payload',
      render: (v) => (
        <pre
          style={{
            margin: 0,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            color: '#e6edf3',
            background: 'transparent',
          }}
        >
          {v || ''}
        </pre>
      ),
    },
  ];

  return (
    <div>
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card title="Blind · Profile（提交端）" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                style={ALERT_DARK_BASE_STYLE}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    这个页面只负责“写入一条 Profile”。盲打的执行发生在后台页（iframe 预览）里。
                  </span>
                }
              />

              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <Text type="secondary">mode</Text>
                <Select
                  value={mode}
                  style={{ width: 160 }}
                  options={[
                    { value: 'vuln', label: 'VULN' },
                    { value: 'safe', label: 'SAFE' },
                  ]}
                  onChange={(v) => {
                    setMode(v);
                    reportUi({ focus: 'mode_change', input: v });
                  }}
                />
                {lastProfileId ? (
                  <Text type="secondary">最近 profileId：{lastProfileId}</Text>
                ) : (
                  <Text type="secondary">还没有提交记录</Text>
                )}
              </div>

              <Form form={form} layout="vertical" onFinish={onFinish} autoComplete="off">
                <Row gutter={[12, 12]}>
                  <Col xs={24} md={10}>
                    <Form.Item
                      label="昵称"
                      name="nickname"
                      rules={[{ required: false }]}
                      extra="用于后台页展示。为空会用“匿名”。"
                    >
                      <Input placeholder="比如：alice" maxLength={60} onChange={(e) => reportUi({ focus: 'nickname', input: e.target.value })} />
                    </Form.Item>
                  </Col>
                  <Col xs={24} md={14}>
                    <Form.Item
                      label="Bio（会在后台页渲染）"
                      name="bio"
                      rules={[{ required: true, message: '请输入 bio' }]}
                      extra="这里是训练输入点（后台页会读取并渲染）。"
                    >
                      <Input.TextArea
                        placeholder="在这里输入你的 Profile 内容（用于教学）。"
                        rows={5}
                        onChange={(e) => reportUi({ focus: 'bio', input: e.target.value })}
                      />
                    </Form.Item>
                  </Col>
                </Row>

                <Divider style={{ margin: '12px 0' }} />
                <Collapse
                  size="small"
                  defaultActiveKey={[]}
                  style={{
                    background: '#0f1419',
                    border: '1px solid #2d3a4d',
                    borderRadius: 12,
                  }}
                  items={[
                    {
                      key: 'payloads',
                      label: <span style={{ color: '#e6edf3' }}>Payload </span>,
                      children: (
                        <Collapse
                          size="small"
                          defaultActiveKey={[]}
                          style={{ background: 'transparent' }}
                          items={PAYLOAD_ITEMS.map((it) => ({
                            key: it.kind,
                            label: <span style={{ color: '#e6edf3', fontWeight: 600 }}>{it.kind}</span>,
                            children: (
                              <div>
                                <pre
                                  style={{
                                    margin: 0,
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-word',
                                    color: '#e6edf3',
                                    background: 'transparent',
                                  }}
                                >
                                  {it.value}
                                </pre>
                                <div style={{ marginTop: 10 }}>
                                  <Button
                                    size="small"
                                    onClick={() => {
                                      form.setFieldsValue({ bio: it.value });
                                      reportUi({ focus: 'payload_click', input: `${it.kind}\n${it.value}` });
                                    }}
                                  >
                                    填充 Bio
                                  </Button>
                                </div>
                              </div>
                            ),
                          }))}
                        />
                      ),
                    },
                  ]}
                />

                {error ? (
                  <Alert
                    type="error"
                    showIcon
                    style={ALERT_DARK_BASE_STYLE}
                    message={<span style={{ color: '#e6edf3' }}>{error}</span>}
                  />
                ) : null}

                <Space>
                  <Button type="primary" htmlType="submit" loading={submitting}>
                    提交 Profile
                  </Button>
                  {quickGo}
                </Space>
              </Form>

              <Divider style={{ margin: '12px 0' }} />

              <Card
                title="攻击者视角 · 带外事件（OOB）"
                size="small"
                bordered
                styles={{ body: { padding: 12 } }}
                extra={
                  <Space>
                    <Text type="secondary">profileId</Text>
                    <InputNumber
                      value={oobProfileId}
                      min={1}
                      placeholder="比如 1"
                      style={{ width: 160 }}
                      onChange={(v) => setOobProfileId(typeof v === 'number' ? v : null)}
                    />
                    <Button size="small" onClick={refreshOob} loading={oobLoading} disabled={!oobProfileId}>
                      手动刷新
                    </Button>
                  </Space>
                }
              >
                <Alert
                  type="info"
                  showIcon
                  style={ALERT_DARK_BASE_STYLE}
                  message={
                    <span style={{ color: '#e6edf3' }}>
                      这里模拟“攻击者的接收端/日志”。当目标后台页执行 payload 并回连{' '}
                      <code style={{ color: '#38bdf8' }}>/api/v1/blind/beacon</code> 时，这里会出现记录。
                    </span>
                  }
                />

                {oobErr ? (
                  <Alert
                    type="error"
                    showIcon
                    style={{ ...ALERT_DARK_BASE_STYLE, marginTop: 8 }}
                    message={<span style={{ color: '#e6edf3' }}>{oobErr}</span>}
                  />
                ) : null}

                <Table
                  size="small"
                  rowKey={(r) => r.id}
                  columns={oobColumns}
                  dataSource={oobItems}
                  loading={oobLoading}
                  pagination={false}
                  style={{ marginTop: 8 }}
                />
              </Card>
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

