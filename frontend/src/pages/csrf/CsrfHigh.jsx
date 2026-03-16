import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Col, Form, Input, Row, Space, Typography } from 'antd';
import { csrfApi } from '../../utils/api';

const { Title, Text, Paragraph } = Typography;

const ALERT_DARK = { background: '#0f1419', border: '1px solid #2d3a4d' };

export default function CsrfHigh() {
  const [loginForm] = Form.useForm();
  const [me, setMe] = useState(null);
  const [loadingMe, setLoadingMe] = useState(false);
  const [err, setErr] = useState('');

  const refreshMe = async () => {
    setLoadingMe(true);
    setErr('');
    try {
      const resp = await csrfApi.me();
      setMe(resp?.data?.data || null);
    } catch (e) {
      setMe(null);
      setErr(e?.response?.data?.message || e?.message || '查询失败');
    } finally {
      setLoadingMe(false);
    }
  };

  useEffect(() => {
    refreshMe();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const victimOrigin = useMemo(() => window.location.origin, []);

  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        CSRF · High（token + XSS 链）
      </Title>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Victim：登录态（与 Low 复用）" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                style={ALERT_DARK}
                message={<span style={{ color: '#e6edf3' }}>先在受害者站点登录（cookie + session），再练 CSRF token 场景。</span>}
              />

              <Form
                form={loginForm}
                layout="vertical"
                initialValues={{ username: 'admin', password: 'admin123' }}
                onFinish={async (v) => {
                  setErr('');
                  try {
                    await csrfApi.login(v.username, v.password);
                    await refreshMe();
                  } catch (e) {
                    setErr(e?.response?.data?.message || e?.message || '登录失败');
                  }
                }}
              >
                <Row gutter={12}>
                  <Col span={12}>
                    <Form.Item name="username" label="用户名" rules={[{ required: true }]}>
                      <Input />
                    </Form.Item>
                  </Col>
                  <Col span={12}>
                    <Form.Item name="password" label="密码" rules={[{ required: true }]}>
                      <Input.Password />
                    </Form.Item>
                  </Col>
                </Row>
                <Space>
                  <Button type="primary" htmlType="submit">
                    登录
                  </Button>
                  <Button
                    onClick={async () => {
                      await csrfApi.logout();
                      await refreshMe();
                    }}
                  >
                    退出
                  </Button>
                  <Button onClick={refreshMe} loading={loadingMe}>
                    刷新 me
                  </Button>
                </Space>
              </Form>

              {err ? <Alert type="error" showIcon style={ALERT_DARK} message={<span style={{ color: '#e6edf3' }}>{err}</span>} /> : null}

              <div style={{ color: '#8b9cb3', fontSize: 12 }}>
                <div>
                  <Text type="secondary">当前 me：</Text>
                </div>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#c6d3e5' }}>{JSON.stringify(me, null, 2)}</pre>
              </div>
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card title="High：Token + 同源 XSS 链（示意）" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                style={ALERT_DARK}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    这个关卡展示的是：有 CSRF token 时，单纯外站 CSRF 会失败；但一旦有 XSS（同源脚本执行），token 可以被读出并用于同源改密。
                  </span>
                }
              />

              <Space wrap>
                <Button onClick={() => window.open('/api/v1/csrf/high/password/page', '_blank', 'noopener,noreferrer')}>
                  打开 victim High 改密表单页
                </Button>
              </Space>

              <div style={{ color: '#8b9cb3', fontSize: 12 }}>
                <Paragraph style={{ color: '#8b9cb3', marginBottom: 4 }}>
                  表单页会发放 <code style={{ color: '#38bdf8' }}>user_token</code> 隐藏字段，并在每次成功/失败后轮转。
                </Paragraph>
                <Paragraph style={{ color: '#8b9cb3', marginBottom: 4 }}>
                  XSS 链的关键：让脚本在 <code style={{ color: '#38bdf8' }}>{victimOrigin}</code> 同源页面中执行，从 DOM 读取 token，再发起{' '}
                  <code style={{ color: '#38bdf8' }}>/api/v1/csrf/high/password/change</code> 的 POST 请求。
                </Paragraph>
              </div>

              <Card size="small" title="攻击链（概念）" style={{ background: '#0f1419', border: '1px solid #2d3a4d' }}>
                <ol style={{ paddingLeft: 20, color: '#c6d3e5', fontSize: 13, lineHeight: 1.7 }}>
                  <li>受害者在 victim 站点登录，浏览器里有 session cookie。</li>
                  <li>受害者访问带 XSS 的 URL（同源页面），脚本在 victim origin 下执行。</li>
                  <li>脚本从 DOM 中读取隐藏字段 <code>user_token</code>。</li>
                  <li>脚本携带该 token 和 cookie，向 <code>/api/v1/csrf/high/password/change</code> 发送 POST 改密请求。</li>
                  <li>服务端校验 token + session 通过，密码被修改。</li>
                </ol>
              </Card>

              <Alert
                type="warning"
                showIcon
                style={ALERT_DARK}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    这里不直接内置完整 XSS payload，而是建议你在浏览器控制台或独立脚本中手敲：读取 <code>user_token</code> → 调用改密接口。
                  </span>
                }
              />
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

