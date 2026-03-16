import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Col, Form, Input, Row, Space, Typography } from 'antd';
import { csrfApi } from '../../utils/api';

const { Title, Text } = Typography;

const ALERT_DARK = { background: '#0f1419', border: '1px solid #2d3a4d' };

export default function CsrfLow() {
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
        CSRF · Low（无防护）
      </Title>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Victim：登录态（session）" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                style={ALERT_DARK}
                message={<span style={{ color: '#e6edf3' }}>先在受害者站点登录（cookie 在浏览器里）。</span>}
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
          <Card title="Low：无 token 的 GET 改密" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="warning"
                showIcon
                style={ALERT_DARK}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    危险点：用 <code style={{ color: '#38bdf8' }}>GET</code> 改状态 + 无 CSRF token。外站诱导一次跳转即可触发。
                  </span>
                }
              />

              <Space wrap>
                <Button onClick={() => window.open('/api/v1/csrf/low/password/page', '_blank', 'noopener,noreferrer')}>
                  打开 victim 改密页（Low）
                </Button>
                <Button onClick={() => window.open('/csrf/evil', '_blank', 'noopener,noreferrer')}>
                  打开 evil 诱导页（外站）
                </Button>
              </Space>

              <div style={{ color: '#8b9cb3', fontSize: 12 }}>
                <div>victim 目标接口（Low）：</div>
                <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#c6d3e5' }}>
                  {`${victimOrigin}/api/v1/csrf/low/password/change?password_new=...&password_conf=...&Change=Change`}
                </pre>
              </div>

              <Alert
                type="info"
                showIcon
                style={ALERT_DARK}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    说明：Low 关建议用“外站页面 → 顶级跳转”触发（更贴近现代浏览器 SameSite=Lax 的行为）。
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

