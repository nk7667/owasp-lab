import { useState } from 'react';
import {
  Card,
  Form,
  Input,
  Button,
  Typography,
  Row,
  Col,
  Tag,
  Space,
  Alert,
  Table,
  Select,
} from 'antd';
import {
  DatabaseOutlined,
  SafetyOutlined,
  PlayCircleOutlined,
  CodeOutlined,
  SortAscendingOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { sqliApi } from '../utils/api';

const { Title, Text } = Typography;

const PAYLOADS = [
  "admin' OR '1'='1'--",
  "' OR 1=1 --",
];

export default function SqlInjection() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const onVulnLogin = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.vulnLogin(values.username, values.password);
      setResult({ type: 'vuln', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'vuln',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const onSafeLogin = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.safeLogin(values.username, values.password);
      setResult({ type: 'safe', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'safe',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const onVulnList = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.vulnUsers(values.sortField || 'id', values.sortOrder || 'asc');
      setResult({ type: 'vulnList', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'vulnList',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const onSafeList = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.safeUsers(values.sortField || '1', values.sortOrder || 'asc');
      setResult({ type: 'safeList', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'safeList',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const onVulnUserDetail = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.vulnUser(values.id);
      setResult({ type: 'vulnUser', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'vulnUser',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const onSafeUserDetail = async (values) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await sqliApi.safeUser(values.id);
      setResult({ type: 'safeUser', success: true, data: res.data });
    } catch (e) {
      setResult({
        type: 'safeUser',
        success: false,
        data: e.response?.data ?? { error: e.message },
      });
    }
    setLoading(false);
  };

  const listData = Array.isArray(result?.data?.data) ? result.data.data : [];
  const listColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 72 },
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: '邮箱', dataIndex: 'email', key: 'email' },
    { title: '角色', dataIndex: 'role', key: 'role', width: 80 },
  ];
  const meta = result?.data?.meta;

  return (
    <div style={{ maxWidth: 960 }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 4 }}>
        SQL 注入
      </Title>
      <Text style={{ color: '#8b9cb3', display: 'block', marginBottom: 24 }}>
        通过将恶意 SQL 插入请求参数，使服务端执行非预期查询。左侧为拼接 SQL（可注入），右侧为参数化查询（安全）。
      </Text>

      <Alert
        title="测试账户：admin / admin123"
        type="info"
        showIcon
        style={{
          marginBottom: 24,
          background: 'rgba(56, 189, 248, 0.08)',
          border: '1px solid #2d3a4d',
        }}
      />

      <Row gutter={24}>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <CodeOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>脆弱登录</span>
              </Space>
            }
            extra={<Tag color="volcano">VULN</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form onFinish={onVulnLogin} layout="vertical" size="middle" data-form="vuln">
              <Form.Item name="username" label="用户名">
                <Input placeholder="admin 或注入 payload" />
              </Form.Item>
              <Form.Item name="password" label="密码">
                <Input.Password placeholder="密码" />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  danger
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  请求
                </Button>
              </Form.Item>
            </Form>
            <Text type="secondary" style={{ fontSize: 12 }}>
              可点击下方 payload 填入用户名后提交
            </Text>
            <div style={{ marginTop: 8 }}>
              {PAYLOADS.map((p) => (
                <Tag
                  key={p}
                  style={{
                    marginBottom: 4,
                    cursor: 'pointer',
                    fontFamily: 'JetBrains Mono, monospace',
                  }}
                  onClick={() => {
                    const form = document.querySelector('[data-form="vuln"]');
                    if (form) {
                      const input = form.querySelector('input');
                      if (input) {
                        input.value = p;
                        input.dispatchEvent(new Event('input', { bubbles: true }));
                      }
                    }
                  }}
                >
                  {p}
                </Tag>
              ))}
            </div>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <SafetyOutlined style={{ color: '#34d399' }} />
                <span style={{ color: '#e6edf3' }}>安全登录</span>
              </Space>
            }
            extra={<Tag color="green">SAFE</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form
              onFinish={onSafeLogin}
              layout="vertical"
              size="middle"
              data-form="safe"
            >
              <Form.Item name="username" label="用户名">
                <Input placeholder="admin" />
              </Form.Item>
              <Form.Item name="password" label="密码">
                <Input.Password placeholder="admin123" />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  请求
                </Button>
              </Form.Item>
            </Form>
            <Text type="secondary" style={{ fontSize: 12 }}>
              仅接受合法用户名与密码，注入无效
            </Text>
          </Card>
        </Col>
      </Row>

      <Title level={4} style={{ color: '#e6edf3', marginTop: 32, marginBottom: 16 }}>
        用户详情·ID（where_id_union）
      </Title>
      <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
        左：拼接 id（可注入）。右：id 按 Long 解析 + 参数化查询（注入会 400 或失败）。
      </Text>
      <Row gutter={24}>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <UserOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>脆弱用户详情</span>
              </Space>
            }
            extra={<Tag color="volcano">VULN</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form onFinish={onVulnUserDetail} layout="vertical" size="middle">
              <Form.Item name="id" label="用户ID" rules={[{ required: true, message: '请输入 id' }]}>
                <Input placeholder="1 或 1 OR 1=1" />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  danger
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  获取详情
                </Button>
              </Form.Item>
            </Form>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <SafetyOutlined style={{ color: '#34d399' }} />
                <span style={{ color: '#e6edf3' }}>安全用户详情</span>
              </Space>
            }
            extra={<Tag color="green">SAFE</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form onFinish={onSafeUserDetail} layout="vertical" size="middle">
              <Form.Item name="id" label="用户ID" rules={[{ required: true, message: '请输入 id' }]}>
                <Input placeholder="1" inputMode="numeric" />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  获取详情
                </Button>
              </Form.Item>
            </Form>
          </Card>
        </Col>
      </Row>

      <Title level={4} style={{ color: '#e6edf3', marginTop: 32, marginBottom: 16 }}>
        用户列表·排序
      </Title>
      <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
        左：排序字段/方向直接拼进 ORDER BY（可注入）。右：仅允许 1=id, 2=username, 3=email, 4=role 及 asc/desc。
      </Text>
      <Row gutter={24}>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <SortAscendingOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>脆弱排序</span>
              </Space>
            }
            extra={<Tag color="volcano">VULN</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form onFinish={onVulnList} layout="vertical" size="middle">
              <Form.Item name="sortField" label="排序字段">
                <Input placeholder="id / username / email / role 或注入" />
              </Form.Item>
              <Form.Item name="sortOrder" label="排序方向">
                <Input placeholder="asc / desc" />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  danger
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  获取列表
                </Button>
              </Form.Item>
            </Form>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <SafetyOutlined style={{ color: '#34d399' }} />
                <span style={{ color: '#e6edf3' }}>安全排序</span>
              </Space>
            }
            extra={<Tag color="green">SAFE</Tag>}
            style={{
              background: '#161f2e',
              border: '1px solid #2d3a4d',
              marginBottom: 24,
            }}
          >
            <Form onFinish={onSafeList} layout="vertical" size="middle">
              <Form.Item name="sortField" label="排序字段" initialValue="1">
                <Select
                  options={[
                    { value: '1', label: '1 → id' },
                    { value: '2', label: '2 → username' },
                    { value: '3', label: '3 → email' },
                    { value: '4', label: '4 → role' },
                  ]}
                />
              </Form.Item>
              <Form.Item name="sortOrder" label="排序方向" initialValue="asc">
                <Select
                  options={[
                    { value: 'asc', label: 'asc' },
                    { value: 'desc', label: 'desc' },
                  ]}
                />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  获取列表
                </Button>
              </Form.Item>
            </Form>
          </Card>
        </Col>
      </Row>

      {result && (
        <Card
          title={
            <Space>
              <DatabaseOutlined />
              <span>响应</span>
              <Tag color={result.success ? 'green' : 'volcano'}>
                {result.success ? '成功' : '失败'}
              </Tag>
            </Space>
          }
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
          }}
        >
          {meta && (
            <div style={{ marginBottom: 12 }}>
              <Space wrap>
                <Tag color="blue">module: {meta.module}</Tag>
                <Tag color="purple">mode: {meta.mode}</Tag>
                <Tag color="cyan">signal: {meta.signalChannel}</Tag>
                <Tag color="geekblue">context: {meta.context}</Tag>
                <Tag>cwe: {meta.cwe}</Tag>
              </Space>
            </div>
          )}
          {listData.length > 0 && (
            <Table
              dataSource={listData}
              columns={listColumns}
              rowKey="id"
              size="small"
              pagination={false}
              style={{ marginBottom: 16 }}
            />
          )}
          <pre
            style={{
              margin: 0,
              padding: 16,
              background: '#0d1117',
              border: '1px solid #2d3a4d',
              borderRadius: 8,
              overflow: 'auto',
              maxHeight: 320,
              fontSize: 12,
              color: '#8b9cb3',
            }}
          >
            {JSON.stringify(result.data, null, 2)}
          </pre>
        </Card>
      )}
    </div>
  );
}
