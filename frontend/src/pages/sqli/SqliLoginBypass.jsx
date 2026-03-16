import { Form, Input, Button, Typography, Tag, Space, Select, Alert } from 'antd';
import { BugOutlined, SafetyOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { sqliApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import LabTips from '../../components/LabTips';
import { useMemo, useState } from 'react';
import MetaTags from '../../components/MetaTags';

const { Text } = Typography;

const PAYLOADS = ["admin' OR '1'='1'--", "' OR 1=1 --"];

const TIPS = {
  principle:
    "本关卡演示“认证绕过”的根因：后端把 username/password 直接拼进 SQL 字符串，导致用户输入被数据库当成 SQL 语法执行。攻击者通过闭合引号、拼接恒真条件（如 1=1）或用注释截断后半段校验，从而绕过登录。",
  exploit: [
    {
      title: '用户名注入：注释截断',
      desc: '目标是“让密码条件失效”。通过注释把后半段截断，或把 WHERE 改造成恒真。',
      payloads: [
        "username: admin' --",
        "username: admin' OR '1'='1'--",
        "username: ' OR 1=1 --",
        'password: 任意/可为空（取决于后端 SQL 拼接方式）',
      ],
    },
    {
      title: '布尔恒真：不依赖注释',
      desc: '如果能闭合引号，就直接把条件改成恒真（不同数据库语法略有差异）。',
      payloads: ["username: admin' OR '1'='1", "password: x' OR '1'='1"],
    },
  ],
  bypassIntro:
    '如果有人尝试用黑名单过滤（拦 OR/--/单引号/空格），通常会被大小写、注释插入、空白变体等绕过。黑名单只能当“辅助”，不能替代参数化与正确认证流程。',
  bypass: [
    '大小写/混淆：Or / oR / OR（如果是大小写敏感过滤）',
    '注释插入：O/**/R、--+、/*...*/（如果只过滤连续关键词）',
    '空白变体：TAB/换行/多空格（如果只过滤普通空格）',
    '编码/转义：URL 编码（%27 %2d%2d 等），取决于网关/框架解码时机',
    '等价逻辑：用括号、AND/OR 组合调整优先级，绕过粗糙正则',
  ],
  fix: [
    'SQL 层：使用参数化查询 / ORM 参数绑定，禁止拼接用户输入。',
    '认证层：密码应使用 BCrypt/Argon2 哈希校验（应用层 matches），避免明文比对；错误提示统一，降低枚举风险。',
    '防护层：增加失败次数限制/短时锁定/速率限制与审计日志（降低爆破与探测效率）。',
  ],
};

export default function SqliLoginBypass() {
  const { loading, result, run } = useRequestRunner();
  const [mode, setMode] = useState('vuln'); // vuln | safe
  const [form] = Form.useForm();
  const loginUser = result?.success ? result?.data?.data : null;
  const meta = result?.data?.meta;

  const modeUi = useMemo(() => {
    return mode === 'safe'
      ? {
          label: 'SAFE',
          icon: <SafetyOutlined style={{ color: '#34d399' }} />,
          tag: <Tag color="green">参数化 + 哈希校验</Tag>,
          buttonDanger: false,
          usernamePh: 'admin',
          passwordPh: 'admin123',
          passwordRequired: true,
          runType: 'safeLogin',
          request: (u, p) => sqliApi.safeLogin(u, p),
        }
      : {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">拼接 WHERE</Tag>,
          buttonDanger: true,
          usernamePh: 'admin 或注入 payload',
          passwordPh: '可为空或任意',
          passwordRequired: false,
          runType: 'vulnLogin',
          request: (u, p) => sqliApi.vulnLogin(u, p),
        };
  }, [mode]);

  return (
    <ThreePanelLab
      title="SQL 注入 · 登录绕过"
      subtitle="关卡：where_login_bypass（inband）。默认只显示一个请求面板，通过下拉切换 VULN/SAFE。"
      bottomExtra={<LabTips tips={TIPS} />}
      hideSafe
      hideResponse
      vuln={{
        title: (
          <Space>
            {modeUi.icon}
            <span style={{ color: '#e6edf3' }}>{modeUi.label}</span>
          </Space>
        ),
        extra: (
          <Space wrap>
            <Select
              size="small"
              value={mode}
              onChange={(v) => setMode(v)}
              options={[
                { value: 'vuln', label: 'VULN' },
                { value: 'safe', label: 'SAFE' },
              ]}
              style={{ width: 110 }}
            />
            {modeUi.tag}
            <MetaTags meta={meta} />
          </Space>
        ),
        children: (
          <>
            <Form
              form={form}
              layout="vertical"
              onFinish={(v) => run(modeUi.runType, () => modeUi.request(v.username, v.password))}
            >
              <Form.Item name="username" label="用户名" rules={[{ required: true, message: '请输入用户名' }]}>
                <Input placeholder={modeUi.usernamePh} />
              </Form.Item>
              <Form.Item
                name="password"
                label="密码"
                rules={modeUi.passwordRequired ? [{ required: true, message: '请输入密码' }] : []}
              >
                <Input.Password placeholder={modeUi.passwordPh} />
              </Form.Item>
              <Form.Item>
                <Button
                  type="primary"
                  danger={modeUi.buttonDanger}
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  请求
                </Button>
              </Form.Item>
            </Form>

            {loginUser && (
              <Alert
                type="success"
                showIcon
                title={
                  <span>
                    已登录为 <b>{String(loginUser.username ?? '')}</b>（role={String(loginUser.role ?? '')}）
                  </span>
                }
                style={{ marginBottom: 12, background: 'rgba(52, 211, 153, 0.06)', border: '1px solid #2d3a4d' }}
              />
            )}
            <Text type="secondary" style={{ fontSize: 12 }}>
              常用 payload（点击填充 username）：
            </Text>
            <div style={{ marginTop: 8 }}>
              {PAYLOADS.map((p) => (
                <Tag
                  key={p}
                  style={{ cursor: 'pointer', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace' }}
                  onClick={async () => {
                    form.setFieldsValue({ username: p });
                    try {
                      await navigator.clipboard.writeText(p);
                    } catch {
                      // ignore
                    }
                  }}
                >
                  {p}
                </Tag>
              ))}
            </div>
          </>
        ),
      }}
      safe={{ title: null, extra: null, children: null }}
      result={result}
    />
  );
}

