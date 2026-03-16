import { Form, Input, Button, Tag, Space, Select, Descriptions, Alert } from 'antd';
import { BugOutlined, SafetyOutlined, PlayCircleOutlined, UserOutlined } from '@ant-design/icons';
import { sqliApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import LabTips from '../../components/LabTips';
import { useMemo, useState } from 'react';
import MetaTags from '../../components/MetaTags';

const TIPS = {
  principle:
    "本关卡的目标是“业务边界（只能查自己）”。SAFE 会先做鉴权（requestedId 必须等于 scopeUserId），并使用强类型 + 参数绑定；VULN 虽然也拼了边界条件，但把 requestedId 直接拼接进 SQL，攻击者可用 OR/注释改写 WHERE，绕过 only-self 读取他人甚至管理员敏感字段（如 secret）。",
  exploit: [
    {
      title: '默认边界：SAFE 只能查自己',
      desc: '不注入时，SAFE 只允许查询“当前用户”的 id（默认 scopeUserId=2）。输入其他 id 会 forbidden。',
      payloads: ['SAFE id: 2（应成功）', 'SAFE id: 1（应 forbidden）'],
    },
    {
      title: '绕过边界：注释截断 / OR 改写',
      desc: 'VULN SQL 形如：`WHERE id = <requestedId> AND id = <scopeUserId>`。让 `<requestedId>` 变成恒真并截断后半段，就能越权读到非本人的记录。',
      payloads: ['VULN id: 1 OR 1=1 -- '],
    },
    {
      title: '制造错误（error-based 信号）',
      desc: '通过非法表达式触发 SQL 异常，观察系统错误差异（如果你后端加了 try/catch，会把信息包进统一响应）。',
      payloads: ['id: 1/0', 'id: abc'],
    },
  ],
  bypassIntro:
    '如果只做“像数字就放行”的弱校验（或只过滤 OR/UNION），通常仍可被括号/空白/等价表达式绕过。更可靠的做法是：输入强类型 + 参数绑定 + 业务鉴权优先。',
  bypass: [
    '等价逻辑变形：括号调整优先级，AND/OR 组合重写',
    '空白/换行/注释：绕过基于关键词的简单过滤（取决于实现）',
    '类型技巧：把输入包在表达式里（如 1+0、(1)），绕过“只匹配纯数字”的粗糙规则',
  ],
  fix: [
    '业务边界：先鉴权（only-self），不把“边界”寄托在 SQL 语句上。',
    '数据访问：强类型 + 参数绑定（Long + bind），禁止拼接（包括数字）。',
    '可观测性：生产避免回显 SQL/异常细节；靶场可用 meta.signalChannel + debug.template/params 做对照教学。',
  ],
};

export default function SqliUserDetail() {
  const { loading, result, run } = useRequestRunner();
  const [mode, setMode] = useState('vuln'); // vuln | safe
  const [form] = Form.useForm();
  const user = result?.success ? result?.data?.data : null;
  const meta = result?.data?.meta;

  const modeUi = useMemo(() => {
    return mode === 'safe'
      ? {
          label: 'SAFE',
          icon: <SafetyOutlined style={{ color: '#34d399' }} />,
          tag: <Tag color="green">Long + 参数化</Tag>,
          buttonDanger: false,
          runType: 'safeUser',
          submitIcon: <UserOutlined />,
          idPh: '2（只能查自己）',
          idRules: [
            { required: true, message: '请输入 id' },
            { pattern: /^[0-9]+$/, message: 'SAFE 仅接受数字 id' },
          ],
          request: (id) => sqliApi.safeUser(id),
        }
      : {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">WHERE 拼接</Tag>,
          buttonDanger: true,
          runType: 'vulnUser',
          submitIcon: <PlayCircleOutlined />,
          idPh: '1 OR 1=1 -- （尝试绕过 only-self）',
          idRules: [{ required: true, message: '请输入 id' }],
          request: (id) => sqliApi.vulnUser(id),
        };
  }, [mode]);

  return (
    <ThreePanelLab
      title="SQL 注入 · 用户详情（ID）"
      subtitle="关卡：where_id_authz（inband / error_based）。默认只显示一个请求面板，通过下拉切换 VULN/SAFE。"
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
          <Form form={form} layout="vertical" onFinish={(v) => run(modeUi.runType, () => modeUi.request(v.id))}>
            <Form.Item name="id" label="用户ID" rules={modeUi.idRules}>
              <Input placeholder={modeUi.idPh} inputMode={mode === 'safe' ? 'numeric' : undefined} />
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                danger={modeUi.buttonDanger}
                htmlType="submit"
                loading={loading}
                icon={modeUi.submitIcon}
              >
                获取详情
              </Button>
            </Form.Item>

            {/* 更贴近真实：详情结果在"请求区"直接展示 */}
            {user && (
              <div style={{ marginTop: 8 }}>
                <Descriptions
                  size="small"
                  column={1}
                  variant="borderless"
                  styles={{ label: { width: 96 } }}
                  items={[
                    { key: 'id', label: 'id', children: String(user.id ?? '') },
                    { key: 'username', label: 'username', children: String(user.username ?? '') },
                    { key: 'email', label: 'email', children: String(user.email ?? '') },
                    { key: 'role', label: 'role', children: String(user.role ?? '') },
                  ]}
                />
              </div>
            )}

            {result && !result.success && (
              <Alert
                type="warning"
                showIcon
                title={String(result?.data?.message ?? '请求失败')}
                style={{ marginTop: 12, background: 'rgba(245, 158, 11, 0.08)', border: '1px solid #2d3a4d' }}
              />
            )}
          </Form>
        ),
      }}
      safe={{ title: null, extra: null, children: null }}
      result={result}
    />
  );
}

