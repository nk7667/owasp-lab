import { Alert, Button, Card, Col, Collapse, Form, Input, Row, Select, Space, Tag, Tabs, Typography } from 'antd';
import { PlayCircleOutlined } from '@ant-design/icons';
import { useEffect, useMemo, useState } from 'react';
import SafeHtml from '../../components/SafeHtml';
import { assertSafeHtml, sanitizeToSafeHtml } from '../../security/safeHtml';
import { reportCoachUi } from './_shared/coachUi';

const { Title, Paragraph, Text } = Typography;
const { TextArea } = Input;

export default function XssDom() {
  const [form] = Form.useForm();
  const [mode, setMode] = useState('vuln');
  const [lab, setLab] = useState('postmessage'); // postmessage | csp_jsonp | canonical
  const [weakLevel, setWeakLevel] = useState(1); // 1 | 2（仅 mode=weak 且部分 lab 有意义）
  const [runSeq, setRunSeq] = useState(0);
  const [safeVariant, setSafeVariant] = useState('plain'); // plain | rich（仅 SAFE 下有意义）

  const keyword = Form.useWatch('keyword', form);
  const qsValue = Form.useWatch('qs', form);

  // DOM SAFE 工具箱：富文本治理（原 /governance 思路内嵌）
  const [hardenMode, setHardenMode] = useState(() => {
    try {
      const v = String(window?.localStorage?.getItem('xss_harden_mode') || '').toLowerCase();
      return v || 'log';
    } catch {
      return 'log';
    }
  });
  const [richDraft, setRichDraft] = useState(
    '<p><b>富文本示例</b>：允许 <code>&lt;b&gt;</code>/<code>&lt;a&gt;</code> 等。</p><p>攻击输入：<img src=x onerror=alert(1)></p>'
  );
  const [richStatus, setRichStatus] = useState('');

  useEffect(() => {
    try {
      window?.localStorage?.setItem('xss_harden_mode', hardenMode);
    } catch {
      // ignore
    }
    reportUi('harden_mode_change', hardenMode);
  }, [hardenMode]);

  const [richSafe, setRichSafe] = useState(() => sanitizeToSafeHtml(richDraft, { source: 'dom_safe_richtext_demo' }));

  const contextIdByLab = (x) => {
    if (x === 'csp_jsonp') return 'xss_csp_jsonp_gadget';
    if (x === 'canonical') return 'xss_seo_canonical_attr_escape';
    return 'xss_dom_postmessage_innerHTML';
  };

  const reportUi = (focusName, inputValue) => {
    reportCoachUi({
      context: contextIdByLab(lab),
      mode,
      target: lab,
      focus: focusName,
      input: inputValue,
      extras: { weakLevel },
    });
  };

  const labOptions = [
    { value: 'postmessage', label: 'PostMessage 链（XSS-Sec L16）' },
    { value: 'csp_jsonp', label: 'CSP + JSONP gadget（XSS-Sec L17）' },
    { value: 'canonical', label: 'Canonical 属性逃逸（XSS-Sec L26）' },
  ];

  const modeOptions = [
    { value: 'vuln', label: 'VULN' },
    { value: 'weak', label: 'WEAK' },
    { value: 'safe', label: 'SAFE' },
  ];

  const payloadItems = useMemo(() => {
    if (lab === 'postmessage') {
      return [
        {
          kind: '对照（WEAK-2 会拦）',
          expect:
            '走“自测同链路”稳定版：后端把 keyword 当作消息写入 out。WEAK-2 黑名单会拦 javascript: 子串，因此该输入会被拦截并显示提示。',
          value: '<img src=x onerror="javascript:alert(1)">',
        },
        {
          kind: '验证（WEAK-2 仍可绕过）',
          expect:
            '走“自测同链路”稳定版：黑名单只拦 <script/javascript:，不拦事件属性，因此仍可触发（应弹窗）。',
          value: '<img src=x onerror=alert(1)>',
        },
        {
          kind: '变体（另一种绕过）',
          expect: '另一种常见载体：svg/onload（也不依赖 <script>）。',
          value:
            "data:text/html,%3Cscript%3EsetTimeout%28function%28%29%7Bparent.postMessage%28%22%3Csvg%20onload%3Dalert%281%29%3E%3C%2Fsvg%3E%22%2C%27%2A%27%29%7D%2C50%29%3C%2Fscript%3E",
        },
        {
          kind: '对照',
          expect: '不弹窗，只显示 Received: hello',
          value: 'hello',
        },
        {
          kind: '提示',
          expect: '为什么只收字符串：开发环境可能有插件/HMR 发对象消息，容易污染训练信号',
          value: '[debug] message as string',
        },
      ];
    }
    if (lab === 'csp_jsonp') {
      return [
        {
          kind: '对照',
          expect: '通常不会弹窗（被 CSP 拦截），控制台会看到 CSP 违规提示',
          value: '<script>alert(1)</script>',
        },
        {
          kind: '验证',
          expect: 'VULN/WEAK：应弹窗（JSONP gadget）。SAFE 会把 callback 收敛到固定 cb，不应弹窗（可能有 console error）。',
          value: '<script src="?callback=alert"></script>',
        },
        {
          kind: 'WEAK（对照）',
          expect: 'WEAK-1：关键字替换黑名单可被 bracket+拼接绕过（JSONP 会调用 callback 并传入对象）',
          value: '<script src="?callback=window[\\\'al\\\'+\\\'ert\\\']"></script>',
        },
        {
          kind: 'WEAK-2（新分支）',
          expect:
            "report-uri 拼接注入：WEAK-2 把调试 token 直接拼进 CSP 的 report-uri（更真实：不在页面表单里提供 token，需要你手动在 URL 追加 &token=...）。用分号注入 script-src-elem 'unsafe-inline' 复活 inline 脚本，应弹窗。",
          value: '<script>alert(1)</script>',
          token: ";script-src-elem 'unsafe-inline'",
        },
      ];
    }
    return [
      {
        kind: '验证',
        expect: '运行后查看预览页源代码：canonical 标签应出现 onclick；并尝试触发（页面会自动触发一次）',
        value: "%27onclick=%27alert(1)%27x=%27",
      },
      {
        kind: '验证',
        expect: '同上（只是更明显的属性注入形态）',
        value: "%27onclick=%27alert(1)%27style=%27display:block%27x=%27",
      },
      {
        kind: '对照',
        expect: '不会发生变化（用于确认你输入确实进入 canonical）',
        value: "foo=bar",
      },
    ];
  }, [lab]);

  const labGoal = useMemo(() => {
    if (lab === 'postmessage') {
      return '学习目标：理解 postMessage 的信任边界（origin/source），以及为什么把消息写入 innerHTML 会触发 DOM XSS；SAFE 应改为 origin 校验 + textContent。';
    }
    if (lab === 'csp_jsonp') {
      return "目标：理解 CSP 禁止 inline 后，为什么同源 JSONP 会变成可利用的脚本 gadget。";
    }
    return "目标：理解“转义选项/引号处理错误”如何导致属性逃逸（建议查看页面源代码）。";
  }, [lab]);

  const domSafePlaybook = useMemo(() => {
    if (mode !== 'safe') {
      return (
        <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.65 }}>
          <div style={{ marginBottom: 6 }}>
            先把实验现象跑出来；最后切到 <b>SAFE</b> 复盘“工程解法”。
          </div>
          <div>
            记一个总公式：<b>DOM SAFE</b> = 信任边界校验（来源） + 危险 sink 替换（落点） +（需要富文本时）白名单清洗 + 可观测/可治理。
          </div>
        </div>
      );
    }

    const hi = (on) => (on ? { color: '#e6edf3' } : { color: '#8b9cb3', opacity: 0.9 });
    const isPost = lab === 'postmessage';
    const isJsonp = lab === 'csp_jsonp';
    const isCanon = lab === 'canonical';

    const Plain = (
      <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.75 }}>
        <div style={{ marginBottom: 8 }}>
          <b>普通 DOM SAFE（不需要富文本）</b>：绝大多数业务都属于这一类。目标是“把输入当数据/文本”，而不是当 HTML/代码。
        </div>

        <div style={{ marginBottom: 8 }}>
          <span style={{ color: '#8b9cb3' }}>本关会点亮的段落：</span>{' '}
          {isPost && <Tag color="blue">信任边界 + textContent</Tag>}
          {isJsonp && <Tag color="purple">别把数据当代码（JSONP）</Tag>}
          {isCanon && <Tag color="geekblue">上下文编码（属性/规范化）</Tag>}
        </div>

        <div style={{ marginTop: 6, ...hi(true) }}>
          1) <b>不当 HTML</b>：使用 <code>textContent</code> / React 默认插值渲染文本，避免 <code>innerHTML</code> /{' '}
          <code>dangerouslySetInnerHTML</code> / <code>document.write</code>。
        </div>

        <div style={{ marginTop: 10, ...hi(isPost) }}>
          2) <b>信任边界（PostMessage）</b>：校验 <code>origin</code> + <code>source</code> + 类型（只收字符串）；SAFE 下最终写入{' '}
          <code>textContent</code>。
        </div>

        <div style={{ marginTop: 10, ...hi(isJsonp) }}>
          3) <b>别把数据当代码（CSP/JSONP）</b>：真实工程尽量不要 JSONP（改 JSON + CORS）。若必须保留，callback 必须是严格结构白名单；
          另外不要把用户输入拼进安全响应头（例如 CSP 的 <code>report-uri</code>/<code>report-to</code>）。
        </div>

        <div style={{ marginTop: 10, ...hi(isCanon) }}>
          4) <b>上下文编码（属性/URL）</b>：不拼不可信 query 或只拼白名单参数；属性上下文完整转义（含引号）；先规范化/解码，再输出编码（顺序不能错）。
        </div>

        <div style={{ marginTop: 10, ...hi(true) }}>
          5) <b>可观测/可治理</b>：用事件上报把关键操作记录下来（你现在每次切 lab/mode、点击 payload、运行预览都会上报）。
        </div>
      </div>
    );

    const RichDemo = (
      <div style={{ marginTop: 10 }}>
        <Space wrap style={{ marginBottom: 10 }}>
          <span style={{ color: '#8b9cb3', fontSize: 12 }}>运行期收敛：</span>
          <Select
            value={hardenMode}
            onChange={(v) => setHardenMode(v)}
            options={[
              { value: 'off', label: 'off（不记录）' },
              { value: 'log', label: 'log（记录，不拦截）' },
              { value: 'block', label: 'block（记录 + 拦截）' },
            ]}
            style={{ width: 240 }}
          />
          <Button
            onClick={() => {
              try {
                const safe = sanitizeToSafeHtml(richDraft, { source: 'dom_safe_richtext_demo' });
                setRichSafe(safe);
                setRichStatus('已更新预览（sanitizeToSafeHtml）。');
                reportUi('richtext_sanitize_preview', richDraft);
              } catch (e) {
                setRichStatus(`更新失败：${(e && e.message) || String(e)}`);
              }
            }}
          >
            更新预览
          </Button>
          <Button
            onClick={() => {
              try {
                assertSafeHtml(richDraft, { source: 'dom_safe_richtext_demo_misuse' });
                setRichStatus('误用演示：未抛错（当前可能是 off/log）。请查看 Coach 事件记录。');
              } catch (e) {
                setRichStatus(`误用演示：被拦截（block）— ${(e && e.message) || String(e)}`);
              }
            }}
          >
            误用演示：把 raw 当 SafeHtml
          </Button>
        </Space>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div>
            <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 6 }}>输入（raw HTML）</div>
            <TextArea
              value={richDraft}
              onChange={(e) => setRichDraft(e.target.value)}
              autoSize={{ minRows: 6, maxRows: 10 }}
              style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}
            />
            {richStatus && (
              <div style={{ marginTop: 8, color: '#8b9cb3', fontSize: 12 }}>
                状态：<span style={{ color: '#c6d3e5' }}>{richStatus}</span>
              </div>
            )}
          </div>
          <div>
            <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 6 }}>
              输出（SAFE：<code>sanitizeToSafeHtml</code> → <code>&lt;SafeHtml/&gt;</code>）
            </div>
            <div style={{ border: '1px solid #2d3a4d', borderRadius: 10, padding: 10, background: '#0f1419', minHeight: 140 }}>
              <SafeHtml value={richSafe} />
            </div>
            <details style={{ marginTop: 8 }}>
              <summary style={{ color: '#8b9cb3', fontSize: 12, cursor: 'pointer' }}>查看清洗后 HTML（调试用）</summary>
              <pre style={{ marginTop: 8, color: '#c6d3e5', fontSize: 12, whiteSpace: 'pre-wrap' }}>{richSafe.html}</pre>
            </details>
          </div>
        </div>
      </div>
    );

    const Rich = (
      <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.75 }}>
        <div style={{ marginBottom: 8 }}>
          <b>富文本 DOM SAFE（需要富文本）</b>：业务必须允许一部分 HTML（评论/公告/富文本编辑器）。这时不能用纯文本渲染替代。
        </div>
        <div style={{ marginTop: 6 }}>
          1) 先 <code>sanitizeToSafeHtml(raw)</code>：白名单收敛（禁 <code>on*</code>、危险标签、危险协议）。
        </div>
        <div style={{ marginTop: 6 }}>
          2) 再 <code>&lt;SafeHtml value=... /&gt;</code>：统一渲染入口（业务侧不直接写 <code>dangerouslySetInnerHTML</code>）。
        </div>
        <div style={{ marginTop: 6 }}>
          3) 治理闭环：off/log/block（先观测再阻断）+ lint 规则提示/阻断危险 sink。
        </div>
        <Collapse
          defaultActiveKey={[]}
          style={{ marginTop: 10, background: '#0b1020', border: '1px solid #2d3a4d', borderRadius: 12 }}
          items={[
            {
              key: 'demo',
              label: '展开：富文本治理演示（sanitize + SafeHtml + off/log/block）',
              children: RichDemo,
            },
          ]}
        />
      </div>
    );

    return (
      <Tabs
        activeKey={safeVariant}
        onChange={(k) => setSafeVariant(k)}
        items={[
          { key: 'plain', label: '普通 SAFE（不需要富文本）', children: Plain },
          { key: 'rich', label: '富文本 SAFE（需要富文本）', children: Rich },
        ]}
      />
    );
  }, [mode, lab, hardenMode, richDraft, richSafe, richStatus, safeVariant, weakLevel]);

  const iframeSrc = useMemo(() => {
    if (lab === 'postmessage') {
      const k = encodeURIComponent(keyword || '');
      return `/api/v1/xss/${mode}/dom/postmessage/page?keyword=${k}&weakLevel=${weakLevel}&__r=${runSeq}`;
    }
    if (lab === 'csp_jsonp') {
      const k = encodeURIComponent(keyword || '');
      return `/api/v1/xss/${mode}/csp/jsonp?keyword=${k}&weakLevel=${weakLevel}&__r=${runSeq}`;
    }
    const qsRaw = String(qsValue || '');
    const qs = qsRaw ? (qsRaw.startsWith('?') ? qsRaw : `?${qsRaw}`) : '';
    const base = `/api/v1/xss/${mode}/seo/canonical${qs}`;
    return base + (base.includes('?') ? '&' : '?') + `__r=${runSeq}`;
  }, [lab, mode, keyword, qsValue, runSeq, weakLevel]);

  const coachFocus = useMemo(() => {
    if (lab === 'postmessage') {
      return { type: 'DOM XSS', context: '跨窗口消息（postMessage）', sink: 'out.innerHTML' };
    }
    if (lab === 'csp_jsonp') {
      return { type: 'DOM/策略', context: 'CSP + 同源 JSONP gadget', sink: 'script-src self + JSONP callback' };
    }
    return { type: 'DOM/编码', context: 'Canonical（属性上下文）', sink: "href='...'(单引号属性)" };
  }, [lab]);

  const weakSummary = useMemo(() => {
    if (mode !== 'weak') return [];
    if (lab === 'postmessage') {
      if (weakLevel >= 2) {
        return [
          'WEAK-2 做了什么：加了黑名单（<script / javascript:）并在命中时直接提示拦截。',
          "WEAK-2 漏了什么：仍然把消息写进 innerHTML；黑名单无法覆盖事件属性/非 script 载体。",
          "你该观察什么：同一条输入在 VULN/WEAK-2/SAFE 下 out 区域的写入方式不同（innerHTML vs textContent）。",
        ];
      }
      return [
        "WEAK-1 做了什么：为了兼容 data:/file:，把 origin==='null' 当作可信；仍使用 innerHTML。",
        'WEAK-1 漏了什么：信任边界校验是错的（null origin 不可信），并且危险 sink 未替换。',
        "你该观察什么：VULN/WEAK 的 out 是 innerHTML；SAFE 才是 origin allowlist + textContent。",
      ];
    }
    if (lab === 'csp_jsonp') {
      if (weakLevel >= 2) {
        return [
          'WEAK-2 做了什么：JSONP callback 用“宽松 allowlist”兼容 bracket 访问；并把调试 token 拼进 CSP 的 report-uri。',
          "WEAK-2 漏了什么：[] 内表达式没约束，仍可构造危险回调；CSP 响应头拼接未编码/未拒绝 ';'，可被注入新指令。",
          '你该观察什么：页面里会显示 CSP 字符串；以及 JSONP 分支返回的 JS 里 callback 是否被收敛。',
        ];
      }
      return [
        'WEAK-1 做了什么：对 callback 做关键字替换（alert / document.cookie）。',
        "WEAK-1 漏了什么：黑名单可被字符串拼接/属性访问绕过；本质仍是“把数据当代码”。",
        '你该观察什么：CSP 禁 inline 但允许同源外链脚本；JSONP 端点是否仍可执行可控回调。',
      ];
    }
    return [
      "WEAK 做了什么：尝试做属性转义/处理，但使用了“半吊子转义”（不转义单引号）或错误的 decode 顺序。",
      "WEAK 漏了什么：属性上下文必须完整转义（含 ' 和 \"），且必须先规范化/解码再输出编码，顺序不能错。",
      '你该观察什么：查看页面源代码里的 canonical link href，是否出现额外属性（例如 onclick）。',
    ];
  }, [lab, mode, weakLevel]);

  const coachSnippet = useMemo(() => {
    const hi = (v) => (
      <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
        {v || '<YOUR_INPUT_HERE>'}
      </span>
    );
    if (lab === 'postmessage') {
      const v = String(keyword || '');
      return (
        <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
          {'e.data = "'}
          {hi(v)}
          {'";\n'}
          {"document.getElementById('out').innerHTML = 'Received: ' + e.data;"}
        </div>
      );
    }
    if (lab === 'csp_jsonp') {
      const v = String(keyword || '');
      return (
        <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
          {'<div>Results for: '}
          {hi(v)}
          {'</div>'}
        </div>
      );
    }
    const v = String(qsValue || '');
    return (
      <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
        {"<link rel=\"canonical\" href='http://site.local/seo/canonical?"}
        {hi(v)}
        {"'>"}
      </div>
    );
  }, [lab, keyword, qsValue]);

  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        XSS · DOM 型
      </Title>

      <Row gutter={16}>
        <Col xs={24} lg={16}>
          <Card
            styles={{ body: { background: '#0f1419', border: '1px solid #2d3a4d' } }}
            style={{ borderRadius: 12, background: '#0f1419', border: '1px solid #2d3a4d' }}
          >
            <Space wrap style={{ marginBottom: 12 }}>
              <Select
                value={lab}
                onChange={(v) => {
                  setLab(v);
                  setWeakLevel(1);
                  setSafeVariant('plain');
                  reportUi('lab_change', v === 'canonical' ? (form.getFieldValue('qs') || '') : (form.getFieldValue('keyword') || ''));
                }}
                options={labOptions}
                style={{ width: 320 }}
              />
              <Select
                value={mode}
                onChange={(v) => {
                  setMode(v);
                  reportUi('mode_change', lab === 'canonical' ? (form.getFieldValue('qs') || '') : (form.getFieldValue('keyword') || ''));
                }}
                options={modeOptions}
                style={{ width: 120 }}
              />
              {mode === 'weak' && (lab === 'postmessage' || lab === 'csp_jsonp') && (
                <Select
                  value={weakLevel}
                  onChange={(v) => {
                    setWeakLevel(v);
                    reportUi('weak_level_change', lab === 'canonical' ? (form.getFieldValue('qs') || '') : (form.getFieldValue('keyword') || ''));
                  }}
                  options={[
                    { value: 1, label: 'WEAK-1（典型错误修复）' },
                    { value: 2, label: lab === 'postmessage' ? 'WEAK-2（黑名单：<script/javascript:）' : 'WEAK-2（宽松 allowlist + CSP 头拼接）' },
                  ]}
                  style={{ width: 280 }}
                />
              )}
            </Space>

            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12, background: 'rgba(56, 189, 248, 0.06)', border: '1px solid #2d3a4d' }}
              title={
                lab === 'postmessage'
                  ? 'PostMessage（L16）'
                  : lab === 'csp_jsonp'
                    ? "CSP 禁 inline，但同源 JSONP 可作为 被用来完成攻击链的可复用执行点。（script-src 'self'）。"
                    : "canonical 的 href 用单引号包裹，转义不含单引号导致逃逸。"
              }
              description={
                <div>
                  <div style={{ marginBottom: 6 }}>{labGoal}</div>
                  <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.6 }}>
                    {lab === 'postmessage' && <div>对照点：VULN/WEAK 用 innerHTML；SAFE 用 textContent 且校验 origin/source。</div>}
                    {lab === 'csp_jsonp' && <div>观测点：inline script 被 CSP 拦截；同源 JSONP gadget 在 callback 可控时会执行。</div>}
                    {lab === 'canonical' && <div>观测点：看页面源代码里的 canonical href/是否出现额外属性。</div>}
                  </div>
                </div>
              }
            />

            <Collapse
              defaultActiveKey={['playbook']}
              style={{ marginBottom: 12, background: '#0b1020', border: '1px solid #2d3a4d', borderRadius: 12 }}
              items={[
                {
                  key: 'playbook',
                  label: 'DOM SAFE 总答案',
                  children: domSafePlaybook,
                },
              ].filter(Boolean)}
            />

            <Form
              form={form}
              layout="vertical"
              initialValues={{ keyword: '', qs: '' }}
              onFinish={() => {
                // 强制刷新 iframe（即使参数未变化）
                reportUi('run_preview', lab === 'canonical' ? (form.getFieldValue('qs') || '') : (form.getFieldValue('keyword') || ''));
                setRunSeq((x) => x + 1);
              }}
            >
              {lab !== 'canonical' && (
                <Form.Item
                  name="keyword"
                  label={lab === 'csp_jsonp' ? 'keyword（反射点：HTML，CSP 环境）' : 'keyword（iframe src：建议 data:text/html,...)'}
                >
                  <Input
                    placeholder={
                      lab === 'csp_jsonp'
                        ? '例如：<script src="?callback=alert(1)"></script>'
                        : '例如：data:text/html,<script>parent.postMessage(...)</script>'
                    }
                  />
                </Form.Item>
              )}
              {lab === 'canonical' && (
                <Form.Item name="qs" label="query string（拼接进 canonical href 的原材料；例如：%27onclick%3D%27alert(1)）">
                  <Input placeholder="例如：%27accesskey=%27x%27onclick=%27alert(1)" />
                </Form.Item>
              )}

              <Button type="primary" htmlType="submit" icon={<PlayCircleOutlined />}>
                运行预览
              </Button>
            </Form>

            <Paragraph style={{ color: '#8b9cb3', fontSize: 12, marginTop: 12, marginBottom: 8 }}>
              预览（iframe 指向后端页面；用于演示 CSP/headers 与真实 DOM 行为）
            </Paragraph>
            <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 8 }}>
              <Text style={{ color: '#8b9cb3' }}>当前预览地址：</Text>
              <span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', color: '#c6d3e5' }}> {iframeSrc}</span>
              <a href={iframeSrc} target="_blank" rel="noreferrer" style={{ marginLeft: 8, color: '#38bdf8' }}>
                新标签打开
              </a>
            </div>
            <iframe
              title="xss-dom-preview"
              sandbox="allow-scripts allow-modals allow-forms"
              src={iframeSrc}
              key={`${iframeSrc}::${runSeq}`}
              style={{ width: '100%', height: 420, border: '1px solid #2d3a4d', borderRadius: 10, background: '#0b1020' }}
            />
          </Card>
        </Col>

        <Col xs={24} lg={8}>
          <Card title={<span style={{ color: '#e6edf3' }}>Security Coach</span>} style={{ background: '#161f2e', border: '1px solid #2d3a4d', height: '100%' }}>
            <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.7 }}>
              <div>当前练习点：</div>
              <div>类型：{coachFocus.type}</div>
              <div>上下文：{coachFocus.context}</div>
              <div>落点：{coachFocus.sink}</div>
              {mode === 'weak' && (
                <div style={{ marginTop: 6 }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    WEAK 表示：做了部分处理但仍可绕过（点开查看原因）
                  </Text>
                </div>
              )}
            </div>

            <div style={{ marginTop: 12 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                你的输入会被插入到这里：
              </Text>
              <div
                style={{
                  marginTop: 8,
                  padding: 12,
                  borderRadius: 10,
                  background: '#0b1020',
                  border: '1px solid #2d3a4d',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-word',
                }}
              >
                {coachSnippet}
              </div>
            </div>

            <Collapse
              size="small"
              style={{ marginTop: 12, background: 'rgba(56, 189, 248, 0.04)', border: '1px solid #2d3a4d' }}
              items={[
                ...(mode === 'weak'
                  ? [
                      {
                        key: 'why-weak',
                        label: '为什么是 WEAK？',
                        children: (
                          <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                            {weakSummary.map((x) => (
                              <div key={x}>- {x}</div>
                            ))}
                          </div>
                        ),
                      },
                    ]
                  : []),
                {
                  key: 'payloads',
                  label: '对照',
                  children: (
                    <div style={{ marginTop: 4 }}>
                      {payloadItems.map((it) => {
                        const k = String(it?.kind ?? '');
                        const tagColor = k.includes('验证') ? 'blue' : k.includes('对照') ? 'gold' : k.includes('WEAK') ? 'volcano' : undefined;
                        return (
                          <Tag
                            key={`${it.kind}:${it.value}:coach`}
                            color={tagColor}
                            style={{
                              cursor: 'pointer',
                              marginBottom: 6,
                              fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                              whiteSpace: 'normal',
                              maxWidth: '100%',
                              wordBreak: 'break-word',
                              lineHeight: 1.25,
                              paddingBlock: 6,
                              paddingInline: 10,
                              marginInlineEnd: 0,
                              display: 'block',
                            }}
                            onClick={() => {
                              if (lab === 'canonical') form.setFieldsValue({ qs: it.value });
                              else form.setFieldsValue({ keyword: it.value });
                              reportUi('payload_click', it.value);
                            }}
                          >
                            <div style={{ fontWeight: 600 }}>{it.kind}</div>
                            <div style={{ opacity: 0.92, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                              {lab === 'csp_jsonp' && it.token ? `keyword=${it.value}\n手动追加：&token=${it.token}` : it.value}
                            </div>
                            <div style={{ marginTop: 6, color: '#8b9cb3', fontSize: 11, whiteSpace: 'pre-wrap', lineHeight: 1.35 }}>
                              预期：{it.expect}
                            </div>
                          </Tag>
                        );
                      })}
                    </div>
                  ),
                },
                {
                  key: 'details',
                  label: '查看技术细节',
                  children: (
                    <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                      <div>mode: {mode}</div>
                      <div>lab: {lab}</div>
                      {mode === 'weak' && (lab === 'postmessage' || lab === 'csp_jsonp') && <div>weakLevel: {weakLevel}</div>}
                      {mode === 'safe' && <div>safeVariant: {safeVariant}</div>}
                      {mode === 'safe' && <div>hardenMode: {hardenMode}</div>}
                      <div>contextId: {contextIdByLab(lab)}</div>
                      <div style={{ marginTop: 6 }}>
                        previewUrl:
                        <div style={{ marginTop: 6, fontFamily: 'JetBrains Mono, ui-monospace, monospace', wordBreak: 'break-word' }}>{iframeSrc}</div>
                      </div>
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}

