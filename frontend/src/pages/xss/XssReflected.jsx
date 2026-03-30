import { Alert, Button, Card, Collapse, Col, Form, Input, Row, Select, Space, Tag, Typography } from 'antd';
import { CodeOutlined, PlayCircleOutlined, SearchOutlined } from '@ant-design/icons';
import { useMemo, useRef, useState } from 'react';
import { xssApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import { reportXssUi } from './_shared/reporting';
import {
  FOCUS_HINT,
  MODE_OPTIONS,
  PAYLOADS_BY_TARGET,
  TARGET_OPTIONS,
  contextIdByTarget,
  getWeakLevelOptions,
  getWeakSummary,
} from './XssReflected.config';

const { Text } = Typography;

function buildAttrBoxSafe({ activeAttr, shareHref, safeJson }) {
  return `<div class="box ${activeAttr ? 'focus' : 'dim'}">
  <div class="muted">Share this search</div>
  <a id="shareLink" ${activeAttr ? '' : 'class="disabled" tabindex="-1" aria-disabled="true"'} href="#">Share link</a>
  <pre class="code" id="hrefVal"></pre>
  <pre class="code" id="hrefDom"></pre>
</div>
<script>
  (function(){
    var a = document.getElementById('shareLink');
    if (!a) return;
    var href = ${safeJson(JSON.stringify(shareHref))};
    // 只允许 http/https，否则降级 #
    try {
      var u = new URL(href, window.location.origin);
      if (u.protocol === 'http:' || u.protocol === 'https:') a.setAttribute('href', u.toString());
      else a.setAttribute('href', '#');
    } catch(e) {
      a.setAttribute('href', '#');
    }
    try {
      var v = document.getElementById('hrefVal');
      var d = document.getElementById('hrefDom');
      if (v) v.textContent = 'shareHref(raw) = ' + href;
      if (d) d.textContent = 'shareLink.outerHTML = ' + a.outerHTML;
    } catch(e2) {}
  })();
</script>`;
}

function buildAttrBoxVuln({ activeAttr, shareHref, safeJson }) {
  return `<div class="box ${activeAttr ? 'focus' : 'dim'}">
    <div class="muted">Share this search</div>
    <a id="shareLink" ${activeAttr ? '' : 'class="disabled" tabindex="-1" aria-disabled="true"'} href="${shareHref}">Share link</a>
    <pre class="code" id="hrefVal"></pre>
    <pre class="code" id="hrefDom"></pre>
  </div>
  <script>
    (function(){
      try{
        var raw = ${safeJson(JSON.stringify(shareHref))};
        var v = document.getElementById('hrefVal');
        if (v) v.textContent = 'shareHref(raw) = ' + raw;
      }catch(e){}
      try{
        var a = document.getElementById('shareLink');
        var d = document.getElementById('hrefDom');
        if (d) d.textContent = 'shareLink.outerHTML = ' + (a ? a.outerHTML : '<missing>');
      }catch(e2){}
    })();
  </script>`;
}

export default function XssReflected() {
  const { loading, result, run } = useRequestRunner();
  const [form] = Form.useForm();
  const [mode, setMode] = useState('vuln');
  const [target, setTarget] = useState('html');
  const [weakLevel, setWeakLevel] = useState(1); // 1 | 2（仅 mode=weak 时有意义）
  const previewRunIdRef = useRef(0);
  const [previewRunId, setPreviewRunId] = useState(0);

  const meta = result?.data?.meta;
  const data = result?.data?.data;

  const q = data?.q ?? form.getFieldValue('q') ?? '';
  const items = Array.isArray(data?.items) ? data.items : [];
  const highlightHtml = String(data?.highlightHtml ?? '');
  const emptyStateHtml = String(data?.emptyStateHtml ?? '');
  const shareHref = String(data?.shareHref ?? '#');
  const analyticsConfig = String(data?.analyticsConfig ?? '');
  const effectiveTarget = String(data?.target ?? target);
  const focus = FOCUS_HINT[effectiveTarget] || FOCUS_HINT.html;
  const effectiveWeakLevel = Number(data?.weakLevel ?? weakLevel) || 1;

  const weakLevelOptions = useMemo(() => getWeakLevelOptions(effectiveTarget), [effectiveTarget]);

  const weakSummary = useMemo(
    () => getWeakSummary(effectiveTarget, effectiveWeakLevel),
    [effectiveTarget, effectiveWeakLevel]
  );

  const focusFieldValue = useMemo(() => {
    if (effectiveTarget === 'attr') return shareHref;
    if (effectiveTarget === 'js') return analyticsConfig;
    return highlightHtml;
  }, [effectiveTarget, shareHref, analyticsConfig, highlightHtml]);

  const reportUi = (focusName, inputValue) => {
    reportXssUi({
      context: contextIdByTarget(target),
      mode,
      target,
      focus: focusName,
      input: inputValue,
      extras: { weakLevel },
    });
  };

  const srcDoc = useMemo(() => {
    // 企业搜索页常见 3 个区域（结果 / 分享 / 埋点）
    // 训练时只高亮当前区域，其它区域置灰（对非目标落点降级为 SAFE）
    const safeJson = (s) => String(s).replace(/</g, '\\u003c');
    const itemsHtml = items
      .map((x) => {
        const title = String(x?.title ?? '');
        const snippet = String(x?.snippet ?? '');
        return `<div class="item"><div class="t">${title}</div><div class="s">${snippet}</div></div>`;
      })
      .join('');

    const isAll = effectiveTarget === 'all';
    const activeHtml = effectiveTarget === 'html' || isAll;
    const activeAttr = effectiveTarget === 'attr' || isAll;
    const activeJs = effectiveTarget === 'js' || isAll;

    const htmlBox = `<div class="box ${activeHtml ? 'focus' : 'dim'}">
  <div class="muted">结果列表</div>
  ${itemsHtml || `<div class="muted" style="margin-top:6px">${emptyStateHtml}</div>`}
</div>`;
    const attrBox =
      mode === 'safe'
        ? buildAttrBoxSafe({ activeAttr, shareHref, safeJson })
        : buildAttrBoxVuln({ activeAttr, shareHref, safeJson });
    const jsBox =
      mode === 'safe'
        ? `<div class="box ${activeJs ? 'focus' : 'dim'}">
  <div class="muted">Analytics Preview（SAFE：JS string escaping）</div>
  <pre class="code" id="cfg"></pre>
</div>
<script>
  (function(){
    var q = ${safeJson(JSON.stringify(String(q ?? '')))};
    document.getElementById('cfg').textContent = "var q = '" + q + "';";
  })();
</script>`
        : `<div class="box ${activeJs ? 'focus' : 'dim'}">
  <div class="muted">Analytics Preview（VULN/WEAK：未做 JS 转义）</div>
  <pre class="code" id="cfg"></pre>
</div>
<script>
  // 漏洞点：把不可信 q 直接拼进 JS 单引号字符串（对照 XSS-Sec note：JS 闭合 + 注释绕过）
  var q = '${String(q ?? '')}';
  document.getElementById('cfg').textContent = "var q = '" + q + "';";
</script>`;

    // 注意：iframe 开了 sandbox 且未设置 allow-same-origin，无法使用 window.top 存状态；这里用 window.name 做跨导航持久化标记。
    const alertOnce = `<script>(function(){var runId=${safeJson(
      JSON.stringify(`xss_reflected:${previewRunId || 0}`)
    )};var marker='__owasp_alert_fired__'+runId;var orig=window.alert;function has(){try{return (window.name||'').indexOf(marker)!==-1;}catch(e){return false;}}function mark(){try{var n=window.name||'';if(n.indexOf(marker)!==-1)return;var next=n?(n+'|'+marker):marker;window.name=next.length>1800?marker:next;}catch(e){}}window.alert=function(){if(has())return;mark();try{return orig.apply(window,arguments);}catch(e){}};})();</script>`;

    return `<!doctype html><meta charset="utf-8">
${alertOnce}
<style>
  body{font-family:system-ui,Segoe UI,Arial;padding:12px;margin:0;background:#0f1419;color:#e6edf3}
  .box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;margin-bottom:12px;background:#161f2e}
  .muted{color:#8b9cb3;font-size:12px}
  .item{padding:8px 0;border-bottom:1px solid rgba(45,58,77,.6)}
  .item:last-child{border-bottom:none}
  .t{font-weight:600;margin-bottom:4px;color:#e6edf3}
  .s{color:#c6d3e5}
  a{color:#38bdf8}
  .dim{opacity:.55}
  .focus{border-color:#38bdf8; box-shadow: 0 0 0 1px rgba(56,189,248,.25)}
  .disabled{pointer-events:none; color:#8b9cb3; text-decoration:none}
  .code{margin:0;white-space:pre-wrap;word-break:break-word;color:#c6d3e5;font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "JetBrains Mono", monospace;font-size:12px}
</style>
${htmlBox}${attrBox}${jsBox}`;
  }, [items, emptyStateHtml, shareHref, effectiveTarget, mode, q, previewRunId]);

  const coachSnippet = useMemo(() => {
    const s = String(q ?? '');
    if (effectiveTarget === 'attr') {
      return (
        <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
          {'<a href="https://intra.example.local/search?q='}
          <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
            {s || '<YOUR_INPUT_HERE>'}
          </span>
          {'">Share link</a>'}
        </div>
      );
    }
    if (effectiveTarget === 'js') {
      return (
        <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
          {'window.analytics = {\n  event: "search",\n  q: "'}
          <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
            {s || '<YOUR_INPUT_HERE>'}
          </span>
          {'"\n}'}
        </div>
      );
    }
    return (
      <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
        {'<mark>'}
        <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
          {s || '<YOUR_INPUT_HERE>'}
        </span>
        {'</mark>'}
      </div>
    );
  }, [effectiveTarget, q]);

  return (
    <ThreePanelLab
      title="XSS · 反射型（企业搜索页）"
      subtitle="输入一个搜索词，页面会展示结果、分享链接与埋点配置。"
      hideSafe
      hideResponse
      vuln={{
        title: (
          <Space>
            <CodeOutlined style={{ color: '#94a3b8' }} />
            <span style={{ color: '#e6edf3' }}>搜索</span>
          </Space>
        ),
        extra: (
          <Space wrap>
            <Select
              size="small"
              value={mode}
              onChange={(v) => {
                setMode(v);
                reportUi('mode_change', form.getFieldValue('q') || '');
              }}
              options={MODE_OPTIONS}
              style={{ width: 160 }}
            />
            {mode === 'weak' && (
              <Select
                size="small"
                value={weakLevel}
                onChange={(v) => {
                  setWeakLevel(v);
                  reportUi('weak_level_change', form.getFieldValue('q') || '');
                }}
                options={weakLevelOptions}
                style={{ width: 320 }}
              />
            )}
            <Select
              size="small"
              value={target}
              onChange={(v) => {
                setTarget(v);
                // js 只保留一个 weakLevel，避免 UI 误导
                if (v === 'js') setWeakLevel(1);
                reportUi('target_change', form.getFieldValue('q') || '');
              }}
              options={TARGET_OPTIONS}
              style={{ width: 220 }}
            />
            <Tag color={mode === 'safe' ? 'green' : mode === 'weak' ? 'gold' : 'volcano'}>{mode.toUpperCase()}</Tag>
          </Space>
        ),
        children: (
          <>
            <Alert
              type="info"
              showIcon
              message="企业搜索页：输入关键词，系统会返回结果列表、分享链接与 Analytics 预览。"
              style={{ marginBottom: 12, background: 'rgba(56, 189, 248, 0.06)', border: '1px solid #2d3a4d' }}
            />

            <Row gutter={16}>
              <Col xs={24} lg={16}>
                <Form
                  form={form}
                  layout="vertical"
                  initialValues={{ q: 'xss' }}
                  onFinish={(v) => {
                    previewRunIdRef.current = Date.now();
                    setPreviewRunId(previewRunIdRef.current);
                    reportUi('submit', v?.q || '');
                    return run('xssSearchResults', () => xssApi.searchResults(mode, v.q || '', target, weakLevel));
                  }}
                >
                  <Form.Item name="q" label="搜索关键词">
                    <Input prefix={<SearchOutlined />} placeholder="例如：xss / 安全编码 / 内网公告" />
                  </Form.Item>
                  <Form.Item>
                    <Button type="primary" htmlType="submit" loading={loading} icon={<PlayCircleOutlined />}>
                      搜索
                    </Button>
                  </Form.Item>
                </Form>

                <Text type="secondary" style={{ fontSize: 12 }}>
                  预览（隔离在 iframe 内）
                </Text>
                <iframe
                  title="xss-search-preview"
                  sandbox="allow-scripts allow-modals"
                  srcDoc={srcDoc}
                  style={{ width: '100%', height: 360, border: '1px solid #2d3a4d', borderRadius: 8, marginTop: 8 }}
                />
              </Col>

              <Col xs={24} lg={8}>
                <Card
                  title={<span style={{ color: '#e6edf3' }}>Security Coach</span>}
                  style={{ background: '#161f2e', border: '1px solid #2d3a4d', height: '100%' }}
                >
                  <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.7 }}>
                    <div>当前练习点：</div>
                    <div>类型：{focus.type}</div>
                    <div>上下文：{focus.context}</div>
                    <div>落点：{focus.sink}</div>
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

                  {mode === 'safe' ? (
                    <Collapse
                      size="small"
                      style={{ marginTop: 12, background: 'rgba(56, 189, 248, 0.04)', border: '1px solid #2d3a4d' }}
                      items={[
                        effectiveTarget === 'html' && {
                          key: 'safe-html',
                          label: 'SAFE：HTML 内容是怎么防的？',
                          children: (
                            <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                              <div style={{ marginBottom: 6 }}>高亮/空状态这条链路只涉及 HTML 文本上下文：</div>
                              <pre
                                style={{
                                  background: '#0b1020',
                                  color: '#c6d3e5',
                                  padding: 10,
                                  borderRadius: 8,
                                  fontSize: 12,
                                  whiteSpace: 'pre-wrap',
                                }}
                              >
{`// ✅ SAFE：先按 HTML 文本编码，再拼模板
String safeHtml = HtmlUtils.htmlEscape(rawQ);
highlightHtml = "<mark>" + safeHtml + "</mark>";
emptyStateHtml = "未找到与 <b>" + safeHtml + "</b> 相关的结果";

// ❌ VULN：直接把原始输入塞进 innerHTML 模板
highlightHtml = "<mark>" + rawQ + "</mark>";
emptyStateHtml = "未找到与 <b>" + rawQ + "</b> 相关的结果";`}
                              </pre>
                              <div style={{ marginTop: 6 }}>
                                对比 SAFE / VULN 的 <code>highlightHtml</code>，你会看到 SAFE 始终把输入当“文本片段”，而不是“半成品 HTML”。
                              </div>
                            </div>
                          ),
                        },
                        effectiveTarget === 'attr' && {
                          key: 'safe-attr',
                          label: 'SAFE：Share 链接是怎么防的？',
                          children: (
                            <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                              <div style={{ marginBottom: 6 }}>Share 链接这条链路是 URL / 属性上下文：</div>
                              <pre
                                style={{
                                  background: '#0b1020',
                                  color: '#c6d3e5',
                                  padding: 10,
                                  borderRadius: 8,
                                  fontSize: 12,
                                  whiteSpace: 'pre-wrap',
                                }}
                              >
{`// ✅ SAFE：先按 URL 编码参数，再做协议白名单
String candidate = "https://intra.example.local/search?q=" + urlEncodeQuery(rawQ);
shareHref = allowHttpUrlOrHash(candidate); // 仅允许 http/https，其它变为 "#"

// ❌ VULN：直接在 href 里拼原始参数
shareHref = "https://intra.example.local/search?q=" + rawQ;`}
                              </pre>
                              <div style={{ marginTop: 6 }}>
                                SAFE 不关心具体 payload，而是先保证 href 是一个“规范 URL”，再限定为 <code>http/https</code>，杜绝
                                <code>javascript:</code>/<code>data:</code> 这类协议。
                              </div>
                            </div>
                          ),
                        },
                        effectiveTarget === 'js' && {
                          key: 'safe-js',
                          label: 'SAFE：Analytics JS 字符串是怎么防的？',
                          children: (
                            <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                              <div style={{ marginBottom: 6 }}>埋点配置这条链路是 JS 字符串上下文：</div>
                              <pre
                                style={{
                                  background: '#0b1020',
                                  color: '#c6d3e5',
                                  padding: 10,
                                  borderRadius: 8,
                                  fontSize: 12,
                                  whiteSpace: 'pre-wrap',
                                }}
                              >
{`// ✅ SAFE：对 JS 字符串做转义
String safeJs = escapeJsString(rawQ); // 处理 \ / 引号 / 换行
analyticsConfigJs = "{ \\"event\\\": \\"search\\", \\"q\\\": \\"" + safeJs + "\\" }";

// ❌ VULN：直接把原始输入拼到 JS 字符串字面量里
analyticsConfigJs = "{ \\"event\\\": \\"search\\", \\"q\\\": \\"" + rawQ + "\\" }";`}
                              </pre>
                              <div style={{ marginTop: 6 }}>
                                在 SAFE 下，你可以看看 <code>analyticsConfig</code> 字段里，对引号/反斜杠的处理已经和 VULN 明显不同。
                              </div>
                            </div>
                          ),
                        },
                      ].filter(Boolean)}
                    />
                  ) : (
                    <Collapse
                      size="small"
                      style={{ marginTop: 12, background: 'rgba(56, 189, 248, 0.04)', border: '1px solid #2d3a4d' }}
                      items={[
                        ...(mode === 'weak'
                          ? [
                              {
                                key: 'why-weak',
                                label: `为什么是 WEAK-${effectiveWeakLevel}？`,
                                children: (
                                  <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                                    <div style={{ marginBottom: 8 }}>
                                      {weakSummary.map((x) => (
                                        <div key={x}>- {x}</div>
                                      ))}
                                    </div>
                                    <Text type="secondary" style={{ fontSize: 12 }}>
                                      当前落点字段
                                    </Text>
                                    <div
                                      style={{
                                        marginTop: 8,
                                        padding: 10,
                                        borderRadius: 10,
                                        background: '#0b1020',
                                        border: '1px solid #2d3a4d',
                                        fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                                        whiteSpace: 'pre-wrap',
                                        wordBreak: 'break-word',
                                      }}
                                    >
                                      <div style={{ color: '#8b9cb3' }}>input：</div>
                                      <div style={{ marginBottom: 8 }}>{String(q || '') || '(空)'}</div>
                                      <div style={{ color: '#8b9cb3' }}>output（{focus.sink}）：</div>
                                      <div>{focusFieldValue || '(空)'}</div>
                                    </div>
                                  </div>
                                ),
                              },
                            ]
                          : []),
                        {
                          key: 'payloads',
                          label: '对照',
                          children: (
                            <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                              {(PAYLOADS_BY_TARGET[target] || PAYLOADS_BY_TARGET.html).map((p) => (
                                <Tag
                                  key={`${p.kind}:${p.value}`}
                                  title={p.expect}
                                  color={
                                    p.kind.includes('对照')
                                      ? 'gold'
                                      : p.kind.includes('验证')
                                        ? 'blue'
                                        : p.kind.includes('定位')
                                          ? 'default'
                                          : 'default'
                                  }
                                  style={{
                                    cursor: 'pointer',
                                    fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                                    maxWidth: '100%',
                                    whiteSpace: 'normal',
                                    wordBreak: 'break-word',
                                    lineHeight: 1.25,
                                    paddingBlock: 6,
                                    paddingInline: 10,
                                    marginInlineEnd: 0,
                                  }}
                                  onClick={() => {
                                    form.setFieldsValue({ q: p.value });
                                    reportUi('payload_click', p.value);
                                  }}
                                >
                                  <div style={{ fontWeight: 600 }}>{p.kind}</div>
                                  <div style={{ opacity: 0.92 }}>{p.value}</div>
                                </Tag>
                              ))}
                            </div>
                          ),
                        },
                        {
                          key: 'details',
                          label: '查看技术细节',
                          children: (
                            <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                              <div>module: {meta?.module || 'xss'}</div>
                              <div>mode: {meta?.mode || '-'}</div>
                              <div>contextId: {meta?.context || '-'}</div>
                              <div>cwe: {meta?.cwe || '-'}</div>
                              <div>signal: {meta?.signalChannel || '-'}</div>
                            </div>
                          ),
                        },
                      ]}
                    />
                  )}
                </Card>
              </Col>
            </Row>
          </>
        ),
      }}
      safe={{ title: null, extra: null, children: null }}
      result={result}
    />
  );
}