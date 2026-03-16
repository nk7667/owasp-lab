import { Alert, Button, Card, Collapse, Col, Form, Input, Row, Select, Space, Tag, Typography } from 'antd';
import { PlayCircleOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useEffect, useMemo, useRef, useState } from 'react';
import { xssApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import { reportCoachUi } from './_shared/coachUi';

const { Text } = Typography;
const { TextArea } = Input;

const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN（原始漏洞）' },
  { value: 'weak', label: 'WEAK（错误修复）' },
  { value: 'safe', label: 'SAFE（正确修复）' },
];

const FOCUS_OPTIONS = [
  { value: 'content', label: '评论内容（HTML 内容）' },
  { value: 'website', label: '个人主页（链接地址）' },
];

const PAYLOADS_BY_FOCUS = {
  content: [
    {
      kind: '对照（WEAK 会挡住）',
      expect: 'WEAK 会把 <script 变形（<script→<scr_ipt）；用于对照“WEAK 做了什么”。',
      value: '<script>alert(1)</script>',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '事件属性不在弱黑名单范围内；用于对照“WEAK 没做什么”。',
      value: "<img src=x onerror=alert('stored-xss')>",
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '另一种载体（不依赖 <script>）。',
      value: '<svg onload=alert(1)></svg>',
    },
  ],
  // WEAK 常见：只挡 javascript: 字面量；补充实体编码/协议变体，帮助理解“弱在哪”
  website: [
    {
      kind: '对照（WEAK 会改写）',
      expect: 'WEAK 常见做法是“移除 javascript: 字面量”；观察管理员页 link 的 href 变化。',
      value: 'javascript:alert(1)',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '实体/混淆形态不等于字面量；字符串替换可能漏掉。',
      value: 'jav&#x61;script:alert(1)',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '非 javascript: 也可能危险（示例：data:）。SAFE 应做协议白名单（http/https）。',
      value: 'data:text/html,<script>alert(1)</script>',
    },
  ],
};

const FOCUS_HINT = {
  content: { type: 'Stored XSS', context: 'HTML 内容', sink: 'content' },
  website: { type: 'Stored XSS', context: '链接地址（属性）', sink: 'websiteHref' },
};

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export default function XssStored() {
  const { loading, result, run } = useRequestRunner();
  const [form] = Form.useForm();
  const [mode, setMode] = useState('vuln');
  const [focus, setFocus] = useState('content'); // content | website
  const [weakLevel, setWeakLevel] = useState(1); // 1 | 2（仅 mode=weak 时有意义）
  const [adminItems, setAdminItems] = useState([]);
  const [lastSavedId, setLastSavedId] = useState(null);
  const adminPreviewRunIdRef = useRef(0);
  const [adminPreviewRunId, setAdminPreviewRunId] = useState(0);
  const modeRef = useRef(mode);
  const weakLevelRef = useRef(weakLevel);

  useEffect(() => {
    modeRef.current = mode;
    weakLevelRef.current = weakLevel;
  }, [mode, weakLevel]);

  // 从预览 iframe（sandbox / null origin）接收删除请求，由父页面执行 API 并刷新预览
  useEffect(() => {
    const onMsg = (e) => {
      const d = e?.data;
      if (!d || typeof d !== 'object') return;
      if (d.__owasp !== 'xss_stored_admin_preview') return;
      if (d.op !== 'delete') return;
      const id = Number(d.id);
      if (!Number.isFinite(id)) return;
      run(`xssCommentDeleteFromPreview:${id}`, async () => {
        reportUi('xss_stored_admin_html_innerHTML', 'delete_one', String(id));
        await xssApi.commentDelete(modeRef.current, id, weakLevelRef.current);
        const review = await xssApi.adminReview(modeRef.current, weakLevelRef.current);
        setAdminItems(review.data?.data?.items ?? []);
        return review;
      });
    };
    window.addEventListener('message', onMsg);
    return () => window.removeEventListener('message', onMsg);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const meta = result?.data?.meta;
  const focusHint = FOCUS_HINT[focus] || FOCUS_HINT.content;

  const reportUi = (ctx, focusName, inputValue) => {
    reportCoachUi({
      context: ctx,
      mode,
      target: focus,
      focus: focusName,
      input: inputValue,
      extras: { weakLevel },
    });
  };

  // 自动刷新：避免“提交后预览为空”造成误判
  useEffect(() => {
    adminPreviewRunIdRef.current = Date.now();
    setAdminPreviewRunId(adminPreviewRunIdRef.current);
    run('xssAdminReviewAuto', async () => {
      const res = await xssApi.adminReview(mode, weakLevel);
      setAdminItems(res.data?.data?.items ?? []);
      return res;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, weakLevel]);

  const weakSummary = useMemo(() => {
    if (focus === 'website') {
      return [
        'WEAK 做了什么：只移除 javascript: 字面量（字符串替换）。',
        'WEAK 漏了什么：没有协议白名单/规范化（http/https），也没有使用 DOM API 安全写入（setAttribute/a.href）。',
        '怎么练出来：看管理员页 link 最终 href；对照 SAFE 下危险 scheme 会降级为 #。',
      ];
    }
    return [
      'WEAK 做了什么：只改写 <script（<script→<scr_ipt）并移除 javascript: 字面量。',
      'WEAK 漏了什么：没有按 HTML 内容上下文做系统性处理（事件属性、其他标签/属性仍可能触发）。',
      '怎么练出来：对照“script 标签类输入”与“事件属性类输入”的差异。',
    ];
  }, [focus]);

  const adminSrcDoc = useMemo(() => {
    const items = Array.isArray(adminItems) ? adminItems : [];
    const safeJson = (s) => String(s).replace(/</g, '\\u003c');
    // 体验优化：避免“同一次提交/刷新”由于 srcDoc 重载触发多次 alert（只允许弹一次）
    // 注意：iframe 开了 sandbox 且未设置 allow-same-origin，无法使用 window.top 存状态；这里用 window.name 做跨导航持久化标记。
    const alertOnce = `<script>(function(){var runId=${safeJson(
      JSON.stringify(`xss_stored_admin:${adminPreviewRunId || 0}`)
    )};var marker='__owasp_alert_fired__'+runId;var orig=window.alert;function has(){try{return (window.name||'').indexOf(marker)!==-1;}catch(e){return false;}}function mark(){try{var n=window.name||'';if(n.indexOf(marker)!==-1)return;var next=n?(n+'|'+marker):marker;window.name=next.length>1800?marker:next;}catch(e){}}window.alert=function(){if(has())return;mark();try{return orig.apply(window,arguments);}catch(e){}};})();</script>`;
    const rows = items
      .map((x) => {
        const author = String(x?.author ?? '');
        const content = String(x?.content ?? '');
        const href = String(x?.websiteHref ?? '#');
        const id = Number(x?.id);
        const idAttr = Number.isFinite(id) ? String(id) : '';

        const activeContent = focus === 'content';
        const activeWebsite = focus === 'website';

        // 非焦点字段强制转义，避免“多点触发”污染因果定位
        const safeAuthor = escapeHtml(author);
        const safeContent = escapeHtml(content);
        const safeHref = escapeHtml(href);
        const websiteLink = !activeWebsite
          ? `<a class="disabled" tabindex="-1" aria-disabled="true" href="${safeHref}">website</a>`
          : mode === 'safe'
            ? `<a class="wlink" data-href="${escapeHtml(JSON.stringify(href))}" href="#">website</a>`
            : `<a href="${href}">website</a>`;

        const delBtn = idAttr
          ? `<button type="button" class="del" data-del-id="${idAttr}" title="删除">🗑️</button>`
          : '';
        return `
<div class="row">
  <div class="top">
    <div class="a">${safeAuthor}</div>
    ${delBtn}
  </div>
  <div class="c ${activeContent ? 'focus' : 'dim'}">${activeContent ? content : safeContent}</div>
  <div class="w ${activeWebsite ? 'focus' : 'dim'}">${websiteLink}</div>
</div>`;
      })
        .join('');

    const safeWebsiteScript =
      mode === 'safe' && focus === 'website'
        ? `<script>
(function(){
  var links = document.querySelectorAll('a.wlink[data-href]');
  for (var i=0;i<links.length;i++){
    var a = links[i];
    var raw = a.getAttribute('data-href');
    if (!raw) { a.setAttribute('href','#'); continue; }
    try{
      var href = JSON.parse(raw);
      var u = new URL(href, window.location.origin);
      if (u.protocol==='http:' || u.protocol==='https:') a.setAttribute('href', u.toString());
      else a.setAttribute('href','#');
    }catch(e){
      a.setAttribute('href','#');
    }
  }
})();
</script>`
        : '';

    // 预览页在 sandbox iframe 中：很多浏览器会阻止 javascript: URL 在点击时执行。
    // 为了让教学效果稳定，这里在 VULN/WEAK 下对 javascript: 链接做“模拟执行”（SAFE 不启用）。
    const jsUriClickScript =
      mode !== 'safe' && focus === 'website'
        ? `<script>
(function(){
  document.addEventListener('click', function(e){
    try{
      var t = e && e.target;
      if (!t) return;
      var a = t.closest ? t.closest('.w a') : null;
      if (!a) return;
      var href = a.getAttribute('href') || '';
      if (!/^javascript\\s*:/i.test(href)) return;
      e.preventDefault();
      var code = href.replace(/^javascript\\s*:/i, '');
      try { Function(code)(); } catch(ex) {}
    }catch(ex2){}
  }, true);
})();
</script>`
        : '';

    const delScript = `<script>
(function(){
  function onClick(e){
    var t = e && e.target;
    if (!t) return;
    var btn = t.closest ? t.closest('button.del[data-del-id]') : null;
    if (!btn) return;
    var id = btn.getAttribute('data-del-id');
    if (!id) return;
    try{
      window.parent && window.parent.postMessage({__owasp:'xss_stored_admin_preview', op:'delete', id: id}, '*');
    }catch(ex2){}
  }
  document.addEventListener('click', onClick, true);
})();
</script>`;

    return `<!doctype html><meta charset="utf-8">
${alertOnce}
<style>
  body{font-family:system-ui,Segoe UI,Arial;padding:12px;margin:0;background:#0f1419;color:#e6edf3}
  .box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;margin-bottom:12px;background:#161f2e}
  .row{padding:10px 0;border-bottom:1px solid rgba(45,58,77,.6)}
  .row:last-child{border-bottom:none}
  .top{display:flex;align-items:center;justify-content:space-between;gap:8px}
  .a{font-weight:600;margin-bottom:6px;color:#e6edf3}
  .c{color:#c6d3e5;margin-bottom:6px}
  .w a{color:#38bdf8;text-decoration:none}
  .muted{color:#8b9cb3;font-size:12px}
  .dim{opacity:.55}
  .focus{outline:1px solid rgba(56,189,248,.55); border-radius:8px; padding:6px}
  .disabled{pointer-events:none; color:#8b9cb3; text-decoration:none}
  .del{border:0;background:transparent;color:#e6edf3;cursor:pointer;padding:2px 6px;border-radius:6px;line-height:1}
  .del:hover{background:rgba(239,68,68,.12)}
</style>
<div class="box">
  ${rows || '<div class="muted" style="margin-top:6px">暂无评论</div>'}
  ${safeWebsiteScript}
  ${jsUriClickScript}
  ${delScript}
</div>`;
  }, [adminItems, focus, mode, adminPreviewRunId]);

  const coachSnippet = useMemo(() => {
    const v = form.getFieldsValue();
    const website = String(v.website ?? '');
    const content = String(v.content ?? '');
    if (focus === 'website') {
      return (
        <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
          {'<a href="'}
          <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
            {website || '<YOUR_INPUT_HERE>'}
          </span>
          {'">website</a>'}
        </div>
      );
    }
    return (
      <div style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace', fontSize: 12, color: '#c6d3e5' }}>
        {'<div class="comment-body">'}
        <span style={{ color: '#38bdf8', background: 'rgba(56,189,248,.12)', padding: '0 4px', borderRadius: 4 }}>
          {content || '<YOUR_INPUT_HERE>'}
        </span>
        {'</div>'}
      </div>
    );
  }, [focus, form]);

  return (
    <ThreePanelLab
      title="XSS · 存储型（评论 → 管理员审核）"
      subtitle="企业化生命周期：用户提交评论入库，管理员审核页查看时触发。"
      hideSafe
      hideResponse
      vuln={{
        title: (
          <Space>
            <SafetyCertificateOutlined style={{ color: '#94a3b8' }} />
            <span style={{ color: '#e6edf3' }}>提交与审核</span>
          </Space>
        ),
        extra: (
          <Space wrap>
            <Select
              size="small"
              value={mode}
              onChange={(v) => {
                setMode(v);
                const vForm = form.getFieldsValue();
                const inputValue = focus === 'website' ? vForm.website : vForm.content;
                reportUi('xss_stored_admin_html_innerHTML', 'mode_change', inputValue);
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
                  const vForm = form.getFieldsValue();
                  const inputValue = focus === 'website' ? vForm.website : vForm.content;
                  reportUi('xss_stored_admin_html_innerHTML', 'weak_level_change', inputValue);
                }}
                options={
                  focus === 'website'
                    ? [
                        { value: 1, label: 'WEAK-1：只移除 javascript:（字符串替换）' },
                        { value: 2, label: 'WEAK-2：先替换后 decode（危险 scheme 可复活）' },
                      ]
                    : [
                        { value: 1, label: 'WEAK-1：<script/javascript: 黑名单示例' },
                        { value: 2, label: 'WEAK-2：仅挡 script/style（富文本弱清洗）' },
                      ]
                }
                style={{ width: 320 }}
              />
            )}
            <Select
              size="small"
              value={focus}
              onChange={(v) => {
                setFocus(v);
                // 切换练习焦点视为一次新的“实验回合”：刷新 runId，避免 alert 去重护栏导致“怎么试都不弹”
                adminPreviewRunIdRef.current = Date.now();
                setAdminPreviewRunId(adminPreviewRunIdRef.current);
                if (v !== 'website') setWeakLevel((x) => x); // no-op：保留用户选择
                const vForm = form.getFieldsValue();
                const inputValue = v === 'website' ? vForm.website : vForm.content;
                reportUi('xss_stored_comment_html_innerHTML', 'focus_change', inputValue);
              }}
              options={FOCUS_OPTIONS}
              style={{ width: 200 }}
            />
            <Tag color={mode === 'safe' ? 'green' : mode === 'weak' ? 'gold' : 'volcano'}>{mode.toUpperCase()}</Tag>
            {typeof lastSavedId === 'number' && <Tag>已保存：#{lastSavedId}</Tag>}
          </Space>
        ),
        children: (
          <>
            <Alert
              type="warning"
              showIcon
              message="存储型 XSS 的关键在于“别人触发”：这里用管理员审核页模拟高权限用户的查看/预览。"
              style={{ marginBottom: 12, background: 'rgba(245, 158, 11, 0.08)', border: '1px solid #2d3a4d' }}
            />

            <Row gutter={16}>
              <Col xs={24} lg={16}>
                <Card size="small" title="用户提交评论" style={{ marginBottom: 12 }}>
                  <Form
                    form={form}
                    layout="vertical"
                    initialValues={{ author: 'alice', website: 'https://example.com', content: 'hello' }}
                    onFinish={(v) =>
                      run('xssCommentSubmit', async () => {
                        adminPreviewRunIdRef.current = Date.now();
                        setAdminPreviewRunId(adminPreviewRunIdRef.current);
                        reportUi('xss_stored_comment_html_innerHTML', 'submit', focus === 'website' ? v.website : v.content);
                        const submitRes = await xssApi.commentSubmit(mode, v.author, v.content, v.website, weakLevel);
                        const savedId = submitRes.data?.data?.savedId;
                        setLastSavedId(typeof savedId === 'number' ? savedId : null);
                        const res = await xssApi.adminReview(mode, weakLevel);
                        setAdminItems(res.data?.data?.items ?? []);
                        return res; // 让 meta 对齐预览页
                      })
                    }
                  >
                    <Form.Item name="author" label="昵称">
                      <Input placeholder="alice" />
                    </Form.Item>
                    <Form.Item name="website" label="个人主页（可选）">
                      <Input placeholder="https://example.com" />
                    </Form.Item>
                    <Form.Item name="content" label="评论内容">
                      <TextArea rows={3} placeholder="（示例）支持富文本/HTML 的评论预览需求" />
                    </Form.Item>
                    <Form.Item>
                      <Button type="primary" htmlType="submit" loading={loading} icon={<PlayCircleOutlined />}>
                        提交
                      </Button>
                      <Button
                        style={{ marginLeft: 8 }}
                        onClick={() =>
                          run('xssAdminReview', async () => {
                            adminPreviewRunIdRef.current = Date.now();
                            setAdminPreviewRunId(adminPreviewRunIdRef.current);
                            const vForm = form.getFieldsValue();
                            const inputValue = focus === 'website' ? vForm.website : vForm.content;
                            reportUi('xss_stored_admin_html_innerHTML', 'refresh_preview', inputValue);
                            const res = await xssApi.adminReview(mode, weakLevel);
                            setAdminItems(res.data?.data?.items ?? []);
                            return res;
                          })
                        }
                      >
                        刷新审核预览
                      </Button>
                    </Form.Item>
                  </Form>
                </Card>

                <Card size="small" title="管理员审核页预览">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 8 }}>
                    <div style={{ color: '#8b9cb3', fontSize: 12, minWidth: 0 }}>
                      管理员审核页预览（别人触发）：会渲染评论内容与链接（每条右侧 🗑️ 可删除）
                    </div>
                    <Button
                      danger
                      size="small"
                      onClick={() =>
                        run('xssCommentClear', async () => {
                          adminPreviewRunIdRef.current = Date.now();
                          setAdminPreviewRunId(adminPreviewRunIdRef.current);
                          reportUi('xss_stored_admin_html_innerHTML', 'clear_all', '');
                          await xssApi.commentClear(modeRef.current, weakLevelRef.current);
                          const review = await xssApi.adminReview(modeRef.current, weakLevelRef.current);
                          setAdminItems(review.data?.data?.items ?? []);
                          return review;
                        })
                      }
                    >
                      清空全部
                    </Button>
                  </div>
                  <iframe
                    title="xss-admin-preview"
                    sandbox="allow-scripts allow-modals"
                    srcDoc={adminSrcDoc}
                    style={{ width: '100%', height: 300, border: '1px solid #2d3a4d', borderRadius: 8, marginTop: 8 }}
                  />
                </Card>
              </Col>

              <Col xs={24} lg={8}>
                <Card
                  title={<span style={{ color: '#e6edf3' }}>Security Coach</span>}
                  style={{ background: '#161f2e', border: '1px solid #2d3a4d', height: '100%' }}
                >
                  <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.7 }}>
                    <div>当前练习点：</div>
                    <div>类型：{focusHint.type}</div>
                    <div>上下文：{focusHint.context}</div>
                    <div>落点：{focusHint.sink}</div>
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
                        label: '对照输入',
                        children: (
                          <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                            {(PAYLOADS_BY_FOCUS[focus] || PAYLOADS_BY_FOCUS.content).map((p) => (
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
                                  if (focus === 'website') form.setFieldsValue({ website: p.value });
                                  else form.setFieldsValue({ content: p.value });
                                  reportUi('xss_stored_comment_html_innerHTML', 'payload_click', p.value);
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

