/**
 * =============================================================================
 * 【参考答案】反射 + 多输出上下文 + CSP 演示。手敲对照用 server.js。
 * 分阶段说明见：上下文与阶段说明.md
 * =============================================================================
 */

const express = require('express');
const app = express();
const PORT = 3456;

/** HTML 文本 / HTML 实体编码 */
function htmlEscape(s) {
  const str = String(s ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * safeHref 上下文：htmlEscape 挡不住 javascript: / data:。
 * 协议白名单。
 */
function safeHref(u) {
  const raw = String(u ?? '').trim();
  if (!raw) return '#';
  if (/^javascript:/i.test(raw) || /^data:/i.test(raw) || /^vbscript:/i.test(raw)) {
    return '#blocked-scheme';
  }
  if (/^https?:\/\//i.test(raw)) {
    return htmlEscape(raw);
  }
  if (raw.startsWith('/') && !raw.startsWith('//')) {
    return htmlEscape(raw);
  }
  return '#blocked-scheme';
}

function pageShell(title, bodyInnerHtml) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>${htmlEscape(title)}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
    code { background: #f4f4f4; padding: 2px 6px; }
    .warn { color: #b45309; }
    .ok { color: #15803d; }
  </style>
</head>
<body>
  <h1>${htmlEscape(title)}</h1>
  ${bodyInnerHtml}
  <p><a href="/">/</a></p>
</body>
</html>`;
}

app.get('/', (_req, res) => {
  res.type('html').send(
    pageShell(
      'index',
      `<p>阶段1：同一 <code>q</code>，不同<strong>输出上下文</strong>（详见 上下文与阶段说明.md）。</p>
      <ul>
        <li><a href="/vuln?q=test">/vuln</a> 正文·危险</li>
        <li><a href="/safe?q=test">/safe</a> 正文·编码</li>
        <li><a href="/ctx-attr-vuln?q=x%22%20onmouseover=alert(1)">/ctx-attr-vuln</a> 属性·危险</li>
        <li><a href="/ctx-attr-safe?q=x%22%20onmouseover=alert(1)">/ctx-attr-safe</a> 属性·编码</li>
        <li><a href="/ctx-href-vuln?q=javascript:alert(1)">/ctx-href-vuln</a> href·危险</li>
        <li><a href="/ctx-href-safe?q=javascript:alert(1)">/ctx-href-safe</a> href·协议白名单</li>
        <li><a href="/ctx-js-vuln?q=%22;alert(1);//">/ctx-js-vuln</a> 脚本串·危险</li>
        <li><a href="/ctx-js-safe?q=hello">/ctx-js-safe</a> 脚本串·JSON 块（演示）</li>
        <li><a href="/ctx-rich-vuln?q=%3Cb%3E粗%3C%2Fb%3E%3Cimg%20src=x%20onerror=alert(1)%3E">/ctx-rich-vuln</a> 富文本·危险</li>
        <li><a href="/ctx-rich-safe?q=同上">/ctx-rich-safe</a> 富文本·整段编码（非白名单）</li>
        <li><a href="/csp-demo">/csp-demo</a> 阶段3·CSP 演示</li>
      </ul>
      <p class="ok">阶段2 DOM 对照：<code>xss-sinks-practice/vanilla/reflected-vs-dom.html</code></p>`
    )
  );
});

/* ---------- 1）HTML 正文 ---------- */
app.get('/vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(pageShell('vuln·正文', `<p class="warn">上下文：元素内文本。未编码。</p><div>${q}</div>`));
});

app.get('/safe', (req, res) => {
  const q = req.query.q ?? '';
  const safe = htmlEscape(q);
  res.type('html').send(pageShell('safe·正文', `<p class="ok">上下文：元素内文本。htmlEscape(q)。</p><div>${safe}</div>`));
});

/* ---------- 2）HTML 属性（双引号 title）----------
 * 危险：q 中含 " 可闭合 title= 并注入新属性/事件。
 * 说明：属性编码与「正文」规则侧重点不同，本 demo 仍用 htmlEscape 演示引号变 &quot;。 */
app.get('/ctx-attr-vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(
    pageShell('attr·vuln', `<p class="warn">上下文：双引号属性值 title=&quot;…&quot;。未编码。</p><div title="${q}">把鼠标悬停在本 div 上看 title</div>`)
  );
});

app.get('/ctx-attr-safe', (req, res) => {
  const q = req.query.q ?? '';
  const a = htmlEscape(q);
  res.type('html').send(
    pageShell('attr·safe', `<p class="ok">上下文：属性值。htmlEscape(q)，引号成实体。</p><div title="${a}">悬停看 title</div>`)
  );
});

/* ---------- 3）href / URL ----------
 * 仅靠 htmlEscape：javascript: 中无 &lt; 也可执行，故需协议白名单。 */
app.get('/ctx-href-vuln', (req, res) => {
  const q = req.query.q ?? '';
  const h = htmlEscape(q);
  res.type('html').send(
    pageShell('href·vuln', `<p class="warn">错误示范：对 href 只做了 htmlEscape，仍可能保留 javascript:（浏览器是否执行因版本/策略而异）。</p><p><a href="${h}">链接</a>（q 经 htmlEscape）</p>`)
  );
});

app.get('/ctx-href-safe', (req, res) => {
  const q = req.query.q ?? '';
  const h = safeHref(q);
  res.type('html').send(
    pageShell('href·safe', `<p class="ok">safeHref：拦 javascript:/data:，仅允许 http(s) 或站内 / 路径，再写入 href。</p><p><a href="${h}">链接</a></p>`)
  );
});

/* ---------- 4）脚本上下文（错误 vs 数据分离）----------
 * 不要把用户输入直接拼进 JS 字符串字面量；演示 JSON 类型 script 块。 */
app.get('/ctx-js-vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(
    pageShell('js·vuln', `<p class="warn">错误示范：用户串进入 JS 双引号字符串。</p><script>var _u = "${q}"</script>`)
  );
});

app.get('/ctx-js-safe', (req, res) => {
  const q = req.query.q ?? '';
  const json = JSON.stringify(q).replace(/</g, '\\u003c');
  res.type('html').send(
    pageShell(
      'js·safe',
      `<p class="ok">不把用户拼进可执行字面量；用 type=application/json 块存放数据（嵌入前对 &lt; 做 \\u003c 防闭合 script）。</p>
      <script type="application/json" id="payload">${json}</script>
      <p>由其它脚本 <code>JSON.parse(document.getElementById('payload').textContent)</code> 读取，勿 eval。</p>`
    )
  );
});

/* ---------- 5）富文本：白名单 vs 整段 htmlEscape ---------- */
app.get('/ctx-rich-vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(
    pageShell('rich·vuln', `<p class="warn">允许标签进正文：未净化则 onerror 等可执行。</p><div>${q}</div>`)
  );
});

app.get('/ctx-rich-safe', (req, res) => {
  const q = req.query.q ?? '';
  const safe = htmlEscape(q);
  res.type('html').send(
    pageShell(
      'rich·safe',
      `<p class="ok">整段 htmlEscape：标签当文字，安全但<strong>失去</strong> &lt;b&gt; 等格式。要「保留部分标签」请用 DOMPurify/filterXSS（见 vanilla/index.html）。</p><div>${safe}</div>`
    )
  );
});

/* ---------- 阶段3：CSP 纵深防御（不替代转义）---------- */
app.get('/csp-demo', (req, res) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'"
  );
  res.type('html').send(
    pageShell(
      'csp-demo',
      `<p>响应头已带 CSP。内联 script / 内联事件常被拦（看控制台）。</p>
      <script>alert('若被 CSP 拦截则不会弹')</script>
      <p><button type="button" onclick="alert('内联事件')">内联 onclick</button></p>`
    )
  );
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('http://127.0.0.1:' + PORT + '/');
});
