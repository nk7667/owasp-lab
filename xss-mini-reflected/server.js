/**
 * =============================================================================
 * 【参考答案】反射 + 多输出上下文 + CSP 演示。手敲对照用 server.js。
 * 分阶段说明见：上下文与阶段说明.md
 * =============================================================================
 */

const express = require('express');
const sanitizeHtml = require('sanitize-html');
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
 * safeHref ：htmlEscape +协议白名单。
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
  // 允许相对路径（如 "123"、"docs/a"），但拒绝协议相对 URL（"//evil.com"）
  if (!raw.startsWith('//')) {
    return htmlEscape(raw);
  }
  return '#blocked-scheme';
}

function hrefValidationReason(rawInput) {
  const raw = String(rawInput ?? '').trim();
  if (!raw) return 'URL 不能为空';
  if (/^javascript:/i.test(raw) || /^data:/i.test(raw) || /^vbscript:/i.test(raw)) {
    return '协议不允许';
  }
  if (/^https?:\/\//i.test(raw) || !raw.startsWith('//')) {
    return '';
  }
  return 'URL 格式不合法（不允许以 // 开头）';
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

function readCookie(rawCookie, name) {
  const all = String(rawCookie ?? '');
  const parts = all.split(';');
  for (const part of parts) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return '';
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
        <li><a href="/ctx-src-vuln?q=data:text/html,<script>alert(1)</script>">/ctx-src-vuln</a> 输出上下文·src 属性</li>
        <li><a href="/ctx-src-safe?q=data:text/html,<script>alert(1)</script>">/ctx-src-safe</a> 输出上下文·src 属性</li>
        <li><a href="/ctx-js-vuln?q=%22;alert(1);//">/ctx-js-vuln</a> 脚本串·危险</li>
        <li><a href="/ctx-js-safe?q=hello">/ctx-js-safe</a> 脚本串·JSON 块（演示）</li>
        <li><a href="/ctx-rich-vuln?q=%3Cb%3E粗%3C%2Fb%3E%3Cimg%20src=x%20onerror=alert(1)%3E">/ctx-rich-vuln</a> 富文本·危险</li>
        <li><a href="/ctx-rich-safe?q=%3Cb%3E粗%3C%2Fb%3E%3Cimg%20src=x%20onerror=alert(1)%3E">/ctx-rich-safe</a> 富文本·白名单净化</li>
        <li><a href="/source-path/%3Cimg%20src=x%20onerror=alert(1)%3E">/source-path/:q</a> 输入源·path param</li>
        <li><a href="/source-header">/source-header</a> 输入源·header（示例：x-forwarded-for）</li>
        <li><a href="/source-cookie">/source-cookie</a> 输入源·cookie（用 lab_q 传值）</li>
        <li><a href="/layer-validation?q=test123&url=https://example.com">/layer-validation</a> 必要1·编码 vs 校验分层</li>
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

/* ---------- 3）href / URL ----------js无 &lt也可执行，需协议白名单。 */
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
  const blocked = q && h === '#blocked-scheme';
  const reason = hrefValidationReason(q);
  if (blocked) {
    return res.status(400).type('html').send(
      pageShell(
        'href·safe',
        `<p class="warn"><strong>校验结果：不通过（${htmlEscape(reason || '输入不合法')}）</strong></p>
        <p>输入 raw：<code>${htmlEscape(String(q))}</code></p>`
      )
    );
  }
  res.type('html').send(
    pageShell(
      'href·safe',
      `<p class="ok">校验结果：通过</p>
      <p>输入 raw：<code>${htmlEscape(String(q))}</code></p>
      <p>最终 href（validated）：<code>${htmlEscape(h)}</code></p>
      <p><a href="${h}">链接</a></p>`
    )
  );
});

/* ---------- 3）src URL 上下文（src（img/iframe/script 等资源地址），form action，link href（样式/预加载链接），iframe src，video/audio source src）----------*/
app.get('/ctx-src-vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(
    pageShell(
      'src·vuln',
      `<p class="warn">错误示范：把不可信输入直接放进 <code>iframe src</code>。</p>
      <p>当前 q：<code>${htmlEscape(q)}</code></p>
      <p>
        <a href="/ctx-src-vuln?q=https://example.com">src=https://example.com</a> /
        <a href="/ctx-src-vuln?q=data:text/html,%3Ch1%3EDATA%20PAYLOAD%3C%2Fh1%3E">src=data:text/html,...</a> /
        <a href="/ctx-src-vuln?q=javascript:alert(1)">src=javascript:alert(1)</a>
      </p>
      <iframe src="${q}" width="100%" height="180" style="border:1px solid #ddd;border-radius:8px"></iframe>`
    )
  );
});

app.get('/ctx-src-safe', (req, res) => {
  const q = req.query.q ?? '';
  const s = safeHref(q);
  const blocked = q && s === '#blocked-scheme';
  const reason = hrefValidationReason(q);
  if (blocked) {
    return res.status(400).type('html').send(
      pageShell(
        'src·safe',
        `<p class="warn"><strong>校验结果：不通过（${htmlEscape(reason || '输入不合法')}）</strong></p>
        <p>输入 raw：<code>${htmlEscape(String(q))}</code></p>`
      )
    );
  }
  res.type('html').send(
    pageShell(
      'src·safe',
      `<p class="ok">校验结果：通过</p>
      <p>输入 raw：<code>${htmlEscape(String(q))}</code></p>
      <p>最终 src（validated）：<code>${htmlEscape(s)}</code></p>
      <p>
        <a href="/ctx-src-safe?q=https://example.com">src=https://example.com</a> /
        <a href="/ctx-src-safe?q=data:text/html,%3Ch1%3EDATA%20PAYLOAD%3C%2Fh1%3E">src=data:text/html,...</a> /
        <a href="/ctx-src-safe?q=javascript:alert(1)">src=javascript:alert(1)</a>
      </p>
      <iframe src="${s}" width="100%" height="180" style="border:1px solid #ddd;border-radius:8px"></iframe>`
    )
  );
});
/* ---------- 4）脚本上下文（错误 vs 数据分离）----------
 * 不要把用户输入直接拼进 JS 字符串字面量；演示 JSON 类型 script 块。 */
app.get('/ctx-js-vuln', (req, res) => {
  const q = req.query.q ?? '';
  res.type('html').send(
    pageShell(
      'js·vuln',
      `<p class="warn">错误示范：把用户输入直接拼进可执行 JS 字符串。</p>
      <p>当前 q：<code>${htmlEscape(q)}</code></p>
      <p>
        <a href="/ctx-js-vuln?q=%22%3Balert(1)%3B%2F%2F">字符串闭合，发生在 JS 语法层 payload</a> /
        <a href="/ctx-js-vuln?q=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E">script 闭合，发生在 HTML 解析层 payload</a>
      </p>
      <script>
        // 漏洞点：q 直接进入 JS 双引号字符串字面量
        var _u = "${q}";
        // 仅用于让你在页面里看到“脚本里最终拿到的值”
        document.body.insertAdjacentHTML('beforeend', '<p>_u = <code>' + String(_u).replace(/</g, '&lt;') + '</code></p>');
      </script>`
    )
  );
});

app.get('/ctx-js-safe', (req, res) => {
  const q = req.query.q ?? '';
  const json = JSON.stringify(q).replace(/</g, '\\u003c');
  res.type('html').send(
    pageShell(
      'js·safe',
      `<p class="ok">安全示范：不把用户拼进可执行 JS；只放进 application/json 数据块。</p>
      <p>当前 q：<code>${htmlEscape(q)}</code></p>
      <p>
        <a href="/ctx-js-safe?q=%22%3Balert(1)%3B%2F%2F">字符串闭合 payload</a> /
        <a href="/ctx-js-safe?q=%3C%2Fscript%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E">script 闭合 payload</a>
      </p>
      <script type="application/json" id="payload">${json}</script>
      <pre id="out"></pre>
      <script>
        (function () {
          var raw = document.getElementById('payload').textContent;
          var parsed = JSON.parse(raw);
          document.getElementById('out').textContent =
            'payload(raw JSON) = ' + raw + '\\n' +
            'parsed value = ' + parsed;
        })();
      </script>`
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
  const safe = sanitizeHtml(String(q), {
    allowedTags: ['b', 'strong', 'i', 'em', 'u', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'a'],
    allowedAttributes: {
      a: ['href', 'title', 'target', 'rel'],
    },
    allowedSchemes: ['http', 'https', 'mailto'],
    allowProtocolRelative: false,
    transformTags: {
      a: (tagName, attribs) => ({
        tagName,
        attribs: {
          ...attribs,
          rel: 'noopener noreferrer',
        },
      }),
    },
  });
  res.type('html').send(
    pageShell(
      'rich·safe',
      `<p class="ok">白名单净化：保留允许标签/属性，移除事件处理器与危险协议（如 javascript:）。</p>
      <p><strong>当前允许标签说明：</strong></p>
      <ul>
        <li><code>b</code>/<code>strong</code>：粗体强调</li>
        <li><code>i</code>/<code>em</code>：斜体强调</li>
        <li><code>u</code>：下划线</li>
        <li><code>p</code>：段落</li>
        <li><code>br</code>：换行</li>
        <li><code>ul</code>/<code>ol</code>/<code>li</code>：无序/有序列表与列表项</li>
        <li><code>code</code>/<code>pre</code>：代码与预格式文本</li>
        <li><code>a</code>：链接（仅允许安全协议，且补 <code>rel=noopener noreferrer</code>）</li>
      </ul>
      <p>示例输入可试：<code>&lt;b&gt;粗体&lt;/b&gt; &lt;a href="javascript:alert(1)"&gt;bad link&lt;/a&gt; &lt;img src=x onerror=alert(1)&gt;</code></p>
      <div>${safe}</div>`
    )
  );
});

/* ---------- 输入源覆盖：path / header / cookie / referer（统一先演示 HTML 文本上下文）---------- */
app.get('/source-path/:q', (req, res) => {
  const raw = req.params.q ?? '';
  const safe = htmlEscape(raw);
  res.type('html').send(
    pageShell(
      'source·path',
      `<p class="warn">输入源：path param（<code>req.params.q</code>）。</p>
      <p>vuln 回显：<code>${raw}</code></p>
      <p>safe 回显：<code>${safe}</code></p>
      <p><a href="/source-path/%3Cimg%20src=x%20onerror=alert(1)%3E">用 payload 重试</a></p>`
    )
  );
});

app.get('/source-header', (req, res) => {
  const raw = req.get('x-forwarded-for') ?? '';
  const safe = htmlEscape(raw);
  res.type('html').send(
    pageShell(
      'source·header',
      `<p class="warn">输入源：header（<code>x-forwarded-for</code>，代理链路常见）。</p>
      <p>提示：可用浏览器插件或 curl 发送请求头。</p>
      <p>vuln 回显：<code>${raw}</code></p>
      <p>safe 回显：<code>${safe}</code></p>
      <pre><code>curl -H "x-forwarded-for: &lt;img src=x onerror=alert(1)&gt;" http://127.0.0.1:3456/source-header</code></pre>`
    )
  );
});

app.get('/source-cookie', (req, res) => {
  const raw = readCookie(req.headers.cookie, 'lab_q');
  const safe = htmlEscape(raw);
  res.type('html').send(
    pageShell(
      'source·cookie',
      `<p class="warn">输入源：cookie（<code>lab_q</code>）。</p>
      <p>先在控制台执行：<code>document.cookie='lab_q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E; path=/'</code></p>
      <p>vuln 回显：<code>${raw}</code></p>
      <p>safe 回显：<code>${safe}</code></p>`
    )
  );
});

/* ----------校验分层（同页演示）---------- */
app.get('/layer-validation', (req, res) => {
  const qRaw = String(req.query.q ?? '');
  const urlRaw = String(req.query.url ?? '');

  // 校验层（业务规则）
  const qErrors = [];
  if (qRaw.length > 20) qErrors.push('q 长度不能超过 20');
  if (!/^[\w\u4e00-\u9fa5\s-]*$/.test(qRaw)) qErrors.push('q 只允许中文/英文/数字/下划线/空格/中划线');

  const urlValidated = safeHref(urlRaw);
  const urlError = urlRaw && urlValidated === '#blocked-scheme' ? 'url 协议不允许（仅允许 http/https 或站内 /path）' : '';

  // 编码层（输出安全）
  const qSafeText = htmlEscape(qRaw);
  const urlSafeText = htmlEscape(urlRaw);

  res.type('html').send(
    pageShell(
      'layer·validation',
      `<p class="ok"><strong>目标：</strong>“校验层”和“编码层”是两件事。</p>
      <p>示例：
        <a href="/layer-validation?q=hello-123&url=https://example.com">合法输入</a> /
        <a href="/layer-validation?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E&url=javascript:alert(1)">危险输入</a> /
        <a href="/layer-validation?q=aaaaaaaaaaaaaaaaaaaaaaaaa&url=//evil.com">规则失败输入</a>
      </p>
      <h3>1) 校验层（业务规则反馈）</h3>
      <p>q(raw): <code>${qSafeText}</code></p>
      <p>url(raw): <code>${urlSafeText}</code></p>
      <p>q 校验结果：${qErrors.length ? `<span class="warn">${qErrors.join('；')}</span>` : '<span class="ok">通过</span>'}</p>
      <p>url 校验结果：${urlError ? `<span class="warn">${htmlEscape(urlError)}</span>` : '<span class="ok">通过</span>'}</p>
      <h3>2) 编码层（输出安全）</h3>
      <p>HTML 文本上下文输出：<code>${qSafeText}</code></p>
      <p>URL 上下文输出（safeHref 后写入 href）：<a href="${urlValidated}">链接</a>（最终 href: <code>${htmlEscape(urlValidated)}</code>）</p>
      <p class="warn"><strong>结论：</strong>校验不替代编码；编码不替代校验。</p>`
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
