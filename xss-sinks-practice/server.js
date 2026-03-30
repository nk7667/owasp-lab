/**
 * DOM 汇点：从 0 到 1 的「单一路径」对照（与 xss-mini-reflected 的 /vuln、/safe 同一套心智模型）。
 * 差异：恶意片段由本页脚本从 URL 读出再写入 DOM；服务端返回的 HTML 模板可固定不变。
 * 勿用于未授权系统。端口刻意与 xss-mini-reflected（3456）错开。
 */
const http = require('http');
const { URL } = require('url');

const PORT = 3457;
const HOST = '127.0.0.1';

function htmlEscape(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function pageShell(title, body) {
  const t = htmlEscape(title);
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>${t}</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
    code { background: #f4f4f4; padding: 2px 6px; }
    .warn { color: #b45309; }
    .ok { color: #15803d; }
    a { margin-right: 1rem; }
  </style>
</head>
<body>
  <h1>${t}</h1>
  ${body}
  <p><a href="/">返回 /</a></p>
</body>
</html>`;
}

const scriptVuln = `<script>
(function () {
  var params = new URLSearchParams(window.location.search);
  var q = params.get('q') || '';
  document.getElementById('out').innerHTML = q;
})();
</script>`;

const scriptSafe = `<script>
(function () {
  var params = new URLSearchParams(window.location.search);
  var q = params.get('q') || '';
  document.getElementById('out').textContent = q;
})();
</script>`;

const routes = {
  '/': pageShell('DOM 汇点 · 迷你路线', `
  <p>与 <strong>xss-mini-reflected</strong> 一样先试 <code>/vuln?q=</code> 再试 <code>/safe?q=</code>；这里演示的是浏览器里的 <strong>innerHTML</strong> / <strong>textContent</strong> 汇点。</p>
  <ul>
    <li><a href="/vuln?q=test">/vuln?q=test</a> <span class="warn">危险</span>：<code>innerHTML = q</code></li>
    <li><a href="/safe?q=test">/safe?q=test</a> <span class="ok">安全</span>：<code>textContent = q</code></li>
    <li><a href="/vuln?q=${encodeURIComponent('<img src=x onerror=alert(1)>')}">/vuln?q=…</a>（payload）</li>
    <li><a href="/safe?q=${encodeURIComponent('<img src=x onerror=alert(1)>')}">/safe?q=…</a>（同 payload，仅显示文本）</li>
  </ul>
  <p>静态手敲练习页：<code>vanilla/index.html</code> 请用资源管理器双击、或在本目录另开终端执行 <code>npm run open</code> / <code>npm run dev</code>（与本服务不同端口）。</p>
  `),

  '/vuln': pageShell('/vuln · innerHTML', `
  <p class="warn">上下文：客户端把 URL 参数 <code>q</code> 赋给 <code>innerHTML</code> → 浏览器按 HTML 解析。</p>
  <div id="out" style="min-height:2em;background:#fafafa;padding:8px;border:1px solid #ccc;"></div>
  ${scriptVuln}
  `),

  '/safe': pageShell('/safe · textContent', `
  <p class="ok">同一 <code>q</code>，改为 <code>textContent</code>：只当纯文本，不解析标签。</p>
  <div id="out" style="min-height:2em;background:#fafafa;padding:8px;border:1px solid #15803d;"></div>
  ${scriptSafe}
  `),
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url || '/', `http://${HOST}:${PORT}`);
  const pathname = url.pathname.replace(/\/$/, '') || '/';
  const body = routes[pathname];

  if (body) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(body);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404');
});

server.listen(PORT, HOST, () => {
  console.log(`xss-sinks-practice 故事线: http://${HOST}:${PORT}/`);
  console.log('  /vuln?q=  → innerHTML（危险）');
  console.log('  /safe?q=  → textContent（安全）');
});
