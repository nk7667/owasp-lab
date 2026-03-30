# xss-mini-reflected

本机学习用。**讲解见 `server.js` 文件头与行内注释**，勿用于未授权系统。

```bash
npm install
npm start          # 改代码后需手动重启
npm run dev        # 改 server.js 后自动重启（需 Node 18.11+）
```

浏览器打开终端里打印的地址；试用 `/vuln?q=` 与 `/safe?q=`。

**反射型怎么手敲练**：见 **`手敲练习-反射.md`**。  
**多上下文 + 阶段说明**：**`上下文与阶段说明.md`**（属性/href/脚本/富文本/CSP）。  
当前 **`server.js`** 为你的练习版；**完整路由与注释**在 **`server.reference.js`**；卡住时 **`npm run answer`**（与 `npm run dev` 同端口勿同时开）。
/**
 * 【手敲练习】本文件由你逐段补全；完整版 + 大段讲解在 server.reference.js。
 *
 * 建议顺序：express 三行 → htmlEscape → pageShell → GET /vuln → GET /safe → GET / → listen
 * 卡住：对照 server.reference.js，或临时运行 npm run answer 起参考答案服务。
 */

// TODO 1：require('express')、创建 app、PORT = 3456
const express = require('express');
const app = express();
const PORT = 3456;
// TODO 2：function htmlEscape(s) { ... replace & < > " ' }
 function htmlEscape(s) {
  const str =String(s ?? '')
  return str
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;')
 }
// TODO 3：function pageShell(title, bodyInnerHtml) { return `整页 HTML，title 用 htmlEscape(title)，中间 ${bodyInnerHtml}` }
 function pageShell(bodyInnerHtml) {
  return `<!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <style>
      body { font-family: system-ui, sans-serif; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
    </style>
  </head>
  <body>
    ${bodyInnerHtml}
    <p><a href="/">/</a></p>
  </body>
  </html>`;
 }
// TODO 4：app.get('/', ...) → pageShell('xss反射练习', 带 /vuln /safe 链接的 ul)
app.get('/',(_req,res)=>{
  res.type('html').send(
    pageShell(`<ul>
      <li><a href="/vuln?q=test">/vuln?q=…</a></li>
      <li><a href="/safe?q=test">/safe?q=…</a></li>
</ul>`)
)
})
// TODO 5：app.get('/vuln', ...) → q = req.query.q ?? ''，body = `<div>${q}</div>`
app.get('/vuln',(req,res)=>{
  const q =req.query.q ?? ''
  const body = `<div>${q}</div>`
  res.type('html').send(pageShell(body))
})
// TODO 6：app.get('/safe', ...) → safe = htmlEscape(q)，body = `<div>${safe}</div>`
app.get('/safe',(req,res)=>{
  const q = req.query.q ?? ''
  const safe = htmlEscape(q)
  const body = `<div>${safe}</div>`
  res.type('html').send(pageShell(body))
})
// TODO 7：app.listen(PORT, '127.0.0.1', () => console.log(...))
app.listen(PORT, '127.0.0.1', () => {
  console.log('http://127.0.0.1:' + PORT + '/');
});