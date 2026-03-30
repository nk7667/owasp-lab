# 危险 DOM 汇点练习（学习用）

代码不熟想**手敲练到熟**：请看 **`手敲练习计划.md`**（每天 20 分钟、背什么、怎么自测）。

**阶段2（反射 vs DOM 对照）**：打开 **`vanilla/reflected-vs-dom.html`**（可与 `xss-mini-reflected` 对照阅读；说明亦在 `xss-mini-reflected/上下文与阶段说明.md`）。

## 有没有必要每种都练？

- **原理上没必要**：`dangerouslySetInnerHTML`、`v-html`、`innerHTML` / `outerHTML`、渲染函数里的 `innerHTML`，本质都是「把字符串当 HTML 解析进 DOM」。
- **工程上有必要扫一遍**：因为写法不同，审计/加固时要认得出来；编译插件也是按语法分别改的。
- **建议练习量**：先 **`vanilla/`（原生）** 搞懂 → 再任选一个 **React** 或 **Vue** 小项目各写一页即可。

## 怎么实现「加固」？

| 场景 | 思路 |
|------|------|
| 只展示纯文本 | 不要用上述 API；用 `textContent`，或服务端/模板 **HTML 实体编码**。 |
| 必须富文本（保留部分标签） | **白名单净化**：开源可用 **DOMPurify** / **xss**；公司内可用 **filterXSS / filterXSSblock**。 |
| 公司方案 | 按你们文档：`xss.config.js` + Babel 插件 + `@dusec/du-js-xss`（本仓库不内置内网包）。 |

## 本目录内容

- **`vanilla/index.html`**：练习 `innerHTML` / `outerHTML`，对比「漏洞 / textContent / DOMPurify」。

## `vanilla` 怎么起环境？能热加载吗？

**方式 A：零环境（最快）**

- 用资源管理器双击 **`vanilla/index.html`**，或在浏览器里 **文件 → 打开文件**。
- 改完代码后 **手动刷新 F5**。  
- 说明：走的是 `file://`，一般够用；若遇个别浏览器对 CDN 限制，再用方式 B。

**方式 B：本机静态服务（改完手动 F5）**

在 **`xss-sinks-practice`** 目录下：

```bash
npm run open
```

浏览器访问终端里提示的地址（多为 `http://localhost:5173`）。**保存文件后按 F5** 看效果。

**方式 C：保存后自动刷新（你要的「热加载」）**

仍在 **`xss-sinks-practice`** 目录：

```bash
npm run dev
```

会用 `live-server` 以 **`vanilla`** 为根目录起服务；**每次保存 `index.html` 浏览器会自动刷新**。  
（第一次会 `npx` 下载依赖，需联网。）

| 方式 | 命令 / 操作 | 热刷新 |
|------|-------------|--------|
| A | 双击 `vanilla/index.html` | 否，手动 F5 |
| B | `npm run open` | 否，手动 F5 |
| C | `npm run dev` | **是**，保存即刷新 |

> 这和 `xss-mini-reflected` 里 `node --watch server.js` 不同：那是 **Node 进程**监视；这里是 **静态 HTML**，用 **live-server** 监视文件并刷新页面。

## React / Vue 自己怎么起最小项目（命令备忘）

```bash
# React
npm create vite@latest react-xss-lab -- --template react

# Vue3
npm create vite@latest vue3-xss-lab -- --template vue
```

然后在单页里分别写：

- React：`dangerouslySetInnerHTML={{ __html: ... }}`（注意属性名是 `__html`，你们文档里 `_html` 多为笔误）
- Vue：`<span v-html="raw"></span>` → 改为 `v-html="purify(raw)"` 或构建期插件自动包一层

Vue2 JSX 的 `domPropsInnerHTML`、渲染函数 `domProps.innerHTML` 与上面同类：**赋值前净化**或**不用 HTML 汇点**。
