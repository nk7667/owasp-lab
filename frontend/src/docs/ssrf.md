# SSRF 关卡说明

本页集中放 SSRF 关卡的背景、模式差异与练习提示。关卡前端页面保持“只提供操作界面 + 结果回显”的简约形态。

## 关卡目标

- 通过“服务器代替你去请求 URL”的功能，理解 SSRF 的本质风险
- 观察不同修复策略（VULN / WEAK / SAFE）在同一输入下的差异行为
- 认识常见绕过面：IP 表示法、DNS 解析、重定向、协议限制、白名单策略等

## 入口

- `URL 获取`：`/ssrf/fetch`
- `说明`：`/ssrf/docs`

## 后端接口与数据结构（当前实现）

### 路由

- `POST /api/v1/ssrf/fetch/{mode}?url=...&weakLevel=1`
- `POST /api/v1/ssrf/image-proxy/{mode}?imageUrl=...&weakLevel=1`（后端抓取图片，仅返回摘要）
- `POST /api/v1/ssrf/download/{mode}?fileUrl=...&weakLevel=1`（后端对 URL 做 HEAD 探测，仅返回摘要）
- `GET /api/v1/ssrf/internal/metadata`（靶场模拟“云元数据”，用于验证 SSRF 是否打到本机）

其中 `{mode}` 取值：`VULN | WEAK | SAFE`（大小写不敏感）。

### fetch 返回字段（`/fetch/{mode}`）

后端核心字段（`ApiResponse.data`）：

- `requestedUrl`: 原始输入 URL
- `mode`: `VULN/WEAK/SAFE`
- `weakLevel`: WEAK 分级（即使非 WEAK 也会回显）
- `success`: 请求是否成功（状态码 2xx/3xx 视为成功）
- `statusCode`: HTTP 状态码（如请求被拦截则可能 отсутств）
- `bodyPreview`: 响应内容预览（最多约 2048 字符）
- `blocked`: 是否被后端策略拦截
- `blockedReason`: 拦截原因（字符串）
- `error`: 异常信息（如 DNS/连接失败等）

前端 `URL 获取` 页仅做这几个字段的最小展示：状态码、拦截原因、错误、内容预览。

## 模式说明

- **VULN（原始漏洞）**：不做（或几乎不做）限制，用户输入什么 URL 就请求什么 URL
- **WEAK（错误修复）**：做了一些过滤/黑名单，但策略不完整，仍可能被绕过
- **SAFE（更贴近工程防御）**：不依赖域名白名单；以**协议白名单 + 端口限制 + DNS 解析后 IP 全量校验**为核心，并配合禁重定向与响应控制收敛风险面

## 当前校验逻辑梳理（`SsrfServiceImpl.validateUrlForMode`）

### 通用

- 先用 `URI.create(url)` 解析出 `scheme` 与 `host`；解析失败或缺失则拒绝（`invalid_url` / `url_parse_error:*`）

### VULN

- **不做校验**：直接放行

### WEAK

- **仅允许** `http/https`（否则 `only_http_https_allowed_in_weak`）
- 当 `weakLevel > 1` 时：**仅拦**主机名**等于** `127.0.0.1`（`127.0.0.1_blocked_in_weak`）
- 其余情况放行（因此仍可能存在明显绕过面：其他回环写法、解析结果校验缺失、重定向未覆盖等）

### SAFE

SAFE 不做“域名白名单”（适配图片抓取等“用户 URL 来源不可控”的场景），但会更严格地约束 URL 结构、端口与解析结果：

- **基础结构拒绝**：
  - URL 过长：`url_too_long`
  - `userinfo`（`http://user:pass@host/`）：`userinfo_not_allowed`
  - `fragment`（`#...`）：`fragment_not_allowed`
- **仅允许** `http/https`：否则 `only_http_https_allowed`
- **端口限制**：
  - 仅允许 `80/443`（未显式端口时按协议映射默认端口）
  - 其他端口：`port_not_allowed:{port}`
- **主机名规范化**：
  - `IDN.toASCII` 失败：`invalid_host`
  - 拦截 `localhost` / `*.localhost`：`localhost_blocked`
- **DNS 解析后 IP 全量校验（所有 A/AAAA）**：
  - 使用 `InetAddress.getAllByName(host)` 解析出全部地址
  - 任一解析结果命中以下类别则拒绝（并回显 `:{ip}`）：
    - `anylocal_blocked`（0.0.0.0 等）
    - `loopback_blocked`（127.0.0.1 / ::1）
    - `linklocal_blocked`（169.254.0.0/16 / fe80::/10）
    - `multicast_blocked`
    - `sitelocal_blocked`（10/172.16-31/192.168、以及部分实现下的 IPv6 site-local/ULA）
    - `cgnat_v4_blocked`（100.64.0.0/10）
    - `benchmark_v4_blocked`（198.18.0.0/15）
    - `reserved_v4_blocked`（0.0.0.0/8 等）
    - `ula_v6_blocked`（fc00::/7）

## HTTP 请求行为（当前实现细节）

- **不跟随重定向**：`setInstanceFollowRedirects(false)`
- **超时**：
  - fetch：connect 4000ms / read 8000ms
  - 其他场景：connect 3000ms / read 6000ms
- **响应体截断**：fetch 只读到约 2048 字符作为 `bodyPreview`（避免把大响应塞回前端）

## 关于“原子性解析 / DNS Pinning”

当前 SAFE **已实现 DNS pinning（原子性解析）**：

- 先对 host 做 `getAllByName`，对所有解析结果做内网/保留地址校验
- 选定一个通过校验的 IP
- **后续连接直接连该 IP**，并设置 `Host` 头为原始域名
- HTTPS 场景额外设置 **SNI=原始域名**，并按原始域名做证书校验

这样可以显著降低“校验一次、请求时又解析一次”带来的 DNS 重绑定风险窗口（即：校验与连接使用同一个解析结果）。

## WEAK 分级（示例）

不同分级体现常见“修复姿势”的演进与缺陷：

- **WEAK-1**：字符串层面拦截 `localhost` / `127.0.0.1`
- **WEAK-2**：解析后对内网网段做黑名单（但可能忽略重定向/多次解析等边界）
- **WEAK-3**：限制协议为 `http/https`（但不等于安全）
- **WEAK-4/5**：叠加更多过滤（仍可能在编码、重定向、非常规主机名等处被绕过）

## 推荐练习思路（不提供一键 payload）


- **本机/内网探测**：思考“如果服务器能访问 `127.0.0.1`/内网网段，会发生什么”
- **IP 表示法**：同一个地址是否能用不同写法表达（短写、整数表示等）
- **重定向**：只校验首个 URL 是否足够？跳转后的目标是否再次校验？
- **协议**：仅限制 `http/https` 并不能阻止访问内网 HTTP 服务
- **白名单策略**：真正的业务通常只需要访问少数外部域名

## 元数据端点（靶场模拟）

靶场提供了一个用于演示“云元数据泄露风险”的本机端点：

- `GET /api/v1/ssrf/internal/metadata`

期望行为：

- 在 **VULN/WEAK** 下可能被访问到（取决于限制策略）
- 在 **SAFE** 下应被禁止（既不在白名单域名中，也会解析为本机/内网地址）

