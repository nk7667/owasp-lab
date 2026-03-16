## OWASP Lab · 学习型漏洞靶场（Java + React）

本项目是一个面向开发者/安全同学的 **教学向 OWASP 漏洞靶场**，后端基于 Spring Boot + H2，前端基于 React + Vite，并内置一个“AI 教练（coach）”用于结合最近流量给出技术向提示。

### 功能概览

- **SQL 注入（SQLi）模块**  
  - 登录绕过：`/api/v1/sqli/vuln/login` vs `/safe/login`（明文拼接 vs 参数化 + BCrypt + 登录锁定）。  
  - ID 越权：`/vuln/users/detail?id=...` vs `/safe/users/detail`（字符串拼接 vs 参数化 + 资源级鉴权）。  
  - ORDER BY / LIMIT：`/vuln/users/list` vs `/safe/users/list`（结构拼接 vs 列/方向白名单 + 固定 LIMIT）。  
  - 新闻多关卡：UNION / 函数视图 / 布尔盲注 / 时间盲注（围绕 `news_*` 系列接口）。

- **XXE（XML External Entity）模块**  
  - DOM DocumentBuilder：`/api/v1/xxe/parse-vuln` vs `/parse-safe`（默认配置 vs 禁用 DOCTYPE/外部实体）。  
  - 前端页面：`frontend/src/pages/xxe/XxeLab.jsx`，支持一键填充 **文件读取 / SSRF / DoS（Billion Laughs）** payload。

- **SSRF 模块**  
  - 通用 fetch：`/api/v1/ssrf/fetch/{VULN|SAFE}`，演示“后端直连任意 URL”与协议/主机/IP 白名单。  
  - 图片代理/文件下载：`/image-proxy/{mode}`、`/download/{mode}`，演示在业务场景中如何演化成 SSRF + 内网探测。

- **命令执行（RCE）模块**  
  - ping：`/api/v1/command-execution/network/ping/{mode}`，覆盖无防护 / 分隔符过滤 / 参数数组等多级修复。  
  - 文件操作：`/file/ls|grep|cat/{mode}`，聚焦“路径拼接 + shell 调用”与“固定根目录 + 参数数组”的对照。

- **XSS / JSONP / CSRF 等模块**  
  - XSS：反射型 / 存储型 / DOM（含 postMessage 链、JSONP callback 等）。  
  - CSRF：Low（纯 GET 改密）+ High（token + XSS 绕过链），对应说明见 `csrf.md`。  
  - JSONP 漏洞演示：`attack-jsonp.html` 搭配后端 JSONP 接口使用。

- **AI 教练（coach）模块**  
  - 路径：`/api/v1/coach/recent`、`/coach/analyze`。  
  - 后端通过 `FlowCaptureFilter` 采集最近 N 条 API 流量，并结合 `resources/coach/specs/*.json` 中的关卡说明，对 SQLi / XSS / XXE / SSRF / RCE / CSRF 等模块给出技术向提示、下一步 payload 建议、SAFE 对照说明。

### 运行方式

#### 1. 启动后端（Spring Boot）

```bash
# 在项目根目录
mvn spring-boot:run
```

默认：

- 端口：`http://localhost:8081`  
- 内存数据库：H2，连接串为 `jdbc:h2:mem:owasp_lab`，控制台路径 `/h2-console`

#### 2. 启动前端（React + Vite）

```bash
cd frontend
npm install
npm run dev
```

默认访问：`http://localhost:5173`  
前端已通过 Vite 代理把 `/api` 流量转发到 `http://localhost:8081`。

### 目录结构（简要）

- `src/main/java/org/owasplab/`  
  - `controller/`：各漏洞模块的 REST 接口（如 `SqliController`、`XxeController`、`SsrfController`、`CommandExecutionController`、`CsrfController` 等）。  
  - `service/`：具体业务与漏洞实现（例如 `SqliServiceImpl` 现已切换为 MyBatis 实现）。  
  - `coach/`：AI 教练相关（FlowCaptureFilter、CoachController、spec 加载与 LLM 适配）。  
  - `core/`：统一响应体 `ApiResponse`、`ApiMeta`、`Mode`、`SignalChannel` 等。
- `src/main/resources/coach/specs/`  
  - 各关卡的 coach 说明 JSON（SQLi: `where_*` / `order_by_limit` / `news_*`，XSS: `xss_*`，XXE: `xxe_dom_documentbuilder`，SSRF: `ssrf_*`，RCE: `rce_ping_*` + `command_file_ops`，CSRF: `csrf_*` 等）。
- `frontend/src/pages/`  
  - 前端实验页面（SQLi、XXE、XSS、CSRF 等）。

### 教学使用建议

- 每个模块都提供 **VULN / SAFE（或多级 WEAK）** 的接口对照，建议按照：  
  1. **先在 VULN 上验证攻击链可行性**（登录绕过 / 文件读取 / SSRF / 命令注入等）；  
  2. 再调用对应 SAFE 接口，对比输入/输出/调试信息差异；  
  3. 最后在 `/api/v1/coach/analyze` 里结合最近流量和 spec，看教练总结的“why safe / next steps”。  
- 所有场景均设计为 **教学/研究用途**，请仅在本地或授权环境中使用。

