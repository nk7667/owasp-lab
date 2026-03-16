# OWASP Lab 前端

- **技术栈**：React 18 + Vite + Ant Design v6
- **主题**：深色科技风，低饱和度配色

## 运行

```bash
cd frontend
npm install
npm run dev
```

浏览器打开 http://localhost:5173 。请先启动后端（Spring Boot 默认 8080），Vite 会将 `/api` 代理到后端。

## 构建

```bash
npm run build
```

输出在 `dist/`，可部署到任意静态托管。
