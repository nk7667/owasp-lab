import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

export const healthApi = {
  get: () => api.get('/health'),
};

export const sqliApi = {
  vulnLogin: (username, password) =>
    api.post('/sqli/vuln/login', { username, password }),
  safeLogin: (username, password) =>
    api.post('/sqli/safe/login', { username, password }),
  vulnUsers: (sortField, sortOrder) =>
    api.get('/sqli/vuln/users/list', { params: { sortField, sortOrder } }),
  safeUsers: (sortField, sortOrder) =>
    api.get('/sqli/safe/users/list', { params: { sortField, sortOrder } }),
  vulnUser: (id) =>
    api.get('/sqli/vuln/users/detail', { params: { id } }),
  safeUser: (id) =>
    api.get('/sqli/safe/users/detail', { params: { id } }),
  vulnNewsUnionSearch: (q) =>
    api.get('/sqli/vuln/news/union/search', { params: { q } }),
  safeNewsUnionSearch: (q) =>
    api.get('/sqli/safe/news/union/search', { params: { q } }),
  vulnNewsAdvSearch: (q, titleMode = 'raw', titleExpr) =>
    api.get('/sqli/vuln/news/adv/search', { params: { q, titleMode, titleExpr } }),
  safeNewsAdvSearch: (q, titleMode = 'raw') =>
    api.get('/sqli/safe/news/adv/search', { params: { q, titleMode } }),
  vulnNewsBooleanProbe: (q, filterExpr) =>
    api.get('/sqli/vuln/news/boolean/probe', { params: { q, filterExpr } }),
  safeNewsBooleanProbe: (q, sortField = 'created_at', sortOrder = 'desc') =>
    api.get('/sqli/safe/news/boolean/probe', { params: { q, sortField, sortOrder } }),
  vulnNewsTimeProbe: (q, filterExpr) =>
    api.get('/sqli/vuln/news/time/probe', { params: { q, filterExpr } }),
  safeNewsTimeProbe: (q) =>
    api.get('/sqli/safe/news/time/probe', { params: { q } }),
};

export const coachApi = {
  recent: (limit = 10) => api.get('/coach/recent', { params: { limit } }),
  // LLM 调用可能 >10s，单独放宽超时
  analyze: (prompt, limit = 5) => api.post('/coach/analyze', { prompt, limit }, { timeout: 60000 }),
  // 前端训练事件上报（DOM XSS 等场景可能没有新的后端请求）
  event: (evt) => api.post('/coach/event', evt, { timeout: 5000 }),
  llmStatus: () => api.get('/coach/llm/status'),
  // 真实连通性检查（会触发一次极小 LLM 请求），放宽超时
  llmCheck: () => api.get('/coach/llm/check', { timeout: 20000 }),
};
export const xssApi = {
  searchRender: (mode = 'vuln', context = 'html', input = '') =>
      api.get(`/xss/${mode}/search/render`, { params: { context, input } }),
  // weakLevel：仅在 mode=weak 时有意义；保持 mode=vuln/weak/safe 不变
  searchResults: (mode = 'vuln', q = '', target = 'html', weakLevel = 1) =>
      api.get(`/xss/${mode}/search/results`, { params: { q, target, weakLevel } }),
  commentSubmit: (mode = 'vuln', author = 'anonymous', content = '', website = '', weakLevel = 1) =>
      api.post(`/xss/${mode}/comment/submit`, { author, content, website }, { params: { weakLevel } }),
  commentList: (mode = 'vuln', weakLevel = 1) =>
      api.get(`/xss/${mode}/comment/list`, { params: { weakLevel } }),
  commentDelete: (mode = 'vuln', id, weakLevel = 1) =>
      api.post(`/xss/${mode}/comment/delete`, null, { params: { id, weakLevel } }),
  commentClear: (mode = 'vuln', weakLevel = 1) =>
      api.post(`/xss/${mode}/comment/clear`, null, { params: { weakLevel } }),
  adminReview: (mode = 'vuln', weakLevel = 1) =>
      api.get(`/xss/${mode}/admin/review`, { params: { weakLevel } }),
  profileSubmit: (mode = 'vuln', nickname = '', bio = '') =>
      api.post(`/xss/${mode}/profile/submit`, { nickname, bio }),
};

export const blindApi = {
  beacon: (evt) => api.post('/blind/beacon', evt, { timeout: 5000 }),
  recent: (profileId, limit = 20) => api.get('/blind/recent', { params: { profileId, limit } }),
};

export const csrfApi = {
  login: (username, password) => api.post('/csrf/login', { username, password }),
  logout: () => api.post('/csrf/logout'),
  me: () => api.get('/csrf/me'),

  lowChange: (passwordNew, passwordConf) =>
    api.get('/csrf/low/password/change', { params: { password_new: passwordNew, password_conf: passwordConf, Change: 'Change' } }),

  highTokenPage: (hint = '') =>
    api.get('/csrf/high/password/page', { params: { hint } , responseType: 'text' }),

  highChange: (passwordNew, passwordConf, userToken) =>
    api.post(
      '/csrf/high/password/change',
      { password_new: passwordNew, password_conf: passwordConf, user_token: userToken },
      { headers: userToken ? { 'user-token': userToken } : {} }
    ),
};

export const ssrfApi = {
  fetch: (mode, url, weakLevel = 1) =>
    api.post(`/ssrf/fetch/${mode}`, null, { params: { url, weakLevel } }),
  imageProxy: (mode, imageUrl, weakLevel = 1) =>
    api.post(`/ssrf/image-proxy/${mode}`, null, { params: { imageUrl, weakLevel } }),
  download: (mode, fileUrl, weakLevel = 1) =>
    api.post(`/ssrf/download/${mode}`, null, { params: { fileUrl, weakLevel } }),
};

// 与后端一致：POST，路径为 /command-execution/network/ping/{mode}、/file/ls|grep|cat/{mode}
export const commandExecutionApi = {
  ping: (mode, host, weakLevel = 1) =>
    api.post(`/command-execution/network/ping/${mode}`, null, { params: { host, weakLevel } }),
  ls: (mode, path, weakLevel = 1) =>
    api.post(`/command-execution/file/ls/${mode}`, null, { params: { path, weakLevel } }),
  grep: (mode, keyword, weakLevel = 1) =>
    api.post(`/command-execution/file/grep/${mode}`, null, { params: { keyword, weakLevel } }),
  cat: (mode, filename, weakLevel = 1) =>
    api.post(`/command-execution/file/cat/${mode}`, null, { params: { filename, weakLevel } }),
};