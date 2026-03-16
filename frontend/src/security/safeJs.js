export function jsStringEscape(s) {
  return String(s ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/'/g, "\\'")
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n');
}

export function jsonStringifySafe(obj) {
  // 解决把 JSON 放进 <script> 时的 "</script>" 闭合风险（最小化演示）
  return JSON.stringify(obj).replace(/</g, '\\u003c');
}

