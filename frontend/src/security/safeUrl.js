export function safeUrlOrHash(raw) {
  const s = String(raw || '').trim();
  if (!s) return '#';
  try {
    const u = new URL(s, window.location.origin);
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString();
    return '#';
  } catch {
    return '#';
  }
}

