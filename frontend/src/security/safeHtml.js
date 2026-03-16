import DOMPurify from 'dompurify';
import { coachApi } from '../utils/api';

const SAFE_HTML_BRAND = Symbol.for('owasp-lab.safeHtml');

function getHardenMode() {
  // off | log | block（运行期收敛：用于“先观测，再阻断”）
  const fromEnv = String(import.meta?.env?.VITE_XSS_HARDEN_MODE || '').toLowerCase();
  const fromLs = String(window?.localStorage?.getItem('xss_harden_mode') || '').toLowerCase();
  return (fromLs || fromEnv || 'log').toLowerCase();
}

function report(evt) {
  coachApi.event({ context: 'xss_api_hardening', ts: Date.now(), ...evt }).catch(() => {});
}

function isAllowedHref(href) {
  const s = String(href || '').trim();
  if (!s) return false;
  try {
    const u = new URL(s, window.location.origin);
    return u.protocol === 'http:' || u.protocol === 'https:' || u.protocol === 'mailto:';
  } catch {
    return false;
  }
}

export function sanitizeToSafeHtml(raw, meta = {}) {
  const input = String(raw ?? '');

  // 白名单策略：可按教学/企业策略收紧
  const clean = DOMPurify.sanitize(input, {
    ALLOWED_TAGS: ['b', 'strong', 'i', 'em', 'u', 'p', 'br', 'ul', 'ol', 'li', 'code', 'pre', 'blockquote', 'a'],
    ALLOWED_ATTR: ['href', 'title', 'target', 'rel'],
    FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'link', 'meta', 'svg', 'math'],
    FORBID_ATTR: [/^on/i, 'srcset', 'style', 'xlink:href'],
    KEEP_CONTENT: true,
  });

  // 协议白名单收敛（显式把策略讲出来）
  const box = document.createElement('div');
  box.innerHTML = clean;
  for (const a of box.querySelectorAll('a[href]')) {
    const href = a.getAttribute('href') || '';
    if (!isAllowedHref(href)) a.setAttribute('href', '#');
    a.setAttribute('rel', 'noreferrer noopener');
  }

  const html = box.innerHTML;
  const mode = getHardenMode();
  if (mode !== 'off') {
    report({
      action: 'sanitize',
      mode,
      source: meta.source || 'unknown',
      bytesIn: input.length,
      bytesOut: html.length,
    });
  }

  return Object.freeze({ [SAFE_HTML_BRAND]: true, html });
}

export function assertSafeHtml(x, meta = {}) {
  const ok = !!(x && x[SAFE_HTML_BRAND] === true && typeof x.html === 'string');
  if (ok) return;

  const mode = getHardenMode();
  const evt = {
    action: 'unsafe_html_usage',
    mode,
    source: meta.source || 'unknown',
    valueType: typeof x,
  };

  if (mode === 'block') {
    report(evt);
    throw new Error('Unsafe HTML blocked: please use sanitizeToSafeHtml()');
  }

  if (mode === 'log') report(evt);
}

