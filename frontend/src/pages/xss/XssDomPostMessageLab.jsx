import { useEffect, useMemo, useRef } from 'react';

const XSS_DOM_HANDWRITTEN_MSG = 'xss-dom-handwritten-v1';

export default function XssDomPostMessageLab({ sink, runSeq, keyword }) {
  const iframeRef = useRef(null);
  const keywordRef = useRef(keyword);

  // 保存最新 keyword，避免 useEffect 依赖 keyword 导致“边打字边发消息”
  useEffect(() => {
    keywordRef.current = keyword;
  }, [keyword]);

  const iframeSrcDoc = useMemo(() => {
    const s = sink;
    const sourceType = 'postmessage';
    const expectedOrigin = window?.location?.origin || '';

    return `<!doctype html>
<meta charset="utf-8">
<title>DOM XSS · postMessage.data → innerHTML / textContent</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}
  .box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;background:#161f2e}
  .muted{color:#8b9cb3;font-size:12px;line-height:1.5;margin-bottom:8px}
  #out{border:1px solid #2d3a4d;border-radius:10px;padding:10px;background:#0b1020;white-space:pre-wrap}
</style>
<div class="box">
  <div class="muted">source：postMessage.data</div>
  <div class="muted">sink：${s}</div>
  <div id="out">Waiting…</div>
</div>
<script>
(function () {
  var sink = ${JSON.stringify(s)};
  var sourceType = ${JSON.stringify(sourceType)};
  var MSG_TYPE = ${JSON.stringify(XSS_DOM_HANDWRITTEN_MSG)};
  var EXPECTED_ORIGIN = ${JSON.stringify(expectedOrigin)};

  var out = document.getElementById('out');
  if (!out) return;

  function handle(d) {
    if (sink === 'textContent') out.textContent = 'Received: ' + d;
    else {
      out.innerHTML = 'Received: ' + d;
      // 一些环境会阻断 inline 事件属性（如 onerror="...">）
      // 这里用 JS 兜底绑定，确保 “innerHTML 解析出 <img>” 可验证。
      try {
        var img = out.querySelector('img');
        if (img) {
          img.onerror = function () {
            try { alert(1); } catch (e) {}
          };
          // 重新触发一次错误：改成“必定无效”的 URL
          img.src = 'x_' + String(Date.now());
        }
      } catch (e2) {}
    }
  }

  window.addEventListener('message', function (e) {
    if (!e || e.source !== window.parent) return;
    if (!EXPECTED_ORIGIN || e.origin !== EXPECTED_ORIGIN) return;
    var data = e.data;
    if (!data || typeof data !== 'object') return;
    if (data.type !== MSG_TYPE) return;
    if (typeof data.payload !== 'string') return;
    handle(data.payload);
  });
})();
</script>`;
  }, [sink]);

  useEffect(() => {
    const win = iframeRef.current?.contentWindow;
    if (!win) return;

    const t = window.setTimeout(() => {
      try {
        const payload = String(keywordRef.current || '');
        win.postMessage({ type: XSS_DOM_HANDWRITTEN_MSG, payload }, '*');
      } catch {
        // ignore
      }
    }, 50);

    return () => window.clearTimeout(t);
  }, [runSeq, sink]);

  return (
    <iframe
      title="xss-dom-preview"
      sandbox="allow-scripts allow-modals"
      srcDoc={iframeSrcDoc}
      key={`postmessage::${sink}`}
      ref={iframeRef}
      style={{
        width: '100%',
        height: 220,
        border: '1px solid #2d3a4d',
        borderRadius: 10,
        background: '#0b1020',
      }}
    />
  );
}

