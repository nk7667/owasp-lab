import { useEffect, useMemo, useRef } from 'react';

const XSS_DOM_HANDWRITTEN_MSG = 'xss-dom-handwritten-v1';

/**
 * 第三关：sink = document.write
 * 教学对照：真实页面里这段字符串常来自 location.search（或其后端映射）；此处为统一沙箱与信任边界，不由独立 .html + ? 传参。
 */
export default function XssDomDocumentWriteSearchLab({ sink, runSeq, keyword }) {
  const iframeRef = useRef(null);
  const keywordRef = useRef(keyword);

  useEffect(() => {
    keywordRef.current = keyword;
  }, [keyword]);

  const iframeSrcDoc = useMemo(() => {
    const s = sink;
    const expectedOrigin = window?.location?.origin || '';

    return `<!doctype html>
<meta charset="utf-8">
<title>DOM XSS · document.write（对应 search 可控数据）</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}
  .box{border:1px solid #2d3a4d;border-radius:10px;padding:10px;background:#161f2e}
  .muted{color:#8b9cb3;font-size:12px;line-height:1.5;margin-bottom:8px}
</style>
<div class="box">
  <div class="muted">真实站点：可控数据常来自 location.search；本沙箱与其它关一致：由父页 postMessage 投递（再进 document.write）。</div>
  <div class="muted">sink：document.write（${s === 'textContent' ? 'SAFE·escapeHtml' : 'VULN·原文拼接'}）</div>
  <div id="hint" class="muted">Waiting…</div>
</div>
<script>
(function () {
  var sink = ${JSON.stringify(s)};
  var MSG_TYPE = ${JSON.stringify(XSS_DOM_HANDWRITTEN_MSG)};
  var EXPECTED_ORIGIN = ${JSON.stringify(expectedOrigin)};

  var hint = document.getElementById('hint');
  function escapeHtml(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function bindImgFallback() {
    try {
      var out = document.getElementById('out');
      if (!out) return;
      var img = out.querySelector('img');
      if (!img) return;
      img.onerror = function () {
        try { alert(1); } catch (e) {}
      };
      img.src = 'x_' + String(Date.now());
    } catch (e2) {}
  }

  function handle(d) {
    var safe = (sink === 'textContent');
    var inner = safe ? escapeHtml(d) : d;
    // 消息到达时文档往往已结束解析；document.write 会隐式 open 并替换文档流
    document.open();
    document.write('<!doctype html><meta charset="utf-8"><style>body{font-family:system-ui,Segoe UI,Arial;margin:0;padding:12px;background:#0f1419;color:#e6edf3}#out{border:1px solid #2d3a4d;border-radius:10px;padding:10px;background:#0b1020;white-space:pre-wrap;margin-top:10px}</style><div id="out">Received: ' + inner + '</div>');
    document.close();
    setTimeout(bindImgFallback, 0);
  }

  window.addEventListener('message', function (e) {
    if (!e || e.source !== window.parent) return;
    if (!EXPECTED_ORIGIN || e.origin !== EXPECTED_ORIGIN) return;
    var data = e.data;
    if (!data || typeof data !== 'object') return;
    if (data.type !== MSG_TYPE) return;
    if (typeof data.payload !== 'string') return;
    if (hint) hint.textContent = 'Received envelope, running document.write…';
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
        win.postMessage(
          { type: XSS_DOM_HANDWRITTEN_MSG, payload: String(keywordRef.current || '') },
          '*',
        );
      } catch {
        // ignore
      }
    }, 50);
    return () => window.clearTimeout(t);
  }, [runSeq, sink]);

  return (
    <iframe
      title="xss-dom-document-write"
      sandbox="allow-scripts allow-modals"
      srcDoc={iframeSrcDoc}
      key={`search_write::${sink}::${runSeq}`}
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
