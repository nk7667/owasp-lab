export const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN（原始漏洞）' },
  { value: 'weak', label: 'WEAK（错误修复）' },
  { value: 'safe', label: 'SAFE（正确修复）' },
];

export const TARGET_OPTIONS = [
  { value: 'html', label: '结果高亮（HTML 内容）' },
  { value: 'attr', label: 'Share 链接（链接地址）' },
  { value: 'js', label: 'Analytics 配置（JS 字符串）' },
  { value: 'all', label: 'ALL（混合流 / 进阶）' },
];

export const PAYLOADS_BY_TARGET = {
  html: [
    {
      kind: '对照（WEAK 会挡住）',
      expect: 'WEAK 仅改写 <script（<script→<scr_ipt），通常不再执行；用于对照“WEAK 做了什么”。',
      value: '<script>alert(1)</script>',
    },
    {
      kind: '差异（WEAK-1 vs WEAK-2）',
      expect:
        '用于区分两个 WEAK：WEAK-1 会移除 javascript: 字面量；WEAK-2（富文本弱清洗）只挡 script/style，不会处理协议。可在预览里点击链接观察。',
      value: '<a href="javascript:alert(1)">click</a>',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '事件属性不在弱黑名单范围内；用于对照“WEAK 没做什么”。',
      value: "<img src=x onerror=alert('xss')>",
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '另一种常见载体（不依赖 <script>）。',
      value: '<svg onload=alert(1)></svg>',
    },
  ],
  attr: [
    {
      kind: '定位（结构是否被打断）',
      expect: '只用于判断是否存在“引号闭合 → 属性注入”。看预览里的 shareLink.outerHTML 是否出现你注入的新属性.',
      value: '" x="',
    },
    {
      kind: '验证（VULN：无需点击即可触发）',
      expect: '用于确认：当引号可闭合时，可以直接插入新元素触发事件（对照：WEAK-2 只有在 decode 后才会出现同样效果）。',
      value: '" ><img src=x onerror=alert(1)> x="',
    },
    {
      kind: '差异（WEAK-2 更容易中招）',
      expect:
        '用于区分 WEAK-1/WEAK-2：WEAK-2 会在字符串替换后额外做一次 decode（%22 复活为 "），从而打断 href 并形成属性/元素注入；VULN 不会 decode，因此 %22 只是一段 URL 文本。',
      value: '%22 onclick=alert(1) x=%22',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '属性注入（需要用户交互）：注入 onclick 后点击 Share link 才会触发。',
      value: '" onclick=alert(1) x="',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '同类问题的另一个触发点（事件属性）。',
      value: '" autofocus onfocus=alert(1) x="',
    },
  ],
  js: [
    {
      kind: '对照（结构是否异常）',
      expect: '用于观察 JS 结构是否被破坏（控制台报错/预览异常）；SAFE 应做 JS string escaping。',
      value: '"',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: 'WEAK 不做 JS 字符串转义，引号闭合仍可能改变结构。',
      value: "';alert(1);//",
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '同类结构逃逸的另一种写法。',
      value: "';alert(1);//",
    },
  ],
  all: [
    {
      kind: '进阶（混合流）',
      expect: 'ALL 会同时影响多个区域；建议先分别在 html/attr/js 下定位与理解原理。',
      value: "<img src=x onerror=alert('xss')>",
    },
    {
      kind: '进阶（混合流）',
      expect: '属性上下文的对照输入。',
      value: '" onclick=alert(1) x="',
    },
    {
      kind: '进阶（混合流）',
      expect: 'JS 上下文的对照输入。',
      value: "';alert(1);//",
    },
  ],
};

export const FOCUS_HINT = {
  html: { type: 'Reflected XSS', context: 'HTML 内容', sink: 'highlightHtml' },
  attr: { type: 'Reflected XSS', context: '链接地址（属性）', sink: 'shareHref' },
  js: { type: 'Reflected XSS', context: 'JavaScript 字符串', sink: 'analyticsConfig' },
  all: { type: 'Reflected XSS', context: '混合流（多落点）', sink: 'multi' },
};

export function contextIdByTarget(t) {
  const x = String(t || 'html');
  if (x === 'attr' || x === 'url') return 'xss_reflected_search_attr_href';
  if (x === 'js') return 'xss_reflected_search_js_jsString';
  if (x === 'all') return 'xss_reflected_search_multi_multi';
  return 'xss_reflected_search_html_innerHTML';
}

export function getWeakLevelOptions(effectiveTarget) {
  if (effectiveTarget === 'attr') {
    return [
      { value: 1, label: 'WEAK-1：只用字符串替换方法移除 javascript:' },
      { value: 2, label: 'WEAK-2：先替换后 decode' },
    ];
  }
  if (effectiveTarget === 'html') {
    return [
      { value: 1, label: 'WEAK-1：<script/javascript: 黑名单示例' },
      { value: 2, label: 'WEAK-2：仅挡 script/style（富文本弱清洗）' },
    ];
  }
  if (effectiveTarget === 'js') {
    return [{ value: 1, label: 'WEAK-1：复用 HTML 弱处理到 JS 字符串（无 JS 转义）' }];
  }
  return [{ value: 1, label: 'WEAK-1' }];
}

export function getWeakSummary(effectiveTarget, effectiveWeakLevel) {
  // 只给“为什么弱”的方向：能从练习现象推回原理，不剧透“最短打穿步骤”
  if (effectiveTarget === 'js') {
    return [
      'WEAK 做了什么：只做最小黑名单替换（例如把 <script 变形、移除 javascript: 字面量）。',
      'WEAK 漏了什么：没有做 JS string escaping（\\ / 引号 / 换行），输入仍可能改变脚本结构。',
      '怎么练出来：对比 SAFE 与 WEAK 的 output（analyticsConfig），看引号/反斜杠是否被正确转义。',
    ];
  }
  if (effectiveTarget === 'attr') {
    if (effectiveWeakLevel === 2) {
      return [
        'WEAK-2 做了什么：在字符串替换后又做了一次 decode（看起来“更规范化”）。',
        'WEAK-2 漏了什么：decode 可能把 %22/%27 还原为引号，导致 href 属性被打断并注入事件属性（典型“顺序错误导致复活”）。',
        '怎么练出来：用 %22 类输入对照 WEAK-1/WEAK-2 输出（shareHref），看引号是否被复活。',
      ];
    }
    return [
      'WEAK-1 做了什么：只移除 javascript: 字面量（属于“看起来像修了”的字符串替换）。',
      'WEAK 漏了什么：没有对 q 做 URL 编码/规范化，也没有做 HTML 属性编码（引号/空白仍危险）。',
      '怎么练出来：看 output（shareHref）里是否出现引号/空白导致结构被打断；SAFE 应降级危险输入或保持为安全 URL。',
    ];
  }
  if (effectiveTarget === 'html') {
    if (effectiveWeakLevel === 2) {
      return [
        'WEAK-2 做了什么：只挡 script/style 标签（富文本弱清洗）。',
        'WEAK-2 漏了什么：不处理事件属性、危险协议（如 javascript:）、以及其它载体（img/svg）。',
        '怎么练出来：对照 “javascript: 链接” 与 “事件属性” 两类输入，理解“只挡标签”为什么不够。',
      ];
    }
    return [
      'WEAK-1 做了什么：只改写 <script（<script→<scr_ipt）并移除 javascript: 字面量。',
      'WEAK 漏了什么：没有按 HTML 内容上下文做系统性处理（事件属性、其他标签/属性仍可能触发）。',
      '怎么练出来：对照“script 标签类输入”与“事件属性类输入”的差异，理解为什么黑名单不可靠。',
    ];
  }
  return [
    'ALL 是混合流：同一输入会进入多个上下文（HTML/href/JS），信号容易混叠。',
    '建议先分别用 html / attr / js 单落点练清原理，再回到 ALL 做综合对照。',
  ];
}
