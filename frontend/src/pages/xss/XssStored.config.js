export const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN（原始漏洞）' },
  { value: 'weak', label: 'WEAK（错误修复）' },
  { value: 'safe', label: 'SAFE（正确修复）' },
];

export const FOCUS_OPTIONS = [
  { value: 'content', label: '评论内容（HTML 内容）' },
  { value: 'website', label: '个人主页（链接地址）' },
];

export const PAYLOADS_BY_FOCUS = {
  content: [
    {
      kind: '对照（WEAK 会挡住）',
      expect: 'WEAK 会把 <script 变形（<script→<scr_ipt）；用于对照“WEAK 做了什么”。',
      value: '<script>alert(1)</script>',
    },
    {
      kind: '可绕过 WEAK',
      expect: '事件属性不在弱黑名单范围内；用于对照“WEAK 没做什么”。',
      value: "<img src=x onerror=alert('stored-xss')>",
    },
    {
      kind: '可绕过 WEAK',
      expect: '另一种载体（不依赖 <script>）。',
      value: '<svg onload=alert(1)></svg>',
    },
  ],
  // WEAK 常见：只挡 javascript: 字面量；补充实体编码/协议变体，帮助理解“弱在哪”
  website: [
    {
      kind: '对照（WEAK 会改写）',
      expect: 'WEAK 常见做法是“移除 javascript: 字面量”；观察管理员页 link 的 href 变化。',
      value: 'javascript:alert(1)',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '实体/混淆形态不等于字面量；字符串替换可能漏掉。',
      value: 'jav&#x61;script:alert(1)',
    },
    {
      kind: '验证（仍可绕过 WEAK）',
      expect: '非 javascript: 也可能危险（示例：data:）。SAFE 应做协议白名单（http/https）。',
      value: 'data:text/html,<script>alert(1)</script>',
    },
  ],
};

export const FOCUS_HINT = {
  content: { type: 'Stored XSS', context: 'HTML 内容', sink: 'content' },
  website: { type: 'Stored XSS', context: '链接地址（属性）', sink: 'websiteHref' },
};

export function getWeakSummaryByFocus(focus) {
  if (focus === 'website') {
    return [
      'WEAK 做了什么：只移除 javascript: 字面量（字符串替换）。',
      'WEAK 漏了什么：没有协议白名单/规范化（http/https），也没有使用 DOM API 安全写入（setAttribute/a.href）。',
      '怎么练出来：看管理员页 link 最终 href；对照 SAFE 下危险 scheme 会降级为 #。',
    ];
  }
  return [
    'WEAK 做了什么：只改写 <script（<script→<scr_ipt）并移除 javascript: 字面量。',
    'WEAK 漏了什么：没有按 HTML 内容上下文做系统性处理（事件属性、其他标签/属性仍可能触发）。',
    '怎么练出来：对照“script 标签类输入”与“事件属性类输入”的差异。',
  ];
}

