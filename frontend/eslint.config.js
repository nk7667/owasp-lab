import js from '@eslint/js';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import owaspXss from './eslint-plugin-owasp-xss/index.js';

// 只提示（warn），不阻断构建/CI
const severity = 'warn';

export default [
  // 只 lint 源码：忽略构建产物/依赖
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,

  {
    files: ['src/**/*.{js,jsx}'],
    plugins: {
      react,
      'react-hooks': reactHooks,
      'owasp-xss': owaspXss,
    },
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      // 前端项目：声明常见浏览器全局变量，避免 no-undef 噪音
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        performance: 'readonly',
        localStorage: 'readonly',
        sessionStorage: 'readonly',
        URL: 'readonly',
        Event: 'readonly',
        MouseEvent: 'readonly',
      },
    },
    settings: { react: { version: 'detect' } },
    rules: {
      // JSX 中使用的变量（组件名等）算作“已使用”，避免大量 no-unused-vars 误报
      'react/jsx-uses-vars': 'warn',
      'react/react-in-jsx-scope': 'off',

      // 只提示：不让 lint 因为“未使用变量/导入”直接失败
      'no-unused-vars': 'warn',

      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // 核心：危险 sink 仅提示（warn），不阻断
      'owasp-xss/no-dangerously-set-inner-html': severity,
      'owasp-xss/no-innerhtml-assign': severity,
    },
  },

  // 靶场关卡：允许出现漏洞写法用于教学对照（否则无法写 VULN/WEAK）
  {
    files: ['src/pages/xss/**/*.{js,jsx}'],
    rules: {
      'owasp-xss/no-dangerously-set-inner-html': 'off',
      'owasp-xss/no-innerhtml-assign': 'off',
    },
  },

  // 安全清洗模块内部会用 innerHTML 做“解析 DOM → 再遍历收敛协议”，不属于业务侧危险用法
  {
    files: ['src/security/safeHtml.js'],
    rules: {
      'owasp-xss/no-innerhtml-assign': 'off',
    },
  },

  // 安全替代组件内部会封装 dangerouslySetInnerHTML：这里不需要再提示
  {
    files: ['src/components/SafeHtml.jsx'],
    rules: {
      'owasp-xss/no-dangerously-set-inner-html': 'off',
    },
  },
];

