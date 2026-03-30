import { reportCoachUi } from './coachUi';

/**
 * 统一 XSS 页面上报入口（轻量封装）：
 * - 规范 context/mode/target/focus/input 字段组织
 * - 保留 extras 透传，便于各实验页逐步共用
 */
export function reportXssUi({ context, mode, target, focus, input, extras }) {
  reportCoachUi({
    context,
    mode,
    target,
    focus,
    input,
    extras,
  });
}

