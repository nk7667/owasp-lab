import { coachApi } from '../../../utils/api';

export function clipInput(inputValue, maxLen = 200) {
  const s = String(inputValue ?? '');
  return s.length <= maxLen ? s : s.slice(0, maxLen);
}

/**
 * 统一的“训练 UI 事件”上报：
 * - 自动截断 input
 * - 自动补 ts
 * - swallow 网络错误（不影响练习）
 * - 支持 extras：保留页面里额外的教学字段（例如 weakLevel / lab 等）
 */
export function reportCoachUi({ context, mode, target, focus, input, ts, extras } = {}) {
  const payload = {
    context: String(context ?? ''),
    mode: String(mode ?? ''),
    target: String(target ?? ''),
    focus: String(focus ?? ''),
    input: clipInput(input, 200),
    ts: typeof ts === 'number' ? ts : Date.now(),
    ...(extras && typeof extras === 'object' ? extras : {}),
  };
  coachApi.event(payload).catch(() => {});
}

