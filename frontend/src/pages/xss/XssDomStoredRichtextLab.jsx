import { Button, Input, Select, Tag, Typography } from 'antd';
import { useMemo, useState } from 'react';
import SafeHtml from '../../components/SafeHtml';
import { sanitizeToSafeHtml } from './richtext/domStoredRichtextSafeHtml';
import { reportXssUi } from './_shared/reporting';

const { Text } = Typography;
const { TextArea } = Input;
const STORAGE_KEY = 'xss_dom_richtext_comments_v1';

function loadComments() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function saveComments(items) {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(items));
  } catch {
    // ignore
  }
}

export default function XssDomStoredRichtextLab() {
  const [mode, setMode] = useState('innerHTML'); // innerHTML | textContent | safeHtml
  const [input, setInput] = useState('');
  const [comments, setComments] = useState(() => loadComments());

  const payloads = useMemo(
    () => [
      { kind: '可执行', value: '<img src=x onerror=alert(1)>' },
      { kind: '富文本', value: '<p><b>hello</b> <a href="javascript:alert(1)">link</a></p>' },
      { kind: '无害', value: '<p><strong>safe text</strong></p>' },
    ],
    [],
  );

  const report = (focus, value) => {
    reportXssUi({
      context: 'xss_dom_stored_richtext',
      mode: mode === 'innerHTML' ? 'vuln' : 'safe',
      target: 'localStorage',
      focus,
      input: String(value || ''),
      extras: { renderMode: mode },
    });
  };

  const addComment = () => {
    const content = String(input || '');
    if (!content) return;
    const next = [
      { id: Date.now(), content, ts: new Date().toLocaleString() },
      ...comments,
    ];
    setComments(next);
    saveComments(next);
    setInput('');
    report('submit_comment', content);
  };

  const clearComments = () => {
    setComments([]);
    saveComments([]);
    report('clear_all', '');
  };

  const reloadComments = () => {
    setComments(loadComments());
    report('reload_from_storage', '');
  };

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 10 }}>
        <Select
          value={mode}
          onChange={(v) => {
            setMode(v);
            report('mode_change', input);
          }}
          options={[
            { value: 'innerHTML', label: 'VULN：innerHTML 原样渲染（可执行）' },
            { value: 'textContent', label: 'SAFE-1：textContent 纯文本' },
            { value: 'safeHtml', label: 'SAFE-2：HTML 白名单（DOMPurify）' },
          ]}
          style={{ minWidth: 360 }}
        />
        <Button onClick={reloadComments}>从 localStorage 重新加载</Button>
        <Button danger onClick={clearComments}>清空评论</Button>
      </div>

      <div style={{ marginBottom: 10, color: '#8b9cb3', fontSize: 12 }}>
        source：用户评论输入 → localStorage（持久化）→ 渲染列表
      </div>

      <TextArea
        rows={3}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="输入评论（支持富文本）"
      />
      <div style={{ marginTop: 8, marginBottom: 10 }}>
        <Button type="primary" onClick={addComment}>发布评论</Button>
      </div>

      <div style={{ marginBottom: 10 }}>
        <Text type="secondary" style={{ fontSize: 12 }}>一键填 payload</Text>
        <div style={{ marginTop: 8 }}>
          {payloads.map((p) => (
            <Tag
              key={p.kind + p.value}
              style={{ cursor: 'pointer', display: 'block', marginBottom: 6, whiteSpace: 'normal' }}
              onClick={() => {
                setInput(p.value);
                report('payload_click', p.value);
              }}
            >
              <div style={{ fontWeight: 600 }}>{p.kind}</div>
              <div>{p.value}</div>
            </Tag>
          ))}
        </div>
      </div>

      <div style={{ border: '1px solid #2d3a4d', borderRadius: 10, padding: 10, background: '#0b1020' }}>
        <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 8 }}>
          评论列表（刷新后仍存在，体现存储型）
        </div>
        {comments.length === 0 ? (
          <div style={{ color: '#94a3b8', fontSize: 12 }}>暂无评论</div>
        ) : (
          comments.map((c) => (
            <div key={c.id} style={{ borderBottom: '1px dashed #2d3a4d', paddingBlock: 8 }}>
              <div style={{ color: '#8b9cb3', fontSize: 12, marginBottom: 4 }}>{c.ts}</div>
              {mode === 'innerHTML' ? (
                <div dangerouslySetInnerHTML={{ __html: c.content }} />
              ) : mode === 'textContent' ? (
                <div>{c.content}</div>
              ) : (
                <SafeHtml value={sanitizeToSafeHtml(c.content, { source: 'xss_dom_stored_richtext' })} />
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

