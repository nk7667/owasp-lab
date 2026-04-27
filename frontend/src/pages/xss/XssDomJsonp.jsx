import { Button, Card, Col, Form, Input, Row, Select, Space, Tag, Typography } from 'antd';
import { PlayCircleOutlined } from '@ant-design/icons';
import { useMemo, useState } from 'react';
import { reportXssUi } from './_shared/reporting';
import {
  contextIdByLab,
  getLabGoal,
  getPayloadItems,
  MODE_OPTIONS,
} from './XssDom.config';

const { Title, Paragraph, Text } = Typography;

const DOM_TEXT = {
  keywordLabelJsonp: 'keyword（JSONP callback 输入）',
  keywordPlaceholderJsonp: '例如：<script src="?callback=alert"></script>',
};

function getWeakLevelOptionsByLab(lab) {
  if (lab === 'csp_jsonp') {
    return [
      { value: 1, label: 'WEAK-1：callback 黑名单（可被拼接/方括号绕过）' },
      { value: 2, label: 'WEAK-2：CSP report-uri 拼接（演示分号注入）' },
    ];
  }
  return [{ value: 1, label: 'WEAK-1' }];
}

function getLabChain(lab) {
  if (lab === 'csp_jsonp') {
    return {
      vuln: '用户输入进入同源 JSONP 的 callback（gadget），在 CSP 限制下仍可能被“同源脚本”路径执行。',
    };
  }
  return { vuln: '' };
}

export default function XssDomJsonp() {
  const [form] = Form.useForm();
  const [mode, setMode] = useState('vuln');
  const [weakLevel, setWeakLevel] = useState(1);
  const [runSeq, setRunSeq] = useState(0);

  const lab = 'csp_jsonp';
  const keyword = Form.useWatch('keyword', form);

  const reportUi = (focusName, inputValue) => {
    reportXssUi({
      context: contextIdByLab(lab),
      mode,
      target: lab,
      focus: focusName,
      input: inputValue,
      extras: { weakLevel },
    });
  };

  const iframeSrc = useMemo(() => {
    const k = encodeURIComponent(keyword || '');
    return `/api/v1/xss/${mode}/csp/jsonp?keyword=${k}&weakLevel=${weakLevel}&__r=${runSeq}`;
  }, [mode, keyword, weakLevel, runSeq]);

  const labGoal = useMemo(() => getLabGoal(lab), []);
  const labChain = useMemo(() => getLabChain(lab), []);
  const payloadItems = useMemo(() => getPayloadItems(lab), []);

  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 4 }}>
        XSS · DOM（JSONP）
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 13, marginBottom: 12 }}>
        选模式 → 填 keyword（JSONP 回调输入）→ 运行预览。这里是单独一关：CSP + 同源 JSONP gadget。
      </Paragraph>

      <Row gutter={16}>
        <Col xs={24} lg={16}>
          <Card
            styles={{ body: { background: '#0f1419', border: '1px solid #2d3a4d' } }}
            style={{ borderRadius: 12, background: '#0f1419', border: '1px solid #2d3a4d' }}
          >
            <Space wrap style={{ marginBottom: 12 }}>
              <Select
                value={mode}
                onChange={(v) => {
                  setMode(v);
                  reportUi('mode_change', keyword || '');
                }}
                options={MODE_OPTIONS}
                style={{ width: 120 }}
              />

              {mode === 'weak' && (
                <Select
                  value={weakLevel}
                  onChange={(v) => {
                    setWeakLevel(v);
                    reportUi('weak_level_change', keyword || '');
                  }}
                  options={getWeakLevelOptionsByLab(lab)}
                  style={{ width: 280 }}
                />
              )}
            </Space>

            {/* 左侧：只展示必要信息，不使用折叠 */}
            {mode !== 'safe' ? (
              <div
                style={{
                  marginBottom: 12,
                  padding: 12,
                  background: '#0b1020',
                  border: '1px solid #2d3a4d',
                  borderRadius: 12,
                  color: '#c6d3e5',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <Text strong style={{ color: '#e6edf3', fontSize: 12 }}>VULN</Text>
                  <span style={{ color: '#8b9cb3', fontSize: 12 }}>CSP + JSONP gadget</span>
                </div>
                <div style={{ marginTop: 6, fontSize: 13, lineHeight: 1.6 }}>{labChain.vuln}</div>

                <div style={{ marginTop: 10, fontSize: 12, lineHeight: 1.65 }}>
                  <div style={{ marginTop: 10, color: '#94a3b8', fontSize: 12 }}>
                    对照：看控制台 CSP（同源 JSONP 可能仍会执行）。
                  </div>
                </div>
              </div>
            ) : (
              <div
                style={{
                  marginBottom: 12,
                  padding: 12,
                  background: '#0b1020',
                  border: '1px solid #2d3a4d',
                  borderRadius: 12,
                  color: '#c6d3e5',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <Text strong style={{ color: '#e6edf3', fontSize: 12 }}>SAFE 要点</Text>
                  <span style={{ color: '#8b9cb3', fontSize: 12 }}>callback 白名单</span>
                </div>
                <div style={{ marginTop: 6, fontSize: 13, lineHeight: 1.6 }}>
                  JSONP 的关键修复：不要把 callback 当“可控代码片段”，而是收敛到固定/白名单函数名。
                </div>
                <div style={{ marginTop: 10, color: '#94a3b8', fontSize: 12, lineHeight: 1.6 }}>
                  对照：看控制台 CSP；SAFE 固定 callback。
                </div>
              </div>
            )}

            <Form
              form={form}
              layout="vertical"
              initialValues={{ keyword: '' }}
              onFinish={() => {
                reportUi('run_preview', keyword || '');
                setRunSeq((x) => x + 1);
              }}
            >
              <Form.Item name="keyword" label={DOM_TEXT.keywordLabelJsonp}>
                <Input placeholder={DOM_TEXT.keywordPlaceholderJsonp} />
              </Form.Item>

              <Button type="primary" htmlType="submit" icon={<PlayCircleOutlined />}>
                运行预览
              </Button>
            </Form>

            <div style={{ color: '#8b9cb3', fontSize: 12, marginTop: 12 }}>
              预览 URL：<span style={{ fontFamily: 'JetBrains Mono, ui-monospace, monospace' }}>{iframeSrc}</span>
            </div>

            <iframe
              title="xss-dom-preview-jsonp"
              sandbox="allow-scripts allow-modals allow-forms"
              src={iframeSrc}
              key={`${mode}::${runSeq}`}
              style={{ width: '100%', height: 420, border: '1px solid #2d3a4d', borderRadius: 10, background: '#0b1020' }}
            />
          </Card>
        </Col>

        <Col xs={24} lg={8}>
          <Card
            title={<span style={{ color: '#e6edf3' }}>对照面板</span>}
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', height: '100%' }}
          >
            <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.65 }}>
              <div>DOM/策略 · CSP + 同源 JSONP gadget</div>
              <div style={{ marginTop: 6 }}>sink：JSONP callback（script-src 'self' 执行路径）</div>
            </div>

            <div style={{ marginTop: 12 }}>
              {payloadItems.map((it) => {
                const kind = String(it?.kind ?? '');
                const tagColor = kind.includes('对照') ? 'gold' : kind.includes('WEAK') ? 'volcano' : kind.includes('inline') ? 'blue' : undefined;
                return (
                  <Tag
                    key={`${it.kind}:${it.value}`}
                    color={tagColor}
                    style={{
                      cursor: 'pointer',
                      marginBottom: 6,
                      fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                      whiteSpace: 'normal',
                      maxWidth: '100%',
                      wordBreak: 'break-word',
                      lineHeight: 1.25,
                      paddingBlock: 6,
                      paddingInline: 10,
                      display: 'block',
                    }}
                    onClick={() => {
                      form.setFieldsValue({ keyword: it.value });
                      reportUi('payload_click', it.value);
                    }}
                  >
                    <div style={{ fontWeight: 600 }}>{kind}</div>
                    <div style={{ opacity: 0.92, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{it.value}</div>
                    <div style={{ marginTop: 6, color: '#8b9cb3', fontSize: 11, whiteSpace: 'pre-wrap', lineHeight: 1.35 }}>
                      {it.expect}
                    </div>
                  </Tag>
                );
              })}
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

