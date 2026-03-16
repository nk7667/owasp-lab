import { useEffect, useMemo, useState } from 'react';
import { useLocation } from 'react-router-dom';
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  InputNumber,
  Row,
  Select,
  Space,
  Switch,
  Typography,
} from 'antd';
import { reportCoachUi } from './_shared/coachUi';

const { Text } = Typography;

function useQuery() {
  const { search } = useLocation();
  return useMemo(() => new URLSearchParams(search), [search]);
}

const ALERT_DARK_BASE_STYLE = {
  background: '#0f1419',
  border: '1px solid #2d3a4d',
};

export default function XssStoredProfileAdmin() {
  const q = useQuery();
  const initialId = q.get('id');
  const initialMode = q.get('mode');

  const [mode, setMode] = useState(initialMode || 'vuln');
  const [profileId, setProfileId] = useState(initialId ? Number(initialId) : null);
  const [allowForms, setAllowForms] = useState(false);
  const [reloadKey, setReloadKey] = useState(1);

  const context = 'xss_blind_profile_admin_html_innerHTML';

  const reportUi = (evt) => {
    reportCoachUi({
      context,
      mode,
      target: 'profile_admin',
      focus: evt?.focus || '',
      input: evt?.input || '',
    });
  };

  const iframeUrl = useMemo(() => {
    if (!profileId) return '';
    const base = `/api/v1/xss/${mode}/profile/admin/view`;
    const params = new URLSearchParams();
    params.set('id', String(profileId));
    params.set('_t', String(reloadKey));
    return `${base}?${params.toString()}`;
  }, [mode, profileId, reloadKey]);

  const sandbox = useMemo(() => {
    const parts = ['allow-scripts', 'allow-same-origin'];
    if (allowForms) parts.push('allow-forms');
    return parts.join(' ');
  }, [allowForms]);

  useEffect(() => {
    reportUi({ focus: 'enter', input: `profileId=${profileId || ''}` });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={15}>
          <Card title="Blind · Profile（后台预览端）" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>

              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <Text type="secondary">mode</Text>
                <Select
                  value={mode}
                  style={{ width: 160 }}
                  options={[
                    { value: 'vuln', label: 'VULN' },
                    { value: 'safe', label: 'SAFE' },
                  ]}
                  onChange={(v) => {
                    setMode(v);
                    reportUi({ focus: 'mode_change', input: v });
                    setReloadKey((x) => x + 1);
                  }}
                />

                <Text type="secondary">profileId</Text>
                <InputNumber
                  value={profileId}
                  min={1}
                  placeholder="比如 1"
                  style={{ width: 180 }}
                  onChange={(v) => {
                    const n = typeof v === 'number' ? v : null;
                    setProfileId(n);
                    reportUi({ focus: 'id_change', input: String(n || '') });
                  }}
                />

                <Text type="secondary">allow-forms</Text>
                <Switch checked={allowForms} onChange={(v) => setAllowForms(v)} />

                <Button onClick={() => setReloadKey((x) => x + 1)} disabled={!profileId}>
                  刷新 iframe
                </Button>
                <Button
                  onClick={() => {
                    if (!iframeUrl) return;
                    window.open(iframeUrl, '_blank', 'noopener,noreferrer');
                  }}
                  disabled={!profileId}
                >
                  新窗口打开后台页
                </Button>
              </div>

              <Divider style={{ margin: '12px 0' }} />

              <div style={{ border: '1px solid #2d3a4d', borderRadius: 12, overflow: 'hidden' }}>
                {iframeUrl ? (
                  <iframe
                    key={`${mode}-${profileId}-${reloadKey}-${sandbox}`}
                    title="admin-profile"
                    src={iframeUrl}
                    sandbox={sandbox}
                    style={{ width: '100%', height: 520, border: 0, background: '#0b1220' }}
                  />
                ) : (
                  <div style={{ padding: 16, color: '#8b9cb3' }}>请输入 profileId 后加载后台页。</div>
                )}
              </div>
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={9}>
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Card title="Security Coach" bordered>
              <Space direction="vertical" size={10} style={{ width: '100%' }}>
                <Descriptions
                  size="small"
                  column={1}
                  bordered
                  items={[
                    { key: 'type', label: '类型', children: 'Stored XSS · Blind · Profile' },
                    { key: 'context', label: 'context', children: context },
                    { key: 'sink', label: '落点', children: 'HTML 内容（bio 区域）' },
                  ]}
                />
                <div>
                  <Text type="secondary">你的输入会被插入到这里：</Text>
                  <pre style={{ marginTop: 8, marginBottom: 0, whiteSpace: 'pre-wrap' }}>
                    {'<div id="bio">\n  <YOUR_INPUT_HERE>\n</div>'}
                  </pre>
                </div>
                <Alert
                  type="info"
                  showIcon
                  style={ALERT_DARK_BASE_STYLE}
                  message={
                    <span style={{ color: '#e6edf3' }}>
                      这是目标系统的后台预览端（用于模拟管理员打开记录并触发执行）。攻击者视角的 OOB 事件请到
                      “盲打 · Profile（提交）”或“攻击者控制台（OOB）”查看。
                    </span>
                  }
                />
              </Space>
            </Card>
          </Space>
        </Col>
      </Row>
    </div>
  );
}

