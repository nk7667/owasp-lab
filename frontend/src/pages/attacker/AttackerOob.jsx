import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Col, InputNumber, Row, Space, Table, Tag, Typography } from 'antd';
import { blindApi } from '../../utils/api';

const { Text } = Typography;

const ALERT_DARK_BASE_STYLE = {
  background: '#0f1419',
  border: '1px solid #2d3a4d',
};

export default function AttackerOob() {
  const [profileId, setProfileId] = useState(null);
  const [limit, setLimit] = useState(50);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState('');
  const [items, setItems] = useState([]);

  const refresh = async () => {
    setLoading(true);
    setErr('');
    try {
      const resp = await blindApi.recent(profileId || undefined, limit);
      const list = resp?.data?.data?.items || [];
      setItems(Array.isArray(list) ? list : []);
    } catch (e) {
      setErr(e?.response?.data?.message || e?.message || '拉取失败');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const t = window.setInterval(refresh, 1200);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profileId, limit]);

  const columns = useMemo(
    () => [
      {
        title: '时间',
        dataIndex: 'ts',
        key: 'ts',
        width: 170,
        render: (v) => (v ? new Date(Number(v)).toLocaleString() : '-'),
      },
      {
        title: 'profileId',
        dataIndex: 'profileId',
        key: 'profileId',
        width: 110,
        render: (v) => (v == null ? '-' : String(v)),
      },
      {
        title: 'kind',
        dataIndex: 'kind',
        key: 'kind',
        width: 120,
        render: (v) => <Tag color={v === 'poc' ? 'gold' : v === 'render' ? 'blue' : 'default'}>{v || '-'}</Tag>,
      },
      {
        title: 'view',
        dataIndex: 'view',
        key: 'view',
        width: 240,
        render: (v) => <Text style={{ color: '#8b9cb3' }}>{v || '-'}</Text>,
      },
      {
        title: 'payload',
        dataIndex: 'payload',
        key: 'payload',
        render: (v) => (
          <pre
            style={{
              margin: 0,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-word',
              color: '#e6edf3',
              background: 'transparent',
            }}
          >
            {v || ''}
          </pre>
        ),
      },
    ],
    []
  );

  return (
    <div>
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <Card title="攻击者控制台 · OOB 信号" bordered>
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="info"
                showIcon
                style={ALERT_DARK_BASE_STYLE}
                message={
                  <span style={{ color: '#e6edf3' }}>
                    这里模拟“攻击者接收端/日志面板”。你不需要进入目标后台页；只要目标后台执行了 payload 并回连到{' '}
                    <code style={{ color: '#38bdf8' }}>/api/v1/blind/beacon</code>，这里就能看到记录。
                  </span>
                }
              />

              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                <Text type="secondary">profileId（可选）</Text>
                <InputNumber
                  value={profileId}
                  min={1}
                  placeholder="留空=全部"
                  style={{ width: 200 }}
                  onChange={(v) => setProfileId(typeof v === 'number' ? v : null)}
                />
                <Text type="secondary">limit</Text>
                <InputNumber value={limit} min={1} max={100} style={{ width: 120 }} onChange={(v) => setLimit(typeof v === 'number' ? v : 50)} />
                <Button onClick={refresh} loading={loading}>
                  立即刷新
                </Button>
              </div>

              {err ? (
                <Alert
                  type="error"
                  showIcon
                  style={ALERT_DARK_BASE_STYLE}
                  message={<span style={{ color: '#e6edf3' }}>{err}</span>}
                />
              ) : null}

              <Table
                size="small"
                rowKey={(r) => r.id}
                columns={columns}
                dataSource={items}
                loading={loading}
                pagination={false}
              />
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

