import { Alert, Card, Col, Row, Space, Tag, Typography, Collapse } from 'antd';
import MetaTags from './MetaTags';

const { Title, Text } = Typography;

export default function ThreePanelLab({
  title,
  subtitle,
  topExtra,
  bottomExtra,
  vuln,
  safe,
  hideSafe,
  hideResponse,
  result,
  responseExtra,
}) {
  const debug = result?.data?.data?.debug;
  const lockInfo =
    debug &&
    (Object.prototype.hasOwnProperty.call(debug, 'locked') ||
      Object.prototype.hasOwnProperty.call(debug, 'retryAfterSeconds') ||
      Object.prototype.hasOwnProperty.call(debug, 'failCount'))
      ? {
          locked: Boolean(debug.locked),
          retryAfterSeconds:
            debug.retryAfterSeconds === 0 || debug.retryAfterSeconds ? Number(debug.retryAfterSeconds) : undefined,
          failCount: debug.failCount === 0 || debug.failCount ? Number(debug.failCount) : undefined,
        }
      : null;

  return (
    <div style={{ maxWidth: 1440, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 4 }}>
        {title}
      </Title>
      {subtitle && (
        <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
          {subtitle}
        </Text>
      )}
      {topExtra}

      <Row gutter={16} align="stretch">
        <Col
          xs={24}
          lg={hideResponse ? (hideSafe ? 24 : 12) : hideSafe ? 12 : 8}
          style={{ display: 'flex' }}
        >
          <Card
            title={vuln.title}
            extra={vuln.extra}
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            {vuln.children}
          </Card>
        </Col>

        {!hideSafe && (
          <Col xs={24} lg={hideResponse ? 12 : 8} style={{ display: 'flex' }}>
            <Card
              title={safe.title}
              extra={safe.extra}
              style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
            >
              {safe.children}
            </Card>
          </Col>
        )}

        {!hideResponse && (
          <Col xs={24} lg={hideSafe ? 12 : 8} style={{ display: 'flex' }}>
            <Card
              title={
                <Space>
                  <span style={{ color: '#e6edf3' }}>响应</span>
                  <Tag color={result?.success ? 'green' : 'volcano'}>
                    {result ? (result.success ? '成功' : '失败') : '待请求'}
                  </Tag>
                </Space>
              }
              style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
            >
              <div style={{ marginBottom: 12 }}>
                <MetaTags meta={result?.data?.meta} />
              </div>
              {lockInfo && (
                <Alert
                  type={lockInfo.locked ? 'error' : 'info'}
                  showIcon
                  title={
                    <Space wrap>
                      <span>Debug 信号</span>
                      {lockInfo.locked && <Tag color="volcano">LOCKED</Tag>}
                      {typeof lockInfo.failCount === 'number' && <Tag>failCount: {lockInfo.failCount}</Tag>}
                      {typeof lockInfo.retryAfterSeconds === 'number' && (
                        <Tag>retryAfterSeconds: {lockInfo.retryAfterSeconds}</Tag>
                      )}
                    </Space>
                  }
                  style={{
                    marginBottom: 12,
                    background: 'rgba(56, 189, 248, 0.06)',
                    border: '1px solid #2d3a4d',
                  }}
                />
              )}
              {responseExtra}
              <Collapse
                size="small"
                defaultActiveKey={[]}
                items={[
                  {
                    key: 'raw',
                    label: '原始响应（JSON）',
                    children: (
                      <pre
                        className="nice-scrollbar"
                        style={{ margin: 0, padding: 16, maxHeight: 420, overflow: 'auto' }}
                      >
                        {JSON.stringify(result?.data ?? { tip: '提交 VULN 或 SAFE 表单后在这里查看响应' }, null, 2)}
                      </pre>
                    ),
                  },
                ]}
                style={{
                  background: 'rgba(56, 189, 248, 0.04)',
                  border: '1px solid #2d3a4d',
                }}
              />
            </Card>
          </Col>
        )}
      </Row>

      {bottomExtra}
    </div>
  );
}

