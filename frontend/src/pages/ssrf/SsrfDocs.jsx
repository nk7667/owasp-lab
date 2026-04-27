import { Card, Space, Typography } from 'antd';
import { GlobalOutlined } from '@ant-design/icons';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import ssrfDoc from '../../docs/ssrf.md?raw';

const { Title } = Typography;

export default function SsrfDocs() {
  return (
    <div style={{ maxWidth: 1100, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 12 }}>
        <GlobalOutlined /> SSRF 说明
      </Title>

      <Card style={{ background: '#161f2e', border: '1px solid #2d3a4d', borderRadius: 12 }}>
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <div
            className="coach-markdown nice-scrollbar"
            style={{
              padding: 16,
              background: '#0d1117',
              border: '1px solid #2d3a4d',
              borderRadius: 10,
              overflow: 'auto',
              color: '#8b9cb3',
            }}
          >
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{ssrfDoc}</ReactMarkdown>
          </div>
        </Space>
      </Card>
    </div>
  );
}

