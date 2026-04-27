import { Button, Card, Space, Typography } from 'antd';
import { GlobalOutlined, LinkOutlined, ReadOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';

const { Title, Paragraph, Text } = Typography;

export default function Ssrf() {
  const navigate = useNavigate();
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <GlobalOutlined /> SSRF 服务端请求伪造
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>选择一个关卡开始练习。</Paragraph>

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <Card
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
            borderRadius: 12,
          }}
        >
          <Space wrap size={10}>
            <Button type="primary" icon={<LinkOutlined />} onClick={() => navigate('/ssrf/fetch')}>
              URL 获取
            </Button>
            <Button icon={<ReadOutlined />} onClick={() => navigate('/ssrf/docs')}>
              说明（Markdown）
            </Button>
            <Text type="secondary">模式/载荷/绕过说明已移至文档页。</Text>
          </Space>
        </Card>
      </Space>
    </div>
  );
}

