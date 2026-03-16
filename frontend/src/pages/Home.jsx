import { Link } from 'react-router-dom';
import { Typography, Card, Button, Space } from 'antd';
import { ArrowRightOutlined, SafetyCertificateOutlined } from '@ant-design/icons';

const { Title, Paragraph } = Typography;

export default function Home() {
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        漏洞练习靶场
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 10 }}>
        面向 SDL 的练习环境，支持 SAST / DAST 场景对照：同一业务目标下提供 VULN / SAFE 两种实现，用于对比“漏洞成因 → 可观测信号 → 修复思路”。
      </Paragraph>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 28 }}>
        你可以在每个模块的响应中看到结构化 meta（module/mode/signalChannel/context），并在提示面板里查看原理、利用、绕过与修复要点。
      </Paragraph>
      <Card
        style={{
          background: '#161f2e',
          border: '1px solid #2d3a4d',
          borderRadius: 12,
        }}
      >
        <Space orientation="vertical" size={16} style={{ width: '100%' }}>
          <Space align="center">
            <SafetyCertificateOutlined style={{ fontSize: 20, color: '#38bdf8' }} />
            <Title level={5} style={{ color: '#e6edf3', margin: 0 }}>
              可用模块
            </Title>
          </Space>
          <Link to="/sqli/login">
            <Button type="primary" icon={<ArrowRightOutlined />} size="middle">
              SQL 注入
            </Button>
          </Link>
        </Space>
      </Card>
    </div>
  );
}
