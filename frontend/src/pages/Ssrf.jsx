import { Card, Space, Tag, Typography } from 'antd';
import { GlobalOutlined, SafetyCertificateOutlined } from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const FIX_CHEATSHEET = [
  {
    k: 'VULN（原始漏洞）',
    v: '完全不校验 URL，服务器会对任意用户输入的地址发起请求，可访问内网、本机、file://、模拟云元数据等。',
  },
  {
    k: 'WEAK-1（只拦 localhost/127.0.0.1）',
    v: '在字符串级别拦截 localhost / 127.0.0.1，但没有考虑十进制 IP、短写 127.1、DNS 重绑定等高级绕过。',
  },
  {
    k: 'WEAK-2（增加 IP 黑名单）',
    v: '在 WEAK-1 基础上，对解析出的 IP 做 127.x / 10.x / 192.168.x / 172.16–31 / 169.254.x 黑名单，但未处理重定向和云元数据等特殊端点。',
  },
  {
    k: 'WEAK-3（只允许 http/https）',
    v: '限制协议为 http/https，阻止 file:// 等，但如果没有配合 IP/域名校验，仍然可以 SSRF 内网 HTTP 服务。',
  },
  {
    k: 'WEAK-4/5（组合型错误修复）',
    v: '叠加多种黑名单和字符串过滤，但仍然依赖字符串匹配而非“先解析再校验”，容易被编码/重定向/非常规主机名绕过。',
  },
  {
    k: 'SAFE（正确修复）',
    v: '只允许访问少量业务需要的外部域名（白名单），并在 DNS 解析后对结果 IP 做黑名单校验，禁止访问内网/本机/元数据等敏感地址。',
  },
];

export default function Ssrf() {
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <GlobalOutlined /> SSRF 服务端请求伪造
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        SSRF（Server-Side Request Forgery）是一类“让服务器替你发请求”的漏洞。
        攻击者控制服务器发起到任意 URL 的请求，可以用来访问内网 HTTP 服务、敏感管理接口，甚至云环境的元数据服务。
        本靶场用 VULN / WEAK / SAFE 三种模式对比不同修复策略，以及 IP 编码、重定向等高级绕过手法。
      </Paragraph>

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <Card
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
            borderRadius: 12,
          }}
        >
          <Title level={4} style={{ color: '#e6edf3', marginBottom: 12 }}>
            <SafetyCertificateOutlined /> 修复与演练指南
          </Title>
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            {FIX_CHEATSHEET.map((item) => (
              <div key={item.k} style={{ display: 'flex', alignItems: 'flex-start' }}>
                <Tag
                  color={
                    item.k.includes('SAFE')
                      ? 'green'
                      : item.k.startsWith('VULN')
                      ? 'red'
                      : 'orange'
                  }
                  style={{ minWidth: 160, marginRight: 12, marginTop: 2 }}
                >
                  {item.k}
                </Tag>
                <Text style={{ color: '#8b9cb3', fontSize: 14, lineHeight: 1.5 }}>
                  {item.v}
                </Text>
              </div>
            ))}
          </Space>
        </Card>
      </Space>
    </div>
  );
}

