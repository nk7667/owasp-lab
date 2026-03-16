import { Card, Space, Tag, Typography } from 'antd';
import { SafetyCertificateOutlined, CodeOutlined } from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const FIX_CHEATSHEET = [
  {
    k: 'VULN（原始漏洞）',
    v: '直接拼接用户输入到命令中，无任何防护。',
  },
  {
    k: 'WEAK-1（基础拦截）',
    v: '拦截分号、逻辑与、管道符等基础分隔符。',
  },
  {
    k: 'WEAK-2（增强拦截）',
    v: '增加拦截反引号、$()、换行符等高级分隔符。',
  },
  {
    k: 'WEAK-3（空格过滤）',
    v: '拦截空格并将其替换为空字符。',
  },
  {
    k: 'WEAK-4（关键字拦截）',
    v: '拦截斜杠、cat、passwd等敏感关键字。',
  },
  {
    k: 'WEAK-5（编码拦截）',
    v: '拦截 cat、passwd 等关键字，需要自解码绕过。',
  },
  {
    k: 'SAFE（正确修复）',
    v: '参数化执行，只允许字母、数字、点、冒号、连字符。',
  },
];

export default function CommandExecution() {
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <CodeOutlined /> 命令注入（Command Injection）
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        命令注入是一种安全漏洞，允许攻击者在服务器上执行任意系统命令。
        本靶场按「网络诊断 / 文件操作」两类拆解命令注入：同一业务目标下提供 VULN / WEAK / SAFE 三种实现，对比漏洞成因、WAF 绕过与修复思路。
      </Paragraph>

      <Space orientation="vertical" size={14} style={{ width: '100%' }}>
        <Card
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
            borderRadius: 12,
          }}
        >
          <Title level={4} style={{ color: '#e6edf3', marginBottom: 12 }}>
            <SafetyCertificateOutlined /> 修复指南
          </Title>
          <Space orientation="vertical" size={8} style={{ width: '100%' }}>
            {FIX_CHEATSHEET.map((item, index) => (
              <div key={index} style={{ display: 'flex', alignItems: 'flex-start' }}>
                <Tag
                  color={item.k.includes('SAFE') ? 'green' : item.k.includes('WEAK') ? 'orange' : 'red'}
                  style={{ minWidth: 120, marginRight: 12, marginTop: 2 }}
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