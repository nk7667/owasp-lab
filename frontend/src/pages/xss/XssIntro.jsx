import { Card, Space, Tag, Typography } from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const FIX_CHEATSHEET = [
  {
    k: 'HTML（innerHTML）',
    v: '白名单 sanitize + 安全挂载，不用 innerHTML。',
  },
  {
    k: 'Attr（href/属性）',
    v: '严格属性转义 + 协议白名单（DOM API setAttribute）。',
  },
  {
    k: 'JS（jsString/JSON）',
    v: '字符串转义或 JSON.stringify；数据放到 data-* 或 application/json 再解析。',
  },
  {
    k: 'JSONP（callback）',
    v: '回调名严格白名单（仅标识符/命名空间），禁止括号/索引/运算；能弃用则弃用。',
  },
  {
    k: 'DOM/消息（postMessage）',
    v: 'origin + source + 类型校验，写入用 textContent。',
  },
  {
    k: 'SVG/命名空间',
    v: '禁用或白名单子集；清洗库需开启 SVG 严格模式。',
  },
];

export default function XssIntro() {
  return (
    <div style={{ maxWidth: 1200, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        XSS（跨站脚本）
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        第二章将按「反射型 / 存储型 / DOM」三类拆解 XSS：同一业务目标下提供 VULN / SAFE 两种实现，对比漏洞成因、可观测信号与修复思路。
      </Paragraph>

      <Space direction="vertical" size={14} style={{ width: '100%' }}>
        <Card
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
            borderRadius: 12,
          }}
        >
          <Space direction="vertical" size={14} style={{ width: '100%' }}>
            <Space align="center">
              <SafetyCertificateOutlined style={{ fontSize: 20, color: '#38bdf8' }} />
              <Text strong style={{ color: '#e6edf3' }}>
                关卡规划
              </Text>
            </Space>
            <div>
              <Tag color="geekblue">反射型 XSS</Tag>
              <Tag color="geekblue">存储型 XSS</Tag>
              <Tag color="geekblue">DOM XSS</Tag>
            </div>
            <Text type="secondary" style={{ fontSize: 12 }}>
              建议学习顺序：先练单一落点（HTML / Attr / JS），再练 DOM/策略链路，最后回到混合流做综合对照。
            </Text>
          </Space>
        </Card>

        <Card
          title={<span style={{ color: '#e6edf3' }}>修复</span>}
          style={{
            background: '#161f2e',
            border: '1px solid #2d3a4d',
            borderRadius: 12,
          }}
        >
          <div
            style={{
              padding: '10px 12px',
              borderRadius: 10,
              border: '1px solid rgba(45,58,77,.8)',
              background: '#0b1020',
              color: '#c6d3e5',
              fontSize: 13,
              lineHeight: 1.6,
            }}
          >
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {FIX_CHEATSHEET.map((x) => (
                <li key={x.k} style={{ margin: '6px 0' }}>
                  <span style={{ color: '#e6edf3', fontWeight: 600 }}>{x.k}</span>
                  <span style={{ color: '#8b9cb3' }}>：</span>
                  <span>{x.v}</span>
                </li>
              ))}
            </ul>
          </div>
        </Card>
      </Space>
    </div>
  );
}

