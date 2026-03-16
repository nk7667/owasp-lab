import { Collapse, Typography, Tag, Space } from 'antd';

const { Paragraph, Text } = Typography;

function CodeLine({ children }) {
  return (
    <div style={{ marginBottom: 6 }}>
      <Text code style={{ fontFamily: 'JetBrains Mono, monospace' }}>
        {children}
      </Text>
    </div>
  );
}

export default function LabTips({ tips }) {
  if (!tips) return null;

  const items = [
    {
      key: 'principle',
      label: '原理',
      children: <Paragraph style={{ marginBottom: 0 }}>{tips.principle}</Paragraph>,
    },
    {
      key: 'exploit',
      label: '利用方式',
      children: (
        <div>
          {tips.exploit?.map((x, idx) => (
            <div key={idx} style={{ marginBottom: 12 }}>
              {x.title && (
                <Space wrap style={{ marginBottom: 6 }}>
                  <Tag color="geekblue">{x.title}</Tag>
                </Space>
              )}
              {x.desc && <Paragraph style={{ marginBottom: 8 }}>{x.desc}</Paragraph>}
              {(x.payloads || []).map((p) => (
                <CodeLine key={p}>{p}</CodeLine>
              ))}
            </div>
          ))}
        </div>
      ),
    },
    {
      key: 'bypass',
      label: '绕过方式（弱防护时）',
      children: (
        <div>
          <Paragraph style={{ marginBottom: 8 }}>{tips.bypassIntro}</Paragraph>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {(tips.bypass || []).map((item) => (
              <li key={item} style={{ color: '#8b9cb3', marginBottom: 6 }}>
                {item}
              </li>
            ))}
          </ul>
        </div>
      ),
    },
    {
      key: 'fix',
      label: '修复方式',
      children: (
        <ul style={{ margin: 0, paddingLeft: 18 }}>
          {(tips.fix || []).map((item) => (
            <li key={item} style={{ color: '#8b9cb3', marginBottom: 6 }}>
              {item}
            </li>
          ))}
        </ul>
      ),
    },
    tips.profile
      ? {
          key: 'profile',
          label: 'Profile / 方言提示',
          children: (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {(tips.profile || []).map((item) => (
                <li key={item} style={{ color: '#8b9cb3', marginBottom: 6 }}>
                  {item}
                </li>
              ))}
            </ul>
          ),
        }
      : null,
  ].filter(Boolean);

  return (
    <Collapse
      size="small"
      defaultActiveKey={[]}
      items={items}
      style={{
        marginTop: 12,
        marginBottom: 16,
        background: 'rgba(56, 189, 248, 0.04)',
        border: '1px solid #2d3a4d',
      }}
    />
  );
}

