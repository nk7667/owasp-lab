import { useState } from 'react';
import { Alert, Button, Card, Collapse, Input, Space, Typography } from 'antd';

const { Title, Paragraph, Text } = Typography;

const JSONP_BASE = 'http://127.0.0.1:8081/api/v1/jsonp';

export default function JsonpLab() {
  const [mode, setMode] = useState('vuln'); // 'vuln' | 'safe'
  const [victimResult, setVictimResult] = useState('');
  const [callbackForXss, setCallbackForXss] = useState('handleUser');

  const isVuln = mode === 'vuln';
  const victimUrl = `${JSONP_BASE}/${isVuln ? 'userinfo-vuln' : 'userinfo-safe'}`;

  return (
    <div style={{ maxWidth: 960, width: '100%', margin: '0 auto' }}>
      <Title level={2} style={{ color: '#e6edf3', fontWeight: 600, marginBottom: 8 }}>
        JSONP · 跨域数据泄露实验
      </Title>
      <Paragraph style={{ color: '#8b9cb3', fontSize: 15, marginBottom: 16 }}>
        这个靶场用一个简单的 JSONP API 来对比
        <Text strong style={{ color: '#e6edf3' }}> VULN（敏感数据 + 任意站点可调用） </Text>
        和
        <Text strong style={{ color: '#e6edf3' }}> SAFE（只返回公开数据 / 或使用 CORS 替代 JSONP） </Text>
        的差异，攻击脚本需自行搭建。
      </Paragraph>

      <Alert
        type={isVuln ? 'error' : 'success'}
        showIcon
        style={{ marginBottom: 16, background: '#0f1419', border: '1px solid #2d3a4d' }}
        title={
          <Space wrap>
            <span style={{ color: '#e6edf3' }}>
              当前接口：
              <Text strong type={isVuln ? 'danger' : 'success'}>
                {isVuln ? ' VULN（敏感 JSONP）' : ' SAFE（仅公开数据）'}
              </Text>
            </span>
            <Button type={isVuln ? 'primary' : 'default'} size="small" onClick={() => setMode('vuln')}>
              VULN
            </Button>
            <Button type={!isVuln ? 'primary' : 'default'} size="small" onClick={() => setMode('safe')}>
              SAFE
            </Button>
          </Space>
        }
        description={
          <span style={{ color: '#94a3b8' }}>
            {isVuln
              ? '任意站点可通过 script 跨域窃取登录用户数据。'
              : '敏感接口已禁用 JSONP 或仅返回公开数据。'}
          </span>
        }
      />

      {/* 真实场景：仿论坛帖子，内含恶意诱导链接 */}
      <Card
        variant="outlined"
        style={{ width: '100%', marginBottom: 16 }}
        title={
          <Space>
            <span style={{ color: '#8b9cb3', fontSize: 13 }}>模拟 · 受害者看到的论坛/消息（攻击者发的帖子）</span>
          </Space>
        }
        styles={{ body: { paddingTop: 12 } }}
      >
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 16 }}>
          <div
            style={{
              width: 40,
              height: 40,
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #64748b 0%, #475569 100%)',
              flexShrink: 0,
            }}
          />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ marginBottom: 4 }}>
              <Text strong style={{ color: '#e6edf3', marginRight: 8 }}>活动小助手</Text>
              <Text type="secondary" style={{ fontSize: 12 }}>2 分钟前</Text>
            </div>
            <div style={{ color: '#94a3b8', fontSize: 14, lineHeight: 1.6 }}>
              【周年庆】恭喜您获得一次抽奖资格，点击下方链接即可领取奖励，仅限今日有效。
              <br />
              <a
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  setVictimResult('');
                  const cbName = 'handleUser';
                  window[cbName] = (data) => {
                    try {
                      setVictimResult(JSON.stringify(data, null, 2));
                    } catch (err) {
                      setVictimResult(String(err || '解析失败'));
                    }
                  };
                  const s = document.createElement('script');
                  s.src = `${victimUrl}?callback=${encodeURIComponent(cbName)}`;
                  s.onerror = () => setVictimResult('请求失败，请检查后端是否已启动。');
                  document.body.appendChild(s);
                }}
                style={{ color: '#38bdf8', textDecoration: 'underline', cursor: 'pointer' }}
              >
                https://activity.example.com/claim?ref=anniversary2024
              </a>
            </div>
          </div>
        </div>
      </Card>

      {/* 窃取结果展示 */}
      <Card variant="outlined" style={{ width: '100%' }}>
        <Collapse
          size="small"
          items={[
            {
              key: 'hint',
              label: <span style={{ color: '#94a3b8', fontSize: 13 }}>操作说明与清空（折叠）</span>,
              children: (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <Text type="secondary" style={{ fontSize: 13 }}>
                    尚未点击链接，或请求失败时，可先登录 Victim 站再点击上方「活动链接」模拟受害者行为。
                  </Text>
                  <Text type="secondary" style={{ fontSize: 13 }}>
                    若返回 <code style={{ background: '#1e293b', padding: '2px 6px', borderRadius: 4 }}>{'{"error": "not_logged_in"}'}</code> 表示未登录，请先登录 Victim 站。
                  </Text>
                  {victimResult ? (
                    <Button type="default" size="small" style={{ alignSelf: 'flex-start' }} onClick={() => setVictimResult('')}>
                      清空
                    </Button>
                  ) : null}
                </div>
              ),
            },
          ]}
          style={{ marginBottom: victimResult ? 12 : 0 }}
        />
        {victimResult ? (
          <pre
            style={{
              margin: 0,
              maxHeight: 260,
              overflow: 'auto',
              background: '#020617',
              borderRadius: 8,
              padding: 12,
              fontSize: 12,
              color: '#e5e7eb',
              border: '1px solid #1f2933',
            }}
          >
            {victimResult}
          </pre>
        ) : null}
      </Card>

      {/* Callback XSS · 站内调试区 */}
      <Card
        variant="outlined"
        style={{ width: '100%', marginTop: 16 }}
        title={
          <Space>
            <span style={{ color: '#8b9cb3', fontSize: 13 }}>Callback XSS（在 Victim 页面原地加载 JSONP）</span>
          </Space>
        }
      >
        <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <Text type="secondary" style={{ fontSize: 13 }}>
            下面的区域模拟开发者在 Victim 页面中，直接拼接 callback 参数并加载 JSONP 接口的错误做法。
            当 callback 不受限制时，可能被构造为 <code>alert(1)//</code> 之类的恶意脚本。
          </Text>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: '#94a3b8', fontSize: 13 }}>callback 参数值：</span>
            <Input
              style={{ maxWidth: 260 }}
              value={callbackForXss}
              onChange={(e) => setCallbackForXss(e.target.value)}
              placeholder="例如：handleUser 或 alert(1)//"
              size="small"
            />
            <Button
              type="primary"
              size="small"
              onClick={() => {
                const cb = (callbackForXss || '').trim();
                if (!cb) return;
                // 漏洞点演示：未对 callback 做任何白名单/正则校验，直接拼接到 JSONP URL 中。
                const s = document.createElement('script');
                s.src = `${victimUrl}?callback=${encodeURIComponent(cb)}`;
                document.body.appendChild(s);
              }}
            >
              在当前 Victim 页面加载 JSONP
            </Button>
          </div>
          <Text type="secondary" style={{ fontSize: 12 }}>
            提示：当 callback 为 <code>alert(1)//</code> 且后端存在
            <code style={{ marginLeft: 4 }}>return callback.trim() + "(" + json + ");</code> 这类逻辑时，将在 Victim
            域名下直接执行 <code>alert(1)</code>。
          </Text>
        </div>
      </Card>
    </div>
  );
}

