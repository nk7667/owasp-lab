import { BrowserRouter, Routes, Route, useNavigate, useLocation, Navigate } from 'react-router-dom';
import { Layout, Menu, Typography } from 'antd';
import {
  HomeOutlined,
  DatabaseOutlined,
  LoginOutlined,
  SortAscendingOutlined,
  UserOutlined,
  RobotOutlined,
  CodeOutlined,
  BugOutlined,
  ThunderboltOutlined,
  GlobalOutlined,
} from '@ant-design/icons';
import { useEffect, useMemo, useState } from 'react';
import Home from './pages/Home';
import SqliLoginBypass from './pages/sqli/SqliLoginBypass';
import SqliOrderBy from './pages/sqli/SqliOrderBy';
import SqliUserDetail from './pages/sqli/SqliUserDetail';
import SqliNewsUnion from './pages/sqli/SqliNewsUnion';
import SqliNewsBlind from './pages/sqli/SqliNewsBlind';
import Coach from './pages/Coach';
import XssIntro from './pages/xss/XssIntro';
import XssReflected from './pages/xss/XssReflected';
import XssStored from './pages/xss/XssStored';
import XssDom from './pages/xss/XssDom';
import XssStoredProfileSubmit from './pages/xss/XssStoredProfileSubmit';
import XssStoredProfileAdmin from './pages/xss/XssStoredProfileAdmin';
import AttackerOob from './pages/attacker/AttackerOob';
import CsrfLow from './pages/csrf/CsrfLow';
import CsrfHigh from './pages/csrf/CsrfHigh';
import CsrfEvilLow from './pages/csrf/CsrfEvilLow';
import CommandExecution from './pages/CommandExecution';
import CommandExecutionFile from './pages/commandexecution/CommandExecutionFile';
import CommandExecutionNetwork from './pages/commandexecution/CommandExecutionNetwork';
import Ssrf from './pages/Ssrf';
import SsrfFetch from './pages/ssrf/SsrfFetch';
import JsonpLab from './pages/jsonp/JsonpLab';
import XxeLab from './pages/xxe/XxeLab';

const { Header, Content, Sider } = Layout;
const { Text } = Typography;

function AppContent() {
  const navigate = useNavigate();
  const location = useLocation();
  const isCoach = location.pathname === '/coach';

  const selectedKeys = useMemo(() => {
    const p = location.pathname;
    if (p === '/sqli') return ['/sqli/login'];
    if (p === '/xss') return ['/xss/intro'];
    return [p];
  }, [location.pathname]);

  const derivedOpenKeys = useMemo(() => {
    const p = location.pathname;
    if (p.startsWith('/sqli')) return ['sqli'];
    if (p.startsWith('/xss')) return ['xss'];
    if (p.startsWith('/csrf')) return ['csrf'];
    if (p.startsWith('/command-execution')) return ['command-execution'];
    if (p.startsWith('/ssrf')) return ['ssrf'];
    if (p.startsWith('/jsonp')) return ['jsonp'];
    if (p.startsWith('/xxe')) return ['xxe'];
    return [];
  }, [location.pathname]);

  const [openKeys, setOpenKeys] = useState(derivedOpenKeys);
  useEffect(() => {
    setOpenKeys(derivedOpenKeys);
  }, [derivedOpenKeys]);

  const menuItems = useMemo(
    () => [
      { key: '/', icon: <HomeOutlined />, label: '首页' },
      {
        key: 'sqli',
        icon: <DatabaseOutlined />,
        label: 'SQL 注入',
        children: [
          { key: '/sqli/login', icon: <LoginOutlined />, label: '登录绕过' },
          { key: '/sqli/order-by', icon: <SortAscendingOutlined />, label: 'ORDER BY 排序' },
          { key: '/sqli/user-detail', icon: <UserOutlined />, label: '用户详情（ID）' },
          { key: '/sqli/news-union', icon: <DatabaseOutlined />, label: '新闻搜索（回显）' },
          { key: '/sqli/news-blind', icon: <DatabaseOutlined />, label: '新闻搜索（盲注）' },
        ],
      },
      {
        key: 'xss',
        icon: <CodeOutlined />,
        label: 'XSS',
        children: [
          { key: '/xss/intro', label: '概览' },
          { key: '/xss/reflected', label: '反射型' },
          { key: '/xss/stored', label: '存储型' },
          { key: '/xss/stored-profile-submit', label: '盲打 · Profile（提交）' },
          { key: '/xss/stored-profile-admin', label: '盲打 · Profile（后台）' },
          { key: '/xss/dom', label: 'DOM 型' },
        ],
      },
      {
        key: 'csrf',
        icon: <BugOutlined />,
        label: 'CSRF',
        children: [
          { key: '/csrf/low', label: '基础 · Low（无防护 GET）' },
          { key: '/csrf/high', label: '进阶 · High（token + XSS）' },
          { key: '/csrf/evil', label: 'Evil 页面示例（Low）' },
        ],
      },
      {
        key: 'command-execution',
        icon: <ThunderboltOutlined />,
        label: '命令注入',
        children: [
          { key: '/command-execution', label: '概览' },
          { key: '/command-execution/network', label: '网络诊断' },
          { key: '/command-execution/file', label: '文件操作' },
        ],
      },
      {
        key: 'ssrf',
        icon: <GlobalOutlined />,
        label: 'SSRF 服务端请求伪造',
        children: [
          { key: '/ssrf', label: '概览' },
          { key: '/ssrf/fetch', label: 'URL 获取' },
        ],
      },
      {
        key: 'jsonp',
        icon: <CodeOutlined />,
        label: 'JSONP',
        children: [{ key: '/jsonp', label: 'JSONP 跨域数据泄露' }],
      },
      {
        key: 'xxe',
        icon: <CodeOutlined />,
        label: 'XXE XML 外部实体',
        children: [{ key: '/xxe', label: 'XXE 实验' }],
      },
      { key: '/coach', icon: <RobotOutlined />, label: 'AI Coach' },
      { key: '/attacker/oob', icon: <BugOutlined />, label: '攻击者控制台（OOB）' },
    ],
    []
  );
  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          height: 56,
        }}
      >
        <span
          style={{
            width: 32,
            height: 32,
            borderRadius: 8,
            background: 'linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%)',
            flexShrink: 0,
          }}
        />
        <Text strong style={{ color: '#e6edf3', fontSize: 16, letterSpacing: '-0.02em' }}>
          OWASP Lab
        </Text>
      </Header>
      <Layout>
        <Sider width={232} style={{ background: 'transparent' }}>
          <Menu
            mode="inline"
            selectedKeys={selectedKeys}
            openKeys={openKeys}
            onOpenChange={(keys) => setOpenKeys(keys)}
            style={{ borderRight: 0, marginTop: 16, paddingInline: 12 }}
            items={menuItems}
            onClick={({ key }) => {
              if (typeof key === 'string' && key.startsWith('/')) navigate(key);
            }}
          />
        </Sider>
        <Layout style={{ padding: isCoach ? 12 : 24 }}>
          <Content
            style={{
              padding: isCoach ? 12 : 24,
              minHeight: 360,
              background: '#0f1419',
            }}
          >
            <div style={{ maxWidth: 1560, width: '100%', margin: '0 auto' }}>
              <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/sqli" element={<Navigate to="/sqli/login" replace />} />
                <Route path="/sqli/login" element={<SqliLoginBypass />} />
                <Route path="/sqli/order-by" element={<SqliOrderBy />} />
                <Route path="/sqli/user-detail" element={<SqliUserDetail />} />
                <Route path="/sqli/news-union" element={<SqliNewsUnion />} />
                <Route path="/sqli/news-blind" element={<SqliNewsBlind />} />

                <Route path="/xss" element={<Navigate to="/xss/intro" replace />} />
                <Route path="/xss/intro" element={<XssIntro />} />
                <Route path="/xss/reflected" element={<XssReflected />} />
                <Route path="/xss/stored" element={<XssStored />} />
                <Route path="/xss/stored-profile-submit" element={<XssStoredProfileSubmit />} />
                <Route path="/xss/stored-profile-admin" element={<XssStoredProfileAdmin />} />
                <Route path="/xss/dom" element={<XssDom />} />

                <Route path="/csrf/low" element={<CsrfLow />} />
                <Route path="/csrf/high" element={<CsrfHigh />} />
                <Route path="/csrf/evil" element={<CsrfEvilLow />} />

                <Route path="/command-execution" element={<CommandExecution />} />
                <Route path="/command-execution/network" element={<CommandExecutionNetwork />} />
                <Route path="/command-execution/file" element={<CommandExecutionFile />} />

                <Route path="/ssrf" element={<Ssrf />} />
                <Route path="/ssrf/fetch" element={<SsrfFetch />} />

                <Route path="/jsonp" element={<JsonpLab />} />
                <Route path="/xxe" element={<XxeLab />} />

                <Route path="/coach" element={<Coach />} />
                <Route path="/attacker/oob" element={<AttackerOob />} />
              </Routes>
            </div>
          </Content>
        </Layout>
      </Layout>
    </Layout>
  );
}

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <AppContent />
    </BrowserRouter>
  );
}
