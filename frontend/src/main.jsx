import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import App from './App';
import './index.css';

const theme = {
  token: {
    colorPrimary: '#0ea5e9',
    colorBgContainer: '#161f2e',
    colorBgElevated: '#1a2332',
    colorBorder: '#2d3a4d',
    colorText: '#e6edf3',
    colorTextSecondary: '#8b9cb3',
    borderRadius: 8,
    fontFamily: "'Inter', system-ui, sans-serif",
  },
  components: {
    Card: {
      colorBorderSecondary: '#2d3a4d',
    },
    Menu: {
      itemSelectedBg: 'rgba(56, 189, 248, 0.08)',
      itemSelectedColor: '#38bdf8',
    },
  },
};

ReactDOM.createRoot(document.getElementById('root')).render(
  <ConfigProvider locale={zhCN} theme={theme}>
    <App />
  </ConfigProvider>
);
