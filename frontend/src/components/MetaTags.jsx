import { Space, Tag } from 'antd';

export default function MetaTags({ meta }) {
  if (!meta) return null;
  return (
    <Space wrap>
      <Tag color="blue">module: {meta.module}</Tag>
      <Tag color="purple">mode: {meta.mode}</Tag>
      <Tag color="cyan">signal: {meta.signalChannel}</Tag>
      <Tag color="geekblue">context: {meta.context}</Tag>
      <Tag>cwe: {meta.cwe}</Tag>
    </Space>
  );
}

