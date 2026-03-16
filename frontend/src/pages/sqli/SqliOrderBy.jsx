import { Form, Input, Button, Typography, Tag, Space, Table, Select } from 'antd';
import { BugOutlined, SafetyOutlined, PlayCircleOutlined, SortAscendingOutlined } from '@ant-design/icons';
import { sqliApi } from '../../utils/api';
import useRequestRunner from '../../hooks/useRequestRunner';
import ThreePanelLab from '../../components/ThreePanelLab';
import LabTips from '../../components/LabTips';
import { useMemo, useState } from 'react';
import MetaTags from '../../components/MetaTags';

const TIPS = {
  principle:
    "本关卡演示“可见范围边界（LIMIT 3）”被绕过的原因：当 ORDER BY 的列名/方向被直接拼接进 SQL，攻击者可能通过注释或语法拼接改变语句结构，进而影响 LIMIT 等后续片段，扩大可见数据范围。",
  exploit: [
    {
      title: '默认边界：只返回一页',
      desc: '不注入时，无论怎么排序，都应该最多返回 3 条（LIMIT 3）。',
      payloads: ['sortField: id', 'sortOrder: asc'],
    },
    {
      title: '结构探测：ORDER BY 列序号',
      desc: '在很多真实注入链路里，ORDER BY 也常用于“探测 SELECT 列数/列序号”。这里我们回显 4 列（id/username/email/role），所以 ORDER BY 1-4 应正常，ORDER BY 5 往往触发 error_based（用于教学对照）。',
      payloads: ['sortField: 1', 'sortField: 4', 'sortField: 5（观察是否 error_based）', 'sortOrder: asc'],
    },
    {
      title: '绕过 LIMIT（注释截断）',
      desc: '尝试用注释把后半段截断，让 LIMIT 失效（依赖数据库注释规则；H2 常见是 `-- ` 末尾有空格）。',
      payloads: ['sortField: id desc -- ', 'sortOrder: asc（可随意）'],
    },
    {
      title: '错误探测（error-based）',
      desc: '输入不存在的列名/非法语法，观察响应差异：我们会把错误兜底成统一结构，并标记 meta.signalChannel=error_based。',
      payloads: ['sortField: not_a_column', 'sortOrder: asc'],
    },
  ],
  bypassIntro:
    '如果有人用黑名单去挡（过滤 desc、-- 等），通常会被大小写/注释/空白变体绕过。ORDER BY 的正确做法是：列名/方向做白名单映射；LIMIT 固定在后端，不允许用户输入参与结构拼装。',
  bypass: [
    '关键字混淆：大小写变化、注释插入（如 d/**/esc）',
    '空白/换行变体：TAB/换行/多空格（绕过只过滤单空格的规则）',
    '把攻击面从 sortField 换到 sortOrder（或反之），绕过单点过滤',
  ],
  fix: [
    '列名白名单：不要试图用占位符绑定列名；应使用枚举值 → 后端映射到固定列名（SAFE 已实现）。',
    '方向白名单：仅允许 asc/desc；其他回退默认值。',
    '边界固定：LIMIT/分页大小由后端固定控制，不能被用户输入影响。',
    '错误处理：统一响应结构 + meta.signalChannel=error_based，用于教学对照（生产环境避免回显细节）。',
  ],
};

export default function SqliOrderBy() {
  const { loading, result, run } = useRequestRunner();
  const [mode, setMode] = useState('vuln'); // vuln | safe
  const [form] = Form.useForm();

  const modeUi = useMemo(() => {
    return mode === 'safe'
      ? {
          label: 'SAFE',
          icon: <SafetyOutlined style={{ color: '#34d399' }} />,
          tag: <Tag color="green">白名单映射</Tag>,
          buttonDanger: false,
          runType: 'safeOrderBy',
          submitIcon: <SortAscendingOutlined />,
          request: (sortField, sortOrder) => sqliApi.safeUsers(sortField || '1', sortOrder || 'asc'),
        }
      : {
          label: 'VULN',
          icon: <BugOutlined style={{ color: '#94a3b8' }} />,
          tag: <Tag color="volcano">ORDER BY 拼接</Tag>,
          buttonDanger: true,
          runType: 'vulnOrderBy',
          submitIcon: <PlayCircleOutlined />,
          request: (sortField, sortOrder) => sqliApi.vulnUsers(sortField || 'id', sortOrder || 'asc'),
        };
  }, [mode]);

  const raw = result?.data?.data;
  const listData = Array.isArray(raw) ? raw : Array.isArray(raw?.items) ? raw.items : [];
  const meta = result?.data?.meta;
  const listColumns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 72 },
    { title: '用户名', dataIndex: 'username', key: 'username' },
    { title: '邮箱', dataIndex: 'email', key: 'email' },
    { title: '角色', dataIndex: 'role', key: 'role', width: 90 },
  ];

  return (
    <ThreePanelLab
      title="SQL 注入 · ORDER BY 排序"
      subtitle="关卡：order_by_limit（inband / error_based）。默认只显示一个请求面板，通过下拉切换 VULN/SAFE。"
      bottomExtra={<LabTips tips={TIPS} />}
      hideSafe
      hideResponse
      vuln={{
        title: (
          <Space>
            {modeUi.icon}
            <span style={{ color: '#e6edf3' }}>{modeUi.label}</span>
          </Space>
        ),
        extra: (
          <Space wrap>
            <Select
              size="small"
              value={mode}
              onChange={(v) => {
                setMode(v);
                const curField = form.getFieldValue('sortField');
                const curOrder = form.getFieldValue('sortOrder');
                if (v === 'safe') {
                  form.setFieldsValue({
                    sortField: ['1', '2', '3', '4'].includes(String(curField)) ? String(curField) : '1',
                    sortOrder: String(curOrder || 'asc').toLowerCase() === 'desc' ? 'desc' : 'asc',
                  });
                } else {
                  form.setFieldsValue({
                    sortField: curField ? String(curField) : 'id',
                    sortOrder: curOrder ? String(curOrder) : 'asc',
                  });
                }
              }}
              options={[
                { value: 'vuln', label: 'VULN' },
                { value: 'safe', label: 'SAFE' },
              ]}
              style={{ width: 110 }}
            />
            {modeUi.tag}
            <MetaTags meta={meta} />
          </Space>
        ),
        children: (
          <Form
            form={form}
            layout="vertical"
            initialValues={{ sortField: 'id', sortOrder: 'asc' }}
            onFinish={(v) => run(modeUi.runType, () => modeUi.request(v.sortField, v.sortOrder))}
          >
            <Form.Item name="sortField" label="排序字段">
              {mode === 'safe' ? (
                <Select
                  options={[
                    { value: '1', label: '1 → id' },
                    { value: '2', label: '2 → username' },
                    { value: '3', label: '3 → email' },
                    { value: '4', label: '4 → role' },
                  ]}
                />
              ) : (
                <Input placeholder="id / username / email / role / 1-4（或注入，尝试绕过 LIMIT / 探测列序号）" />
              )}
            </Form.Item>
            <Form.Item name="sortOrder" label="排序方向">
              {mode === 'safe' ? (
                <Select
                  options={[
                    { value: 'asc', label: 'asc' },
                    { value: 'desc', label: 'desc' },
                  ]}
                />
              ) : (
                <Input placeholder="asc / desc" />
              )}
            </Form.Item>
            <Form.Item>
              <Button
                type="primary"
                danger={modeUi.buttonDanger}
                htmlType="submit"
                loading={loading}
                icon={modeUi.submitIcon}
              >
                获取列表
              </Button>
            </Form.Item>

            {/* 更贴近真实：列表结果在“请求区”直接展示 */}
            {listData.length > 0 && (
              <Table
                className="compact-table"
                dataSource={listData}
                columns={listColumns}
                rowKey="id"
                size="small"
                pagination={false}
                scroll={{ x: 'max-content' }}
                style={{ marginTop: 8 }}
              />
            )}
          </Form>
        ),
      }}
      safe={{ title: null, extra: null, children: null }}
      result={result}
    />
  );
}

