import { Select } from 'antd';

const { Option } = Select;

export default function DarkSelect({ options, ...props }) {
  return (
    <Select
      className="dark-select"
      options={options}
      classNames={{
        popup: 'dark-select-popup',
      }}
      styles={{
        popup: {
          backgroundColor: '#0f1419',
          borderColor: '#2d3a4d',
        },
      }}
      style={{
        color: '#e6edf3',
        backgroundColor: '#0f1419',
        borderColor: '#2d3a4d',
        ...props.style
      }}
      {...props}
    />
  );
}
