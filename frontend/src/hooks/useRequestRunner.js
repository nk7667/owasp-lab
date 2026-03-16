import { useCallback, useState } from 'react';

/**
 * 统一请求执行与结果收集：页面只需要 run(type, fn)。
 * result 结构：{ type, success, data }
 */
export default function useRequestRunner() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  const run = useCallback(async (type, fn) => {
    setLoading(true);
    setResult(null);
    try {
      const res = await fn();
      setResult({ type, success: true, data: res.data });
    } catch (e) {
      setResult({ type, success: false, data: e.response?.data ?? { error: e.message } });
    } finally {
      setLoading(false);
    }
  }, []);

  return { loading, result, run, setResult };
}

