import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: ['www.nk7667.site'],
    proxy: {
      '/api': { target: 'http://localhost:8082', changeOrigin: true },
    },
  },
});
