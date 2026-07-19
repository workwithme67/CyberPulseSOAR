import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/dashboard': 'http://localhost:8000',
      '/alerts': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
      '/playbooks': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
    },
  },
});
