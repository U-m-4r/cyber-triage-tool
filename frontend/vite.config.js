import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => ({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // Lets the frontend call the existing Flask API at /api/* without CORS juggling
    // Flask runs on :5001 (backend/app.py).
    proxy: {
      '/api': {
        target: loadEnv(mode, process.cwd(), '').BACKEND_PROXY_TARGET || 'http://127.0.0.1:5001',
        changeOrigin: true,
      },
    },
  },
}))
