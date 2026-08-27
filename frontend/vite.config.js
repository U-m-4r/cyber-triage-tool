import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Lets the frontend call the existing Flask API at /api/* without CORS juggling
    // once the two are wired together. Flask runs on :5000 (backend/app.py).
    proxy: {
      '/api': {
        target: 'http://localhost:5001',
        changeOrigin: true,
      },
    },
  },
})
