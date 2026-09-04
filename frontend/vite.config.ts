import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// dev 模式下 vite 容器内 `localhost` 是容器自身, 连不到宿主机 :8001 backend
//   用 `host.docker.internal:8001` 走 Docker Desktop 的 host-gateway DNS 解析
//   prod 模式 (vite build 静态产物) 不依赖 server.proxy, 改这里不影响 prod
const BACKEND_PROXY = process.env.BACKEND_PROXY || 'http://host.docker.internal:8001'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3001,
    strictPort: true,
    proxy: { '/api': BACKEND_PROXY },
  },
})
