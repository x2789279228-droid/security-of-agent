import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { initBrowserTelemetry } from './lib/otel'
import App from './App'

// 初始化浏览器 OTel trace (浏览器 → collector → Jaeger/Tempo), 幂等
initBrowserTelemetry()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
