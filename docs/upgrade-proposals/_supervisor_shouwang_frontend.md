# Supervisor · 守望 frontend rebuild

Date: 2026-09-06
Brand: 守望 / SHOUWANG · Night Watch SOC

## Roles

- **Grok**: design system (night canvas, phosphor LIVE, cinnabar watch-fire), primitives (BrandMark, KpiStat, Sparkline, HealthGauge, LiveBadge), tokens, Home ThreatNetwork frame fix, Monitor KPI always-on, visual QA.
- **Reasonix (DeepSeek)**: Home, Login/Register/BrandPanel, TopNav/Sidebar, eventStream + Logs + operations badges color maps.
- **OpenCode**: Monitor hierarchy, ThreatNetwork WebGL, RateHistogram recharts, relay/thought chrome.
- **MiniMax**: QA only. RESULT: PASS (`docs/upgrade-proposals/_minimax_shouwang_frontend_qa.md`). Wrapper timed out at 930s but the report is on disk and independently checked.

## Independent checks (Grok)

- `npx tsc -b` from `frontend/` → 0 errors.
- oxlint on key files → warnings only (Math.random in 3D builder, pre-existing setState-in-effect).
- `frontend/src/**/*.tsx` and `index.html` contain 0 × 「共享记忆」/ Shared Memory.
- Headless Chrome against Vite `:5173`:
  - login: night split + radar + 守望 + phosphor CTA
  - home: 112px wordmark, ON WATCH, ThreatNetwork phosphor glow + stars
  - monitor: 待处理 67504 cinnabar hero + sparkline; other KPIs quieter; LIVE stream; health gauges
  - mobile home: brand + CTAs hold
- Script: `frontend/scripts/verify-shouwang.mjs` → ok true.

## Leftover

- Docker `:3001` still serves the **old nginx image** until `shared-memory-frontend` is rebuilt.
- Operations / SecurityAudit / SelfPlay inherit tokens (dark + status colors) but were not fully re-composed.
- TopNav ON WATCH is ornamental (not bound to SSE). Monitor page extra badge is bound to stream status.
- Home `/api/stats` still 401 when logged out, so landing KPIs may read 0 until login.
- ML Fast Path / batch LLM UI: out of scope this round.
