# 守望 SHOUWANG · Frontend Brand Rollout — Reasonix Implementation Report

Implements the 2026-Q3 「守望 / SHOUWANG」frontend visual system (docs/upgrade-proposals/2026-q3-frontend-shouwang.md) across Home, auth pages, nav, and status-color maps. Tokens from `frontend/src/index.css` were **not** touched; no API contract, route, auth, or business-logic changes; no new npm packages.

## Files changed

| File | Change |
| --- | --- |
| `frontend/src/layouts/TopNav.tsx` | `glass-nav` background; brand text → `BrandMark md + wordmark 守望`; active-tab underline `bg-accent` w/ phosphor glow (was `bg-ink`); static `LiveBadge LIVE` on right + auth actions (退出 hover→alert; 登录 as phosphor-outline chip). Height stays `h-14` so `RootLayout`'s `pt-14` is untouched. |
| `frontend/src/layouts/Sidebar.tsx` | `BrandMark md + 守望` header, subtitle → `Night Watch SOC`; active item now `border-accent/25 bg-accent/10 text-accent` (was black `bg-ink` pill); footer `守望 · v1.0`. (Sidebar is not mounted by `RootLayout` today — updated for the layout that uses it.) |
| `frontend/src/pages/Home.tsx` | Full flagship visual rebuild (see below). All API calls (`api.logsEvents`, `api.stats`, `eventsStream`), state, and capability/tier/pipeline data preserved verbatim. |
| `frontend/src/pages/Login.tsx` / `Register.tsx` | Form card `bg-white` rectangle → `glass-strong` panel; footer lockup → `BRAND.footer` (守望 · Night Watch SOC). Submit logic untouched. |
| `frontend/src/components/login/BrandPanel.tsx` | Rebuilt: night gradient + phosphor grid + decorative radar-disc rings (CSS `.radar-disc` from index.css) + `BrandMark lg` + 守望 h1 + `BRAND.nameEn` + tagline + pipeline 01–04 chips (ghost) + highlights; bottom lockup. Old `bg-ink`(→teal) gray-block design removed. |
| `frontend/src/components/login/LoginForm.tsx` / `RegisterForm.tsx` | Visual only: error box → cinnabar chip, cross-links → accent underline. Submit/validation logic identical. |
| `frontend/src/lib/eventStream.ts` | `EVENT_META` + `SEVERITY_META` class strings only (see below). Consumers (Monitor `EventRow` etc.) render these strings unchanged. |
| `frontend/src/pages/Logs.tsx` | Severity chips + list chrome only; data/stream/table logic kept. |
| `frontend/src/components/operations/badges.tsx` | Gray hex map → `BRAND_COLORS` soft chips (rounded-lg, inset ring), SLA overdue = alert pulse + cinnabar dot, `OrderTypeIcon` stroke `currentColor` (was `#111`). |
| `frontend/src/components/phishing/PhishingDetect.tsx` | Light chrome pass (visual only): risk chips safe/suspicious/phishing → phosphor/amber/cinnabar; indicator dots, tab buttons, detect button, confidence bar, history dots, checkbox accents. Logic untouched. |
| `docs/upgrade-proposals/_reasonix_shouwang_home_report.md` | This report. |

Not edited: `index.css`, `package.json`/lockfile, `Monitor.tsx` + `components/monitor/**`, `ThreatNetwork.tsx`, `backend/**`, any Python.

## What the pages now look like

**TopNav** — Translucent dark nav (`glass-nav`) floating over the page. BrandMark watchtower mark + 守望 wordmark on the left. Tabs keep Chinese labels; the active tab gets a glowing 2px phosphor underline (never ink-black). Right: pulsing `LIVE` chip, then username or a phosphor-outline 登录 button. Layout height unchanged.

**Home (flagship)** — Dark night hero, centered: `ON WATCH` LIVE badge + mono kicker → 守望 huge (SplittingText stagger, ~112px) → `SHOUWANG · Night Watch SOC` in phosphor → tagline 「灯火未熄。每一条日志，都在被守望。」 + manifesto. CTAs: primary `进入控制台`(console), outline `实时监控`, underline `阅读审计`, ghost `知识库`.
- 态势: ThreatNetwork 3D is framed in a glass radar panel (~420px) with top LIVE strip and bottom caption showing live 攻击脉冲 counter (cinnabar when >0, phosphor at 0), radar-sweep conic behind. The 3D's fixed 280px canvas is center-scaled 1.5× inside the frame (see risks).
- 数据: four `KpiStat` cards. 待处理 becomes tone=`hero` (large, cinnabar, beacon glow) when pending>0, else phosphor `ok`. 审计完成 ok + progress hint; 已接入 + 语义记忆 neutral.
- 能力: five `TiltCard` entries with hover phosphor edge, nav intact.
- 架构: four `GlassPanel` tiers with color identity — L1 phosphor / L2 signal blue / L3 amber / L4 cinnabar top-bar + ghost badge, so layers are distinguishable at a glance (previously all black).
- 事件: recent logs now carry severity chips — critical = cinnabar outline chip, high = amber, medium = signal blue, low/info = faint — inside a rounded bordered list.
- Footer: 守望 · Night Watch SOC (old “Shared Memory · Monochrome” gone).

**Login / Register** — Left BrandPanel is a night command desk: radar disc sweep, BrandMark + 守望 + English lockup + pipeline 01–04. Right form card is restored glass (`glass-strong`, phosphor-tinted edge, rounded), auth inputs keep the `auth-input` night style, footer lockup reads 守望 · Night Watch SOC.

## Status color maps (0.1 s rule)

`SEVERITY_META` (eventStream.ts, mirrored in Logs/Home):
- critical → `bg-alert/15 text-alert border border-alert/40`, bar `bg-alert w-[3px]`
- high → amber `warn` variants, bar `bg-warn w-[3px]`
- medium → signal blue `hui`, bar `bg-hui w-[3px]`
- low / info → faint (dan/line), thin bars

`EVENT_META`: security_event = phosphor; alert + tool_anomaly = cinnabar; audit_complete = phosphor-ghost; response_action = amber; agent_stage / pipeline_health = signal; selfplay = dashed phosphor/amber; thoughts & NDR/verdict types neutral ghost.

Operations badges: status/severity/priority/SLA now render as rounded chips with brand hue + translucent fill + inset ring; SLA overdue pulses cinnabar; order-type icons stroke ink instead of hard `#111`.

## Leftover risks / notes

1. **ThreatNetwork height**: the 3D file (owned by another agent) still hard-codes `h-[280px]` + `bg-white` wrapper. Home centers it with `scale-[1.5]` inside the 420px frame — mild upscaling softness possible; when the 3D owner raises its own height, drop the `scale-[1.5]` wrapper. Its `bg-white` renders as card color via the index.css override, so it blends.
2. **TopNav LIVE is static** (per contract, no stream hook in the nav). If a shared `useEventStreamLifecycle` consumer is added later, pass its `online` state to `LiveBadge`.
3. **KpiStat sparklines unused on Home**: `/stats` is a single snapshot with no time series and the contract forbids new endpoints; KPIs carry textual progress hints instead.
4. Other agents' pages may still contain their own leftover light-theme classes (`bg-ink`, `bg-white`, `#111`) — the global overrides in index.css keep them readable (ink→phosphor-dark, white→card), and shared meta strings now carry real colors, but those files were out of scope.
5. `Sidebar` is currently unused (RootLayout renders `TopNav`); kept in sync for any future layout that mounts it.
6. `index.html` title already read 「守望 · Night Watch SOC」 — no change needed.

## Verify

- `npx tsc -b --pretty false` (from `frontend/`) → **exit 0, no errors**.
- `npx oxlint` on touched files → **0 errors**; 3 warnings are pre-existing patterns, not introduced by this change:
  - `only-export-components` (badges.tsx exports `orderTypeLabel` helper alongside components — pre-existing module shape)
  - `purity` Date.now in `SlaBadge` (pre-existing logic, kept as-is)
  - `set-state-in-effect` in Logs initial load (pre-existing data logic, intentionally untouched)
