# 守望 · Frontend Visual System

Brand: **守望** / SHOUWANG
English lockup: `SHOUWANG · Night Watch SOC`
Tagline: `灯火未熄。每一条日志，都在被守望。`
Emotion: 被守护 + 实时警觉。不是美术馆，不是灰阶后台。

This document is the contract. Implementers must use these tokens and components. Do not invent a second palette.

## 1. Why the old UI failed

- Status colors collapsed to `#111–#888`. Critical and OK were the same black.
- `border-radius: 0 !important` flattened every control into an admin console.
- Glass, tilt, and motion components were CSS-overridden into white rectangles.
- No chart library; KPIs were equal-weight numbers.
- Three.js was a static node graph with gray pulses.
- Brand was four characters of text: 共享记忆.

## 2. Palette (night canvas, beacon + watch-fire)

| Token | Hex | Role |
|---|---|---|
| `--color-night` | `#070B12` | Page canvas |
| `--color-surface` | `#070B12` | Same as night (Tailwind `bg-surface`) |
| `--color-card` | `#101820` | Elevated panel |
| `--color-mist` | `#161E2A` | Hover / inset |
| `--color-line` | `#243040` | Hairline |
| `--color-ink` | `#E8EEF6` | Primary text |
| `--color-ink-soft` | `#9AA8B8` | Secondary text |
| `--color-ink-faint` | `#6B7788` | Tertiary / labels |
| `--color-accent` | `#2AF4C4` | LIVE / healthy / radar (phosphor) |
| `--color-accent-hover` | `#1FCFAB` | Accent hover |
| `--color-ok` | `#2AF4C4` | Healthy |
| `--color-warn` | `#F5B942` | Warning |
| `--color-alert` | `#FF3D4A` | Critical / watch-fire |
| `--color-cinnabar` | `#FF3D4A` | Brand fire (same as alert) |
| `--color-signal` | `#5B8DEF` | Info / link |
| `--color-nong` | `#F5B942` | Legacy class → warn |
| `--color-hui` | `#5B8DEF` | Legacy class → info |
| `--color-dan` | `#3A4656` | Strong line |
| `--color-qing` | `#1A2430` | Inset fill |
| `--color-paper` | `#0C121A` | Alternate surface |

**0.1s scan rule:** critical = cinnabar, high = amber, ok = phosphor, info = signal blue. Never reuse ink for status.

Radius: **10px** default (`rounded-lg` / `.mono-card`). LIVE dots and avatars keep `rounded-full`. Do not zero radius with `!important`.

## 3. Type

- UI: IBM Plex Sans + Noto Sans SC
- Numbers / IPs / traces: IBM Plex Mono, `tabular-nums`
- Brand wordmark: Noto Sans SC 900, tracking `-0.04em`
- Body ≥ 13px. Do not default to 11px.

## 4. Signature visuals (must exist)

1. **BrandMark** — watchtower + radar arc + cinnabar lamp. Always next to 守望.
2. **LIVE phosphor dot** — pulsing in TopNav when the event stream is online.
3. **Hero KPI rupture** — pending / critical is larger, cinnabar, optional glow. Other KPIs are quieter.
4. **ThreatNetwork** — dark WebGL: phosphor nodes, cinnabar attack pulses, orbit, bloom-like additive glow. Not a gray SVG.
5. **Sparklines** on every primary KPI.
6. **Glass restored** — translucent card + blur + 1px phosphor-tinted edge.

## 5. Components to use (do not re-invent)

- `src/components/brand/BrandMark.tsx`
- `src/components/ui/LiveBadge.tsx`
- `src/components/ui/KpiStat.tsx`
- `src/components/ui/HealthGauge.tsx`
- `src/components/charts/Sparkline.tsx`
- `src/components/ui/GlassPanel.tsx` (real glass again)
- `src/components/ui/Button.tsx` (phosphor primary, cinnabar danger)
- `src/lib/brand.ts` copy constants

## 6. Information hierarchy

- One focal number per view (Monitor: 待处理 if > 0, else 已分析).
- Service health: left 3px tone bar + gauge + label color. Healthy ≠ identical gray cards.
- Agent relay: active node phosphor glow; idle dim; error cinnabar.
- Time: sparkline or Δ vs previous window. Naked integers are not enough.

## 7. Out of scope this round

- ML Fast Path UI
- Rewriting 20k-line page business logic
- New routes
- Replacing react-window virtualization
- Celery / ClickHouse / flipping ingest authority
