# 守望 · 白昼台账（Daylight Ledger）

Brand: **守望** / SHOUWANG
English lockup: `SHOUWANG · Daylight Ledger`
Tagline: `灯火未熄。每一条日志，都在被守望。`
Emotion: 白日案卷、冷静、可阅读。不是夜视 HUD，不是奶油生活方式，不是蓝按钮 SaaS。

This document is the contract. Implementers must use these tokens. Do not invent a second palette.

## 0. Why this look

The previous UI was a coffee-metal night canvas. The brief now: **朴素、浅色占大部分，但不能空成一张白纸。**

Product vernacular is a county yamen's daytime ledger + a limestone operations hall. The watchman's book is open after dawn. Threats are marked with a cinnabar seal. Everything else is ink on stone.

## 1. Palette (majority light)

| Token | Hex | Role |
|---|---|---|
| `--color-surface` | `#F1F4F6` | Page canvas. Cool limestone. **Majority of pixels.** |
| `--color-card` / `--color-paper` | `#FAFCFD` | Elevated paper. Stacked on limestone. |
| `--color-mist` | `#E6ECF0` | Hover, inset, chip track. |
| `--color-line` | `#D4DCE3` | Hairline rules. |
| `--color-ink` | `#1C2838` | Primary text. 黛墨. |
| `--color-ink-soft` | `#5C6B7A` | Secondary. |
| `--color-ink-faint` | `#8A97A4` | Labels / tertiary. |
| `--color-accent` | `#3A6570` | Live / action / watch-post. **暮青.** Not Tailwind teal, not SaaS blue. |
| `--color-accent-hover` | `#2F545E` | Accent hover. |
| `--color-on-accent` | `#F7FBFC` | Text on accent buttons. |
| `--color-ok` | `#3E7A64` | Healthy. 松绿, muted. |
| `--color-warn` | `#C08A3A` | Warning. 柿黄. |
| `--color-alert` | `#C23A32` | Critical only. 朱砂印. |
| `--color-signal` | `#4A7A88` | Info. Lighter dusk. |
| `--color-link` | `#3A6570` | Same as accent. |
| `--color-night` | `#1C2838` | **Not the page.** Dark well for 3D scenes that still need contrast, and dai ink alias. |
| `--color-dan` | `#C5CED6` | Stronger line (legacy). |
| `--color-qing` | `#E8EEF2` | Inset fill (legacy). |
| `--color-nong` | `#C08A3A` | → warn |
| `--color-hui` | `#4A7A88` | → signal |

**0.1s scan rule:** critical = cinnabar, high = persimmon, ok = pine, live/action = dusk. Never reuse ink for status. Never wash the page in accent.

**Forbidden (this brief):**
- Cream `#F4F1EA` + terracotta `#D97757` lifestyle kit
- Near-black canvas + phosphor/acid green
- Generic SaaS blue `#3B82F6` / iOS `#0071e3`
- Gold/coffee metal as the field
- Heavy glow, neon edges, decorative gradient washes
- Identical 16px-radius cards with the same grey drop shadow on every surface

Radius: **10px** default (`rounded-lg` / `.mono-card`). LIVE dots stay `rounded-full`. Do not zero radius with `!important`.

## 2. Type

- Brand wordmark **守望**: `Noto Serif SC` 900, tracking `-0.04em`. This is the one flourish.
- UI: IBM Plex Sans + Noto Sans SC
- Numbers / IPs / traces: IBM Plex Mono, `tabular-nums`
- Body ≥ 13px. Do not default to 11px.
- Do not Inter / Roboto / Arial as personality.
- Do not ALL-CAPS tracked eyebrows on every heading. Mono + small caps is for data labels and LIVE only.

## 3. Layout concept

A limestone hall with a paper spine on the left. Content is an open case file: left-aligned, generous padding, hairline rules, stacked paper.

```
+------+------------------------------------------+
| 守望 |  首页                         LIVE  user |
| serif|------ hairline --------------------------|
| 首页 |                                          |
| 日志 |   待处理 12          已审计    接入      |
| 监控 |   (cinnabar if >0)   quiet     quiet     |
| ...  |   ------------------------------------   |
|      |   paper cards on limestone               |
+------+------------------------------------------+
```

Sidebar: paper/limestone, 1px `line` rail. Active item: 3px dusk bar + `mist` fill + dusk text. Not a glowing pill.

TopNav: translucent paper (`rgba(250,252,253,0.86)` + blur). Hairline bottom.

## 4. Material (朴素但不空)

Depth comes from **paper on limestone**, not from glass-on-black:

- Card: `#FAFCFD`, 1px `#D4DCE3`, shadow `0 8px 24px rgba(28,40,56,0.06)`
- Optional 1px inner highlight `inset 0 1px 0 rgba(255,255,255,0.8)`
- `.glass` on light: `rgba(250,252,253,0.72)` + blur 14px + 1px line. No dark scrim.
- Page texture: faint cool ledger grid (48px, `rgba(58,101,112,0.05)`), masked so it is a whisper, not graph paper wallpaper.
- Soft dusk/pine radial stains at corners, opacity ≤ 0.08. Not decorative gradients.

Boldness is spent in **two places only**:
1. The serif 守望 wordmark
2. Cinnabar when something is actually wrong (pending > 0, critical event)

Cut one accessory if a page feels busy.

## 5. Components

- `BrandMark` — keep icon/mascot assets; wordmark uses **serif**. English lockup in mono dusk.
- `LiveBadge` — dusk teal, not gold.
- `KpiStat` — hero/pending is larger + cinnabar; others quiet. Soft ring, **no neon glow**.
- `Button` primary: `bg-accent text-on-accent` (dusk field, paper text). Danger: cinnabar. Outline: line + ink.
- `GlassPanel` / `.mono-card` — paper material above.
- Sparklines / gauges / status dots — pine / persimmon / cinnabar / dusk. Tracks are mist, not dark.

## 6. Auth (login / register)

Light must still dominate. Left brand panel is **limestone + serif 守望 + faint grid**, not a coffee night mural. Mascot can stay, but drop the dark gradient. Form card is paper on limestone. Inputs: white/paper field, cool line, dusk focus ring.

## 7. Hero / 3D

Home hero sits on limestone. Particle field: sparse dusk dots, **NormalBlending**, opacity ~0.28. No additive gold sparks on black.

ThreatNetwork: fog and clear color `#E8EEF2` (qing). Nodes dusk `#3A6570`, dim `#5C7A82`. Attack pulses cinnabar `#C23A32`. Remove `Stars` (stars on daylight look like a leftover night HUD). Edge lines cool grey-teal, low opacity.

Radar chrome bars: paper/80, not `bg-night/60`.

## 8. Pages

Do not rewrite business logic, routes, or virtualization. Restyle:

- Replace hardcoded coffee hex (`#100E0C`, `#1C1814`, `#C4A07A`, `#F7F3EE`, `#4E9A72`, `#C24F32` as field colors).
- `bg-night` overlays on light pages → `bg-card/90` or `bg-surface`.
- `text-night` on accent buttons → `text-on-accent` (or paper).
- iOS leftover `#0071e3` in phishing → accent/signal.
- Heavy `shadow-[0_0_Nx_rgba(196,160,122,...)]` → paper shadow or semantic-color ring at 12–16% opacity.
- Critical rows: 3px cinnabar left bar, not a red wash.

## 9. Motion

One orchestrated home hero reveal. Elsewhere: respond to user action. Honor `prefers-reduced-motion`. Do not fade-slide every card.

## 10. Accessibility

Body text ≥ 4.5:1 on limestone. Large type ≥ 3:1. Focus rings visible (dusk 3px at 18% alpha). `:selection` dusk on paper.

## 11. Out of scope

- New routes, backend, ML Fast Path
- Rewriting page business logic
- Replacing react-window
- New illustration assets (reuse brand-icon / mascot)

## 12. File split (implementers)

**Reasonix (foundation):** `index.css`, `index.html`, `lib/brand.ts`, `lib/operationsTokens.ts`, `layouts/*`, `components/ui/*`, `components/brand/*`, `components/login/*`, `components/common/PageFrame.tsx`, `components/charts/Sparkline.tsx`, `pages/Login.tsx`, `pages/Register.tsx`, `public/favicon.svg`.

**OpenCode (surfaces):** all other `pages/*`, `components/hero/*`, `components/monitor/*`, `components/operations/*`, `components/phishing/*`, `components/rag/*`. Do not edit Reasonix files.
