# Reasonix（foundation）· 白昼台账 Daylight Ledger 交付报告

Contract: `docs/upgrade-proposals/2026-q3-frontend-daylight-ledger.md`
Scope: Reasonix foundation files only. OpenCode-owned pages/hero/monitor/operations/phishing/rag files were NOT edited.

## Files changed

| File | Change |
|---|---|
| `frontend/src/index.css` | Full rewrite: light `@theme` tokens (surface `#F1F4F6`, card/paper `#FAFCFD`, accent `#3A6570`, on-accent `#F7FBFC`, ok/warn/alert/signal/dan/qing/nong/hui per contract); light `html`/`body`; faint 48px ledger grid `rgba(58,101,112,0.05)` masked; two corner dusk/pine stains ≤0.08; dusk `::selection`; cool scrollbar; `.mono-card`/`.glass`/`.glass-strong`/`.glass-nav`/`.glass-input`/`.auth-input` now paper-on-limestone with 3px dusk focus ring `rgba(58,101,112,0.18)`; light autofill (kept light bg + dark text); `.page-title` ink; `.rule-ink` dusk→pine; `.bg-white` → card; removed coffee `.bg-ink` brown override; beacon/radar recolored cinnabar/dusk; `prefers-reduced-motion` block added |
| `frontend/src/lib/brand.ts` | `BRAND_COLORS` → new hex set per contract (night/card/ink stay dark-ink aliases `#1C2838`/`#FAFCFD`); added `paper` + `onAccent`; `AI_GRADIENT`/`AI_GRADIENT_STOPS` → dusk→pine `#3A6570→#4A7A88→#3E7A64`, no gold |
| `frontend/src/lib/operationsTokens.ts` | `INK_FAINT` `#8A97A4`, `TRACK` `#E6ECF0`; `CHART_GRADIENT` / `CHART_GRADIENT_DIVERGING` hexes updated; all 咖啡/森绿/琥珀 comments rewritten to 暮青/松绿/柿黄/灰青/朱砂 |
| `frontend/src/layouts/Sidebar.tsx` | Paper spine (`bg-paper`); active item → 3px dusk bar (`w-[3px]`) + `bg-mist` fill + `text-accent`, no glowing pill |
| `frontend/src/components/ui/Button.tsx` | Primary `bg-accent text-on-accent` + soft dusk shadow (no gold glow); danger `bg-alert text-paper`; outline line+ink with `hover:bg-paper`; ghost unchanged semantics; comment 咖啡→暮青/朱砂 |
| `frontend/src/components/ui/HealthGauge.tsx` | ok/warn/alert hexes → `#3E7A64/#C08A3A/#C23A32` with light tracks |
| `frontend/src/components/ui/KpiStat.tsx` | Card `bg-card`; gold/phosphor rgba glows → quiet semantic rings (4px / 10–12% alpha); `hero` keeps cinnabar `kpi-hero-glow` |
| `frontend/src/components/ui/StatusDot.tsx` | New ok/warn/error hexes; glow softened (`0 0 5px` @66%); pulse guarded by `useReducedMotion` |
| `frontend/src/components/ui/TiltCard.tsx` | Paper card, line border, paper shadow `0 8px 24px rgba(28,40,56,0.06)` + inner highlight; hover `border-accent/40`; no 0.28 black shadow / gold glow |
| `frontend/src/components/brand/BrandMark.tsx` | Wordmark 守望 → `font-serif` 900 `tracking-[-0.04em]`; English lockup mono `text-accent` (full dusk, not /90) |
| `frontend/src/components/login/BrandPanel.tsx` | Light limestone panel (`#f1f4f6` base + ≤0.08 dusk/pine corner stains + faint cool grid), no `#1a1612/#100e0c` coffee gradient; hairline `border-r` (full) / `border-b` (compact); 守望 h1 serif; mascot soft ink shadow; chips paper-on-line; mono footer |
| `frontend/src/components/common/PageFrame.tsx` | `tabOn` `text-night` → `text-on-accent` |
| `frontend/index.html` | `theme-color` → `#F1F4F6`; font links untouched (Noto Serif SC already loaded) |
| `frontend/public/favicon.svg` | Recolored dusk square `#3A6570` + line ring `#D4DCE3` + paper face `#FAFCFD` + dai-ink features `#1C2838`; face kept |

Unchanged but verified token-clean (colors flow through `@theme`/`BRAND_COLORS`): `layouts/RootLayout.tsx`, `layouts/TopNav.tsx`, `components/ui/GlassPanel.tsx`, `components/ui/LiveBadge.tsx`, `components/ui/SplittingText.tsx` (no hardcoded color/type), `components/charts/Sparkline.tsx` (driven by `BRAND_COLORS`), `components/login/LoginForm.tsx`, `RegisterForm.tsx`, `pages/Login.tsx`, `pages/Register.tsx` (form card = `.glass-strong`, now light paper, via CSS).

## Tests run

| Test | Command | Result |
|---|---|---|
| Type check + lint | `npm --prefix frontend run check` (`tsc -b && oxlint`) | exit 0; only pre-existing oxlint warnings, all in OpenCode-owned files |
| Production build (CSS pipeline) | `npm --prefix frontend run build` (`tsc -b && vite build`) | exit 0; 1930 modules; chunk-size warnings only (pre-existing) |
| Token grep (verify 1) | `search_content` for `#100e0c #1c1814 #c4a07a #f7f3ee #1a1612 #b8895c` + legacy rgba forms + `text-night` across my file list | 0 matches in my files; remaining hits are all in OpenCode trees |
| Emitted CSS (verify 3) | grep `dist/assets/index-*.css` | `--color-on-accent:#f7fbfc`, `--color-paper:#fafcfd`, `.text-on-accent`, `.bg-paper`, `.text-paper` all present |

## Result

Foundation layer fully restyled to Daylight Ledger: majority cool light limestone, paper-on-limestone material, dusk action color, pine/persimmon/cinnabar statuses, cinnabar reserved for real threats. No coffee/ivory hex, no gold gradient, no phosphor neon remains in any Reasonix file. Business logic, routes, and backend untouched.

## Leftover risks

- **OpenCode files still carry coffee hexes / gold glows / `text-night` on accent buttons** (e.g. `pages/Home.tsx`, `pages/Logs.tsx:208`, `pages/Monitor.tsx:386`, `components/monitor/*`, `components/operations/KpiTab.tsx:90`, `CostTab.tsx:266`, `components/hero/ThreatNetwork.tsx`, `components/phishing/PhishingDetect.tsx`). Until their pass lands, those surfaces render mid-state (dark-on-accent text is momentarily illegible; gold glow code is inert against new dusk tokens but should be deleted per contract §8). Foundation CSS alone cannot fix page-scoped hardcodes.
- **Shared class semantics flipped** (intended, contract-driven): `.bg-white` → card `#FAFCFD`; custom `.bg-ink` brown override removed → `bg-ink` is now dai-ink `#1C2838` (pairs fine with `text-white` chips). OpenCode pages that assumed the old meanings should re-verify.
- **`brand-mascot.jpg` / `brand-icon.jpg` are dark-themed raster assets**, kept per "no new assets". On the now-light BrandPanel the mascot sits on limestone with a soft ink shadow (contract: mascot may stay). A future asset pass could re-export it on limestone.
- **English brand strings untouched** (`BRAND.lockup`/`footer` = `SHOUWANG · Night Watch SOC`, `<title>`). Proposal header suggests lockup `SHOUWANG · Daylight Ledger`, but the implementer brief lists no copy/string change, so text was left for the owner's decision.
- `.mono-card-ink` was remapped to a qing inset "well" (`#E8EEF2`/`#C5CED6`); any page expecting the old dark-glow card should restyle it (no current page usage found in codebase scan).
- Reduced-motion handling added for CSS beacon/radar/ping and StatusDot; framer-motion reveals elsewhere still animate per existing code.
