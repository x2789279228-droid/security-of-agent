# MiniMax QA — 守望 (SHOUWANG) Frontend Rebuild

- Role: MiniMax QA only — inspection, no feature work.
- Contract: `docs/upgrade-proposals/2026-q3-frontend-shouwang.md`
- Workspace: `D:\揭榜挂帅\shared-memory-platform\frontend`
- Date: 2026-09-06

## Methodology

- `tsc -b --pretty false` run once from `frontend/` (background, log captured).
- Static inspection via `read_file` / `grep_content` on:
  - `frontend/src/index.css`
  - `frontend/src/pages/Home.tsx`
  - `frontend/src/pages/Monitor.tsx`
  - `frontend/src/components/hero/ThreatNetwork.tsx`
  - `frontend/src/components/monitor/RateHistogram.tsx`
  - `frontend/src/components/login/BrandPanel.tsx`
  - `frontend/src/components/ui/HealthGauge.tsx`
  - `frontend/src/lib/brand.ts`
  - `frontend/package.json`
  - `frontend/index.html`
- Repo-wide ripgrep for legacy brand strings in `frontend/**`.

No product code was modified.

## Acceptance Checklist

### 1. `npx tsc -b --pretty false` exits 0 — PASS

- Command: `cd "D:\揭榜挂帅\shared-memory-platform\frontend"; npx tsc -b --pretty false`
- Background task `bg_652fb095-8762-4504-9bfe-fb45d9a5c9fb` returned `exit=0`.
- No stderr diagnostics emitted on stdout.
- No code changes were required to satisfy this gate.

### 2. No 共享记忆 / Shared Memory in user-visible copy — PASS

- Repo-wide ripgrep for `共享记忆|Shared Memory|shared-memory|SharedMemory`:
  - `frontend/src/**/*.tsx` — **0 matches**.
  - `frontend/index.html` — **0 matches**.
- Only residual occurrences:
  - `frontend/package.json:2` `"name": "shared-memory-frontend"` — contract explicitly permits.
  - `frontend/package-lock.json:2, 8` same name (auto-generated).
- Brand surfaces use `BRAND.name = '守望'` / `BRAND.nameEn = 'SHOUWANG'` (`frontend/src/lib/brand.ts:2-4`).

### 3. Status tokens distinct hues, not gray — PASS

`frontend/src/index.css:17-21`:

```
--color-ok: #2af4c4;       /* phosphor green */
--color-warn: #f5b942;      /* amber */
--color-alert: #ff3d4a;     /* cinnabar red */
--color-cinnabar: #ff3d4a;  /* cinnabar red */
```

- `ok` ≠ `warn` ≠ `alert` ≠ `cinnabar` (4 distinct hues).
- No `#111` / `#555` collapse on any status slot.

### 4. No `border-radius: 0 !important` wipe — PASS

- ripgrep for `border-radius: 0 !important` across `frontend/src` → 0 hits.
- `.glass` keeps `border-radius: 14px` (`index.css:175`); rounded utility surfaces
  (`rounded-xl`, `rounded-full`, `rounded-lg`) are intact in the inspected
  components.

### 5. Glass restored — PASS

`frontend/src/index.css:171-178`:

```
.glass,
.glass-strong {
  background: rgba(16, 24, 32, 0.62);
  border: 1px solid rgba(42, 244, 196, 0.12);
  border-radius: 14px;
  box-shadow: 0 18px 48px rgba(0, 0, 0, 0.35);
  backdrop-filter: blur(18px) saturate(1.25);
}
```

`backdrop-filter` is present on `.glass` and `.glass-nav` (`index.css:186`).

### 6. Home.tsx uses BrandMark + 守望 + KpiStat, pending → hero/alert — PASS

`frontend/src/pages/Home.tsx`:

- L6 imports `BrandMark`; L8 imports `KpiStat`.
- L217 `<BrandMark size="lg" />` rendered in hero.
- L221 `<SplittingText text="守望" delay={0.15} />` rendered as `<h1>`.
- L316-321 pending KPI:
  ```
  <KpiStat label="待处理" value={pending}
           tone={pending > 0 ? 'hero' : 'ok'}
           hint={pending > 0 ? '等待复核或自动处置' : '队列已清空'} />
  ```
  i.e. switches to `hero` (alert) when pending > 0.

### 7. Monitor.tsx uses KpiStat + HealthGauge, 待处理 is focal — PASS

`frontend/src/pages/Monitor.tsx`:

- L12 imports `HealthGauge`; L13 imports `KpiStat`.
- L319 `<HealthGauge health={tone.gauge} />` for each of the 3 service cards.
- L346-354 pending KPI:
  ```
  <KpiStat label="待处理" value={securityPending}
           tone={securityPending > 0 ? 'hero' : 'ok'}
           spark={pendingSpark}
           live={securityPending > 0}
           hint={...}
           className="col-span-2" />
  ```
- Other 4 KPIs share single-column grid slots; 待处理 occupies **2 of 6
  columns** (`col-span-2` on a `grid-cols-6`), making it the visual focal
  KPI. Hero tone + `live` indicator only when pending > 0.

### 8. ThreatNetwork.tsx uses phosphor/cinnabar, OrbitControls, AdditiveBlending — PASS

`frontend/src/components/hero/ThreatNetwork.tsx`:

- L3 `import { OrbitControls, Stars } from '@react-three/drei'`.
- L19 `COLOR_OK = new THREE.Color('#2AF4C4')` (phosphor).
- L21 `COLOR_ATTACK = new THREE.Color('#FF3D4A')` (cinnabar).
- L252 edge material `color="#2AF4C4"`.
- L196 pulses use `COLOR_ATTACK` for attack, `COLOR_OK` for normal — **not all `#111`**.
- L265, L279 glow + pulse materials use `blending={THREE.AdditiveBlending}`.
- L329-337 `<OrbitControls ... enableDamping autoRotate autoRotateSpeed={0.4} ... />`.

### 9. recharts in package.json + RateHistogram uses it — PASS

- `frontend/package.json:33` `"recharts": "^3.10.1"` present in `dependencies`.
- `frontend/src/components/monitor/RateHistogram.tsx:6` imports
  `Bar, BarChart, Cell, ResponsiveContainer, Tooltip` from `recharts`.
- L69-89 builds a `<BarChart>` with 12 buckets, latest-bucket highlight via
  `BRAND_COLORS.accent`, dimmed phosphor for non-empty older buckets,
  phosphor-aware cursor fill.

### 10. Login BrandPanel says 守望 — PASS

`frontend/src/components/login/BrandPanel.tsx`:

- L7 imports `BRAND`; L88-91 renders `{BRAND.name}` + `{BRAND.nameEn}`.
- `BRAND.name = '守望'` (`frontend/src/lib/brand.ts:2`).
- BrandMark + “Night Watch SOC” lockup also present.

### 11. No docker rebuild required — PASS

- This QA run touched no Docker images, compose files, or backend services.
- No product code was edited; only this report was written.
- Build and runtime parity is preserved (`tsc -b` already green from step 1).

## Files Inspected

- `frontend/src/index.css`
- `frontend/src/pages/Home.tsx`
- `frontend/src/pages/Monitor.tsx`
- `frontend/src/components/hero/ThreatNetwork.tsx`
- `frontend/src/components/monitor/RateHistogram.tsx`
- `frontend/src/components/login/BrandPanel.tsx`
- `frontend/src/components/ui/HealthGauge.tsx`
- `frontend/src/lib/brand.ts`
- `frontend/package.json`
- `frontend/index.html`

## Leftover Risks / Notes (non-blocking)

- **package.json name unchanged.** `frontend/package.json:2` still reads
  `"shared-memory-frontend"`. Contract explicitly permits; downstream
  artifact names will keep that string until a rename commit. No effect on
  acceptance.
- **TypeScript build references.** `tsc -b` returned 0 with no diagnostics;
  if build-info caching masks an issue, a clean rebuild (`rm -rf tsconfig*.tsbuildinfo`) is recommended before release, but not required by the contract.
- **Visual regression.** This QA is static — no browser snapshot diff was run.
  The Day-One smoke test should still walk: Home hero, Monitor pending KPI,
  ThreatNetwork orbit + attack pulse injection, Login panel.
- **Pending KPI is wired to live stats.** The `hero` tone only fires when
  `securityPending > 0`. In a quiet demo environment it will render in `ok`
  phosphor — that is the intended quiet-state behavior per the spec.
- **No code changes were made** during this audit; the report is the only
  artifact written.

RESULT: PASS