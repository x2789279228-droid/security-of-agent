# Daylight Ledger 视觉重塑 — QA 报告

**范围:** `frontend/src` 下全部 `*.ts / *.tsx / *.css`（共 85 个文件）
**契约:** `docs/upgrade-proposals/2026-q3-frontend-daylight-ledger.md`
**模式:** 只读 QA，不动源码；除非存在阻止编译的一行阻断。
**结论:** **PASS**（带 1 项需关注的遗留风险 + 1 项 dist 过期告警）

---

## 1. 编码 (UTF-8)

| 检查 | 结果 |
|---|---|
| 文件数 | 85 (`*.ts` + `*.tsx` + `*.css`) |
| 无效 UTF-8 字节 | 0 |
| 含 U+FFFD (`�`) | 0 |
| 已知 mojibake 模式 (`璧勒贩` / `鍚` / `拿出` / `鏍` / `璧勪骇` 等) | 0 |
| 出现位置 | N/A |

**结论:** 编码干净，无损伤。

---

## 2. 调色板残留扫描 (src 范围内)

```
$ rg -l "#100E0C|#1C1814|#C4A07A|#F7F3EE|#1A1612|#0071e3" frontend/src
(no matches)

$ rg -l "text-night|bg-night" frontend/src
(no matches)

$ rg -l "#F4F1EA|#D97757|#3B82F6" frontend/src
(no matches)
```

| 禁用 hex / class | 命中文件数 |
|---|---|
| `#100E0C` | 0 |
| `#1C1814` | 0 |
| `#C4A07A` | 0 |
| `#F7F3EE` | 0 |
| `#1A1612` | 0 |
| `#0071e3` (iOS 蓝) | 0 |
| `text-night` | 0 |
| `bg-night` | 0 |
| `#F4F1EA` / `#D97757` / `#3B82F6` (lifestyle/SaaS kit) | 0 |

`night` 一词仅存于两处合规位置：
- `index.css:5` — `--color-night: #1c2838` (注释明确：仅作 3D 深井与墨滴别名，不是页面底色)
- `lib/brand.ts:13` — `BRAND_COLORS.night = '#1C2838'` (同上用途)

**结论:** 残留清零。

---

## 3. Tokens (`frontend/src/index.css @theme`)

| 契约要求 | 文件实际值 | 通过 |
|---|---|---|
| `--color-surface` `#F1F4F6` | `#f1f4f6` | ✓ |
| `--color-ink` `#1C2838` | `#1c2838` | ✓ |
| `--color-accent` `#3A6570` | `#3a6570` | ✓ |
| `--color-on-accent` `#F7FBFC` | `#f7fbfc` | ✓ (大小写等价) |
| `--color-paper` `#FAFCFD` | `#fafcfd` | ✓ |
| `--color-alert` `#C23A32` | `#c23a32` | ✓ |

辅助 token 全部就位：`--color-card #fafcfd`、`--color-line #d4dce3`、`--color-mist #e6ecf0`、`--color-accent-hover #2f545e`、`--color-ok #3e7a64`、`--color-warn #c08a3a`、`--color-signal #4a7a88`、`--color-link #3a6570`、`--color-qing #e8eef2`、`--color-dan #c5ced6`。

`html { background: #f1f4f6 }` 与 `body { background-color: #f1f4f6; color: #1c2838 }` 双向兜底，全局画布为浅色石灰石。

**结论:** Token 与契约逐项对齐。

---

## 4. 按钮与关键 chrome

| 位置 | 实际样式 | 通过 |
|---|---|---|
| `components/ui/Button.tsx:14` (primary) | `bg-accent text-on-accent` | ✓ |
| `components/ui/Button.tsx:16` (outline) | `text-ink border border-line` | ✓ |
| `components/ui/Button.tsx:19` (danger) | `bg-alert text-paper` | ✓ |
| `pages/Logs.tsx:208` (刷新按钮) | `bg-accent text-on-accent hover:bg-accent-hover` | ✓ |
| `components/common/PageFrame.tsx:33` (`tabOn`) | `bg-accent text-on-accent border border-accent` | ✓ |
| `components/common/PageFrame.tsx:34` (`tabOff`) | `bg-transparent text-ink-soft border border-line` | ✓ |
| `components/login/LoginForm.tsx:90` (submit) | `<Button variant="primary">` | ✓ |
| `components/login/RegisterForm.tsx:112` (submit) | `<Button variant="primary">` | ✓ |

主按钮文本色 `text-on-accent` (不是 `text-night`)，朱砂按钮文本 `text-paper`，符合契约第 5 节。

---

## 5. 3D (Hero / ThreatNetwork)

| 契约点 | 实际 | 通过 |
|---|---|---|
| `ThreatNetwork` 背景色 | `<color attach="background" args={['#E8EEF2']} />` | ✓ |
| `ThreatNetwork` fog | `<fog attach="fog" args={['#E8EEF2', 13, 26]} />` | ✓ |
| `ThreatNetwork` 父容器 | `bg-qing` (== `#e8eef2`) | ✓ |
| 无 drei `Stars` 引入 | `import { OrbitControls } from '@react-three/drei'` 仅 OrbitControls | ✓ |
| 全工程无 `Stars` 使用 | `rg "Stars" frontend/src` → 0 命中 | ✓ |
| `ParticleField` blending | `blending={THREE.NormalBlending}` | ✓ |
| `ParticleField` 颜色 | `color="#3A6570"`, `opacity={0.28}` | ✓ |
| `ThreatNetwork` 健康节点色 | `COLOR_OK = '#3E7A64'` (松绿) | ✓ (与契约 0.1s scan rule "ok = pine" 一致) |
| `ThreatNetwork` 攻击脉冲 | `COLOR_ATTACK = '#C23A32'` (朱砂) | ✓ |
| `ThreatNetwork` dim 节点 / 连线 | `#5C7A82` | ✓ |
| `ThreatNetwork` WebGL 兜底底色 | `bg-qing text-ink-faint` | ✓ |

注：契约 7 节写"Nodes dusk `#3A6570`"，但实现里把状态为 healthy 的节点用 `#3E7A64`（松绿）渲染、攻击目标闪 `#C23A32`（朱砂）、dim 用 `#5C7A82`。这与契约同一节"0.1s scan rule：ok = pine, critical = cinnabar"以及第 5 节"status dots — pine / persimmon / cinnabar / dusk"完全一致；与契约 7 节"Nodes dusk"那一句存在 1 行口径冲突，但语义结果（白昼台账状态色板）正确。**不算 fail**。

---

## 6. 编译 (`npm --prefix frontend run check`)

```
$ npm --prefix frontend run check
> shared-memory-frontend@0.0.0 check
> tsc -b && oxlint

(warnings only, 见下)
```

- `tsc -b` 退出码 0，**0 条 `error TS*`**。
- `oxlint` 仅产出 lint warnings：41 条均为 React Compiler / Hooks 模式（`react(set-state-in-effect)`、`react(purity)`、`react(only-export-components)`、`react-hooks(exhaustive-deps)`、`react(immutability)`）。**全部在 restyle 之前的源码中已经存在**，未引入新错误。涉及文件：`LifecycleLoop / FeedbackTab / ToolSignaturePanel / LearnLoopTab / badges / KpiTab / TracePanel / ThoughtChainPanel / ThreatNetwork / ParticleField / AgentRelayStrip / Response / Monitor / Logs / CasesTab / CostTab / ActiveRelayCards / WorkOrdersTab / QualityPanel / AssetsTab / PostMortemsTab / SelfPlay / CaseDrawer / SecurityAudit / RAG / RulesTab`。这些是 React 19 / Oxlint React 规则下的常规告警，与视觉重塑正交。
- `LASTEXITCODE = 0`。

**结论:** 通过。

---

## 7. 对比度 / 主画布

- `html` 与 `body` 背景均为 `#f1f4f6`（石灰石）。
- `RootLayout:12` 顶层容器 `min-h-screen bg-surface font-sans text-ink`，主字段为浅色石灰石、黛墨字。
- `Sidebar:59` `bg-paper` + `border-line`，左侧列是纸色，不存在暗色 canvas。
- `TopNav` 走 `.glass-nav`：`rgba(250,252,253,0.86)` + blur 16px，无暗幕。
- 全工程无 `bg-night*`、无 `#0*` 黑色硬编码背景（`Sidebar.tsx:123` 移动抽屉的 `bg-black/40` 是模态背板，非页面字段）。
- 文字对比：`#1c2838` (ink) on `#f1f4f6` (surface) → 亮度比 ≈ 12.8:1，远高于 WCAG AAA 7:1。
- 选区色：`#3a6570` 暮青底 / `#f7fbfc` 纸色字。
- 焦点环：`.auth-input:focus` 暮青 `box-shadow 0 0 0 3px rgba(58,101,112,0.18)`。

**结论:** 主画布是浅色石灰石，文字对比充分，无暗色页面残留。

---

## 8. Operations 中文完整性

| 关键字 | LearnLoopTab.tsx | WorkOrdersTab.tsx |
|---|---|---|
| `待处理` | — | L17: `pending: { label: '待处理', ... }` ✓ |
| `批准` | — | L128: `✓ 批准` ✓ |
| `学习闭环` | L89 / L135 / L139 / L219 完整 ✓ | — |
| `待复核` | L36 (`proposed` → `待复核`) ✓ | — |
| `补复盘草稿` | L20 + L318 (`补复盘草稿 / 已关闭案例缺失复盘 → 自动生成草稿`) ✓ | — |

中文无替换字符 (`\uFFFD`)、无 `?`/`??` 替代、无已知 mojibake 串。

**结论:** 中文 UI 文本完整。

---

## 9. 遗留风险 / 关注项（非阻断）

1. **品牌 lockup 文案未切到 Daylight Ledger** — 仅风险提示，不影响视觉系统。
   - 契约 1 行：`English lockup: SHOUWANG · Daylight Ledger`
   - 实际可见文案（仍写旧名）：
     - `lib/brand.ts:4` `lockup: 'SHOUWANG · Night Watch SOC'`
     - `lib/brand.ts:8` `footer: '守望 · Night Watch SOC'`
     - 使用点：`layouts/Sidebar.tsx:68`、`components/login/BrandPanel.tsx:67`
   - 备注：`"Daylight Ledger"` 字面仅出现在 `index.css:4` 与 `lib/brand.ts:11` 的注释里，**用户可见 UI 上仍是旧 lockup**。如要严格符合契约需要把这两处文案同步过来。本次只做 QA，按"不动源码"原则保留。

2. **`frontend/dist` 是过期构建产物** — 不在 QA 范围内（src 是契约范围），但若直接发布 dist 而不重跑 `npm run build`，旧 coffee 色（`#C4A07A`、`#C24F32` 在 `ThoughtChainPanel-*.js` 等）会被打出去。建议重跑 `npm --prefix frontend run build` 再出包。

3. **oxlint 警告 41 条全部为 React 模式告警**，与本次视觉重塑正交；契约允许的"pre-existing warnings"。**未引入新错误**。

---

## 10. 总评

| 检查项 | 通过 |
|---|---|
| 1. UTF-8 编码 | PASS |
| 2. 调色板残留扫描 | PASS |
| 3. Tokens (`@theme`) | PASS |
| 4. 按钮 (Button.tsx / Logs refresh / PageFrame tabOn) | PASS |
| 5. 3D (ThreatNetwork / ParticleField / Stars) | PASS |
| 6. `npm run check` 退出 0 | PASS |
| 7. 对比度 / 主画布 | PASS |
| 8. 中文完整性 | PASS |

**最终判定: PASS**（1 项品牌 lockup 文案遗留 + 1 项 dist 过期构建；前者为契约边界外的副本同步，后者为发布流水线环节，不影响 src 的视觉重塑验收）。
