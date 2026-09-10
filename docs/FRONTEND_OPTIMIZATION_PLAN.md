# 前端视觉优化方案 · 守望 (Watch)

> **范围**：仅前端视觉与交互层，不涉及后端 API / 数据结构改动。
> **约束**：保持浅色基调 + 案卷/竖印的设计语言，只在克制的前提下补回现代视觉信号。
> **基线**：`frontend/src/index.css`、`TopNav.tsx`、`RootLayout.tsx`、`pages/Home.tsx`、`pages/Monitor.tsx` 及 16 个 page、50+ component。

---

## 0. 设计原则（贯穿全文）

| 保留 | 改进 |
|---|---|
| 浅色基调（`#f1f4f6` / `#fafcfd` / `#1c2838`） | 在 mono-tone 中加 1–2 个浅色"提亮"色，避免"灰突突" |
| 案卷/竖印的命名（守望、值班、徽墨） | 装饰元素用得省，但**该用就用**——掐光 ≠ 朴素 |
| Noto Serif SC 标题、宋体感 | 数字改 tabular-nums，KPI 不再"跳舞" |
| 圆角克制（不追求大圆角） | 从 2/6/16 渐进到 4/8/12，按层级选用 |
| `mono-input` 的下划线输入 | 保留下划线为默认，**新增**填充态供高密度表单选用 |
| accent 青墨只用一处（active 下划线） | accent 增加"次级"色（hover/focus），但仍是低饱和 |

**单一视觉锚点**：每个页面只允许出现 **一处**"亮"信号（彩色 gradient、发光、印章红）。其余位置继续用灰阶 + 1px 线分层。

---

## 1. 设计 Token 升级 · `frontend/src/index.css:3-36`

### 1.1 圆角梯度（替换 `:33-35`）

```css
--radius-xs: 2px;   /* 案卷边角、印章、tag */
--radius-sm: 4px;   /* input、表格行 hover */
--radius-md: 8px;   /* 卡片、按钮 */
--radius-lg: 12px;  /* modal、drawer、hero card */
--radius-pill: 999px; /* status dot、chip */
```

### 1.2 阴影梯度（**新增**，对应 `--radius-md/lg`）

```css
--shadow-1: 0 1px 2px rgba(28,40,56,0.04), 0 1px 1px rgba(28,40,56,0.03);
--shadow-2: 0 4px 12px rgba(28,40,56,0.06), 0 2px 4px rgba(28,40,56,0.04);
--shadow-3: 0 12px 32px rgba(28,40,56,0.10), 0 4px 8px rgba(28,40,56,0.06);
```

> 仍极克制——opacity 不超过 0.10，颜色用 `--color-ink` 的低透明版，避免"白上加白"的 SaaS 感。

### 1.3 浅色"提亮"色（**新增**，4 个）

```css
/* 暖白：用于 KPI 卡底色，提升层级 */
--color-paper-warm: #fbf7f0;
/* 薄荷：用于 ok 状态背景 */
--color-mint: #e8f1ec;
/* 淡桃：用于 hero 区域渐变点缀 */
--color-peach: #f7e8e0;
/* 印章红：唯一的"亮色"信号，限 1 处/页 */
--color-seal: #a8392f;
```

### 1.4 字体梯度细化（替换 `:27-31`）

```css
--font-sans: ...;
--font-serif: ...;
--font-mono: ...;

/* 数字字宽统一 */
--font-num: ui-monospace, "IBM Plex Mono", "SF Mono", "Roboto Mono", monospace;
```

并在 `body` 加：`font-variant-numeric: tabular-nums;`（KPI/数字对齐）。

### 1.5 间距系统（**新增**）

```css
--space-1: 4px;
--space-2: 8px;
--space-3: 12px;
--space-4: 16px;
--space-5: 24px;
--space-6: 32px;
--space-8: 48px;
--space-10: 64px;
```

### 1.6 删除 / 弱化

- `index.css:241-243` 的 `.kpi-hero-glow { animation: none }` —— 这个禁用了 KPI 光晕，是"掐光"代表；改成可选。
- `.glass` 的 `box-shadow: none` / `backdrop-filter: none`（`:164-180`）—— 现在它已经不"glass"，**改名**为 `.surface-flat` 或直接删除，避免语义混淆。

---

## 2. 通用组件升级 · `frontend/src/components/ui/`

### 2.1 `Button.tsx` · 加视觉变体

**现状**（推测）：可能只有文字按钮。

**新增 3 态 + 2 size**：
- `variant: 'primary'` —— 青墨底 + 浅米文字 + `--shadow-1`，hover 加深 4%
- `variant: 'secondary'` —— 白底 + 1px `--color-line` 边框 + `--shadow-1`
- `variant: 'ghost'` —— 透明底，hover 出现 `--color-mist` 背景
- `size: 'sm' | 'md'` —— 高度 32 / 40
- `loading` 态 —— 内置 spinner，按钮禁用

### 2.2 `KpiStat.tsx` · 加趋势可视化

- 数字用 `--font-num` + `tabular-nums`
- 增加 `<Sparkline>`（已有 `components/charts/Sparkline.tsx`，复用）作为趋势背景，opacity 0.4
- hover：背景从 `--color-card` 过渡到 `--color-paper-warm`，加 `--shadow-1`
- 趋势箭头：↑/↓ 用 `--color-ok` / `--color-alert`，而非文字色

### 2.3 `GlassPanel.tsx` → 改名 `SurfacePanel.tsx`

- 移除 `backdrop-filter: none`、`box-shadow: none` 的过度抑制
- 新增 `elevation: 1 | 2 | 3` 对应 `--shadow-1/2/3`
- 新增 `tone: 'default' | 'warm' | 'mint' | 'peach'` 4 种浅色背景

### 2.4 新增组件 · `Card.tsx`

```ts
<Card elevation={1} interactive>
  <Card.Header>
    <Card.Title>感知事件</Card.Title>
    <Card.Meta>近 1 小时</Card.Meta>
  </Card.Header>
  <Card.Body>...</Card.Body>
</Card>
```

- `interactive` 时 hover 加 `--shadow-2` + `translate-y-[-1px]`
- 圆角 `--radius-md` (8px)，边框 1px `--color-line`

### 2.5 `HealthGauge.tsx` · 加数值数字

- 中心数字改 `--font-num` + `tabular-nums`
- 数字下加 8px 副标（`已用 / 总量`），替代现在可能的纯环图

### 2.6 `WatchShift.tsx` · 增强值班感

- 在值班轮换时增加 0.3s 渐变（`bg-ok` → `bg-warn`），而非突变
- 当前值班人姓名加印章红 `--color-seal` 下划线（页内**唯一一处**亮色）

---

## 3. 布局 & 信息密度 · 16 个 page 统一

### 3.1 `PageFrame.tsx`（`components/common/`） · 升级

**现状**（推测）：可能只有基础容器。

**新增能力**：
- `<PageFrame>` 增加 `stickyHeader` 模式（页面内副标题 + tab 切换）
- `<PageFrame.Header>` 内置面包屑 + 操作区右侧对齐
- `<PageFrame.Body>` 默认 `gap-6` (24px)，可覆盖

### 3.2 表格统一（影响 `Monitor/Logs/RAG/SecurityAudit` 等）

**当前问题**：从 `Monitor.tsx` 看，大概率直接用 `<div>` 模拟表格，行高不一致，无斑马纹。

**统一规范**：
- 行高 44px（紧凑）或 52px（标准），二选一，**全站统一**
- 斑马纹：`odd:bg-card even:bg-surface/50`（极淡对比）
- hover：`hover:bg-mist`
- sticky header：`sticky top-12 bg-paper/95 backdrop-blur`（TopNav 高度已固定 48px）
- 数字列右对齐 + `tabular-nums`

### 3.3 KPI 网格（影响 `Home/Monitor/Operations/SelfPlay`）

**当前问题**：可能每页自己写 4 列 grid，间距不一致。

**统一规范**：
```tsx
<div className="grid grid-cols-2 md:grid-cols-4 gap-4">
  <KpiStat ... />
</div>
```
- 间距统一 `--space-4` (16px)
- 大屏 (≥1280px) 用 4 列，中屏 2 列，手机 1 列
- 每个 KpiStat 高度统一 112px

---

## 4. 关键页面改造

### 4.1 `Home.tsx` (14.4KB) · Hero 区域 + 能力卡片

**当前**：已经有 `HeroScene` + `ThreatNetwork`（components/hero/），但视觉权重可能不够。

**改造**：
1. Hero 区域用 `--color-paper-warm` 做底，加 1 处印章红 (`--color-seal`) 印章装饰元素（`居中右上角 60×60px`，`opacity: 0.85`）
2. 能力卡片（`capabilities` array, `:16-47`）改用 `<Card interactive>`，hover 提升 + 边框变 `--color-accent`
3. capabilityTiers (`:49-74`) 4 个 tier 改用阶梯式布局，每层左侧 3px `--color-accent` 条
4. pipeline (`:76-82`) 5 步改为带连接的 timeline（细线 + 圆点）

### 4.2 `Monitor.tsx` (17.3KB) · 事件流卡片化

**改造**：
1. 顶部 KPI 4 列用统一网格（§3.3）
2. `EventToolbar`（`components/monitor/`）加 filter chip 化（已用？改成圆角 16px chip，hover 变 `--color-mist`）
3. `EventRow` 加 hover 整行高亮 + 左侧 2px `--color-accent` 出现
4. `ThoughtChainPanel` + `ThoughtDag` 加 `SurfacePanel` 包裹，elevation=2

### 4.3 `Logs.tsx` (13.3KB) · 表格统一

**改造**：套 §3.2 表格规范；右侧详情面板从纯下划线 → `<SurfacePanel>` 滑出。

### 4.4 `SecurityAudit.tsx` (25.6KB) + `Response.tsx` (22.6KB) + `RAG.tsx` (30.6KB)

**改造**：
1. 顶部加 page-level tab 切换（如果还没有），统一用 `<SurfacePanel elevation=1>` 包裹
2. 表格按 §3.2
3. 详情/抽屉统一用 `<CaseDrawer>`（已有 `components/operations/CaseDrawer.tsx`，检查是否可复用）

### 4.5 `Operations.tsx` (4.9KB) · 内部 tab 已有 13 个组件

**改造**：
- 13 个 tab 组件 (`components/operations/`) 内部统一间距
- `OverviewTab`、`KpiTab` 用 §3.3 KPI 网格
- `badges.tsx` 标准化 badge 形态（圆角 `--radius-pill`、5 色对应 5 状态）

### 4.6 `Login.tsx` (3.1KB) + `Register.tsx` (3.2KB)

**改造**：
- 已有 `BrandPanel`（`components/login/`）+ `LoginForm`，统一底色用 `--color-paper-warm`
- 登录卡 `<SurfacePanel elevation=3>` 替代当前 `.mono-card-ink`
- 表单按钮用 `<Button variant="primary" size="md">`

### 4.7 `SelfPlay.tsx` (17.8KB) · 红蓝对抗可视化

**改造**：
- 顶部加 4 列 KPI（红队出招 / 蓝队拦截 / 漏报 / 已修复）
- 红蓝两栏改用对比色块：左侧 `--color-alert/8` 背景，右侧 `--color-ok/8` 背景
- 时间轴用细线 + 红/蓝圆点

---

## 5. 微交互 · `frontend/src/index.css` + 组件

### 5.1 入场动画（替换 `:253-259` 的 `ink-up`）

新增 3 类：
```css
@keyframes fade-up {
  from { opacity: 0; transform: translateY(8px); }
  to { opacity: 1; transform: translateY(0); }
}
@keyframes stagger-in { /* 同 fade-up 但配合 delay */ }
@keyframes mask-reveal {
  from { clip-path: inset(0 100% 0 0); }
  to { clip-path: inset(0 0 0 0); }
}
```

### 5.2 Hover 反馈统一

全站 `<button>` / `<Card interactive>` / `<a>`：
- 默认 → hover：`bg-card` → `bg-paper-warm` 或 `bg-mist`
- 过渡 150ms `cubic-bezier(0.4, 0, 0.2, 1)`
- 卡片 hover：`translateY(-1px) + shadow-2`

### 5.3 加载状态（替换 `App.tsx:26-35` 的 PageLoader）

- 现有：守望 + "加载中" 文字
- 改造：保留品牌文字，但加 8px 圆点节奏动画（`跳动 · 0.6s · stagger 0.15s`）
- 页面内部加载：骨架屏（`Skeleton` 组件，`animate-pulse` 但 opacity 0.5）

### 5.4 状态切换

`ok → warn → alert` 颜色变化统一用 `transition: background-color 0.3s, color 0.3s, border-color 0.3s;`

---

## 6. 响应式 & 可访问性

### 6.1 断点统一

```
sm: 640px   手机横屏
md: 768px   平板
lg: 1024px  小桌面
xl: 1280px  桌面
2xl: 1536px 大桌面
```

`index.css:212-214` 已有 `xl` 断点处理 `page-shell` padding，沿用即可。

### 6.2 移动端

- TopNav 已有汉堡菜单（`TopNav.tsx:147-173`），但建议加遮罩 + 抽屉式（左侧滑入 80% 宽）替代当前下拉
- 表格在 `<md` 改为卡片堆叠（行变 card）

### 6.3 可访问性 · WCAG AA 检查

- 所有正文文字 vs 背景对比度 ≥ 4.5:1
- 大字（≥18px bold 或 ≥24px regular）vs 背景 ≥ 3:1
- 检查 `--color-ink-faint: #8a97a4` vs `--color-card: #fafcfd`（约 3.4:1，**略低于 AA**，需调整到 ≥ 4.5:1）

---

## 7. 改动优先级（分 3 阶段）

### P0 · 设计 Token + 组件基线（5 天）
> 风险低，不动业务逻辑；所有后续优化的地基。

1. `index.css` 加 §1 的新 token（保留旧的，**新增**而不是替换）
2. `Button.tsx` / `Card.tsx` / `SurfacePanel.tsx` 新增组件
3. `KpiStat.tsx` / `HealthGauge.tsx` 升级

### P1 · 关键页面改造（8 天）
1. `Login/Register` —— 改动小、影响所有用户第一印象
2. `Home` —— 营销/门面页
3. `Monitor` —— 高频使用页

### P2 · 全站推广（7 天）
1. `Logs/RAG/SecurityAudit/Response/SelfPlay` 表格统一（§3.2）
2. `Operations` 13 个 tab 内部间距统一
3. 微交互（§5）全站应用
4. 响应式 + 可访问性（§6）

---

## 8. 不要做的事（避免反向踩坑）

1. **不要把"案卷/竖印"命名换掉** —— 这是品牌识别，改名 = 项目定位丢失
2. **不要引入大色块渐变 hero** —— 跟宋体感冲突，会变成"政务 SaaS"
3. **不要把圆角统一到 12px+** —— 失去案卷感，正确做法是**梯度**用 4/8/12
4. **不要引入 emoji / icon-only 按钮作为主导航** —— 跟印章味冲突
5. **不要动后端 API / 数据结构** —— 本方案纯前端
6. **不要一次提交全部改动** —— 按 P0/P1/P2 分 PR，每 PR ≤ 800 行 diff，便于 review

---

## 9. 验收标准

每阶段完成后用以下 4 项自检：

1. **保留性**：浅色基调 + 案卷命名 + 宋体标题 + mono-tone 主色全部保留
2. **新增性**：每页至少 1 处现代视觉信号（阴影/渐变/动效 之一）
3. **一致性**：所有 button、card、input、KPI 视觉形态统一（用 §2 组件库）
4. **可读性**：所有正文文字对比度 ≥ 4.5:1（WebAIM Contrast Checker 验证）

---

**附 · 文件改动清单（粗略行数估计）**

| 文件 | 改动类型 | 估计行数 |
|---|---|---|
| `index.css` | 新增 token + 动画 | +80 / -20 |
| `components/ui/Button.tsx` | 重写 | +60 / -20 |
| `components/ui/Card.tsx` | 新建 | +40 |
| `components/ui/SurfacePanel.tsx` | 改写 | +30 / -15 |
| `components/ui/KpiStat.tsx` | 升级 | +25 / -10 |
| `components/common/PageFrame.tsx` | 升级 | +20 / -5 |
| `pages/Home.tsx` | 局部改 | +60 / -30 |
| `pages/Monitor.tsx` | 局部改 | +80 / -40 |
| `pages/Login.tsx` + `Register.tsx` | 局部改 | +30 / -10 |
| 其他 12 个 page | 表格/间距统一 | +200 / -100 |
| **合计** | | **+625 / -250** |

预计 P0 + P1 完成（约 2 周）后，页面"朴素感"应消失 70% 以上；P2 完成后再消 20%。
