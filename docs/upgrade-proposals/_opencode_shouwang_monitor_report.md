# OpenCode · 守望 Monitor / ThreatNetwork 落地报告

Scope: `docs/upgrade-proposals/2026-q3-frontend-shouwang.md`（契约）。Grok 的 tokens/primitives 未动，Home/Login/Nav、`index.css`、`package.json`、`eventStream.ts`、`layouts/**`、`backend/**` 均未触碰。

## 1. Files changed

| 文件 | 变更 |
|---|---|
| `frontend/src/pages/Monitor.tsx` | 服务卡 + KPI 带 + 页头 LiveBadge + 玻璃容器化（业务逻辑零改动） |
| `frontend/src/components/monitor/StreamStatusBar.tsx` | 状态音色重制 |
| `frontend/src/components/monitor/AgentRelayStrip.tsx` | 节点三态 + 磷光/朱砂数据包 |
| `frontend/src/components/monitor/PipelineStrip.tsx` | 节点玻璃化 + 磷光数据包 |
| `frontend/src/components/monitor/RateHistogram.tsx` | recharts BarChart 重写 |
| `frontend/src/components/monitor/ActiveRelayCards.tsx` | 卡片玻璃化 + 阶段格三色 |
| `frontend/src/components/monitor/ThoughtNode.tsx` / `ThoughtDag.tsx` | 状态音色 + 连线颜色 |
| `frontend/src/components/monitor/EventToolbar.tsx` | glass 输入 + accent 焦点 |
| `frontend/src/components/monitor/EventRow.tsx` | 仅 chrome：展开 JSON `bg-white → bg-card`（虚拟化/memo 未动） |
| `frontend/src/components/monitor/ToolAnomalyBanner.tsx` | 朱砂边框/辉光 + 脉冲点 |
| `frontend/src/components/monitor/ThoughtChainPanel.tsx` / `EvidenceHeatLinks.tsx` | 玻璃 chrome、注意力条改磷光 |
| `frontend/src/components/monitor/ToolSignaturePanel.tsx` | 白卡残留清理（bg-white → bg-card、border-ink → accent/alert 音色） |
| `frontend/src/components/hero/ThreatNetwork.tsx` | WebGL 全量重制（见 §3） |
| `frontend/src/components/hero/ParticleField.tsx` | 仅颜色：`#4a6cf7 → #5B8DEF`(signal) + AdditiveBlending |
| `frontend/src/components/hero/HeroScene.tsx` | 仅底色：白渐变 → `from-[#0C1522] to-night` |

未新增依赖：辉光用 AdditiveBlending + instanced glow 球实现（未引入 @react-three/postprocessing）；drei 的 `OrbitControls` / `Stars` 已在依赖树内。

## 2. Monitor 信息层级（0.1s 扫描）

- **裂口数字（hero）**：`待处理 > 0 → KpiStat tone="hero"`（44–52px 朱砂 + kpi-hero-glow + LIVE 徽标，占 2 列）；`= 0 → tone="ok"`。是该视图唯一的焦点数字。
- **待处理 sparkline**：组件内真实滚动缓冲（`pendingSparkRef`，≤24 点，每次 stats 节流刷新推入真实样本）；首帧用当前值播种 11 个平滑合成点（正弦微扰，代码内有注释说明），后续全被真实样本覆盖。
- 其余 KPI：已分析 → ok；安全事件 → neutral；记忆树节点 / Redis Keys → neutral + 缩小内边距（quieter）。全部走 `KpiStat`，不再有裸整数。
- **服务卡**（pgvector / Redis / LLM）：`rounded-xl bg-card/80` + 左缘 3px 音色调条（磷光/琥珀/朱砂带自发光）+ `HealthGauge` 中心脉冲点 + 标签随健康度着色（正常=磷光、告警=琥珀、异常=朱砂）。健康与异常一眼可辨，且三张卡不再同款。
- 页头 `extra` 槽：`LiveBadge` 绑定 `useEventStreamStore.status`（LIVE / 连接中 / 重连中 / 离线 / 未连接）。
- 所有 `border border-line bg-white` 包装 → 玻璃 / `bg-card` rounded-xl；演示按钮 → 磷光 primary；恢复推送按钮 → 圆形磷光徽标。react-window List、筛选、SSE、演示 ingest、思维链选择逻辑原样保留。

## 3. StreamStatusBar / 接力条 / 直方图

- **StreamStatusBar**：online = 磷光 LIVE（ping 圆点 + 发光，不再用 bg-ink 表示"已连接"）；reconnecting/connecting = 琥珀脉冲；offline = 朱砂脉冲；idle = 暗色。控制按钮玻璃化、hover 走 accent。
- **AgentRelayStrip**：节点三态 — 进行中/active = 磷光边框 + 发光 + 磷光数字；有错 = 朱砂；空闲 = 暗淡 `bg-mist/40 opacity-75`。数据包磷光发光、`status==='error'` 时朱砂。节点脉冲叠层 `bg-accent/25`。
- **PipelineStrip**：同款玻璃节点 + 磷光数据包（该组件当前未被 Monitor 引用，保留并同步换肤）。
- **RateHistogram**：recharts `BarChart`（12 × 5s 分桶逻辑与 1s 采样原样保留），磷光柱（最新桶满亮）、夜幕 `bg-night/95` tooltip、`cursor` 磷光微光；`-60s / 现在` 轴标与 `N/30s` 摘要保留。

## 4. ThreatNetwork — WebGL 重制（保持 attackCount API）

- 夜幕画布：容器 `bg-night` + Canvas alpha，`fog(#070B12, 13, 26)` 提供纵深。
- 节点：磷光 `#2AF4C4` 基色（亮度随机插值），**按图度数定标**（枢纽更大更亮，非全员同款）；外层 **3.6× 加法混合辉光球**（AdditiveBlending, opacity 0.13, depthWrite off）+ 正弦呼吸。
- 脉冲：正常 = 磷光加法混合；攻击 = `#FF3D4A`、约 2.3× 大小；`attackCount` 变化注入 **4 发**连发（原 3 发），命中点亮目标节点（节点与辉光同时转朱砂并放大 2.4×）。
- 连线：磷光 `opacity 0.25`；攻击能量抬升至最高 0.6 并随时间衰减（攻击时网线整体"发亮"）。
- 交互：drei `OrbitControls`（autoRotate 0.4、damping、禁 pan、min/maxDistance 7–18），自转交给相机（移除原 group 自转避免双重旋转）；`Stars`(1400) 星场纵深。
- 高度 ≥ 360px（`h-[360px] lg:h-[440px]`）+ HUD（威胁态势 · THREAT NETWORK / 拖拽提示，pointer-events-none）。
- **WebGL 兜底**：`CanvasGuard`（React error boundary）捕获 Canvas 抛错，降级为文案占位，不阻断监控。

## 5. 验证结果

- `cd frontend && npx tsc -b --pretty false` → **0 错误**（含 recharts v3 自定义 Tooltip、drei OrbitControls 类型）。
- `npm run test:pipeline` → **5/5 pass**（未触碰 agentPipeline 业务逻辑）。
- `oxlint` 仅既有模式的 warning（场景构建器内 Math.random、effect 内 setState），无新增错误。

## 6. Leftover risks

1. **SSE 严重度章未换色**：`EVENT_META / SEVERITY_META`（eventStream.ts，另一 agent 负责）仍是灰阶 badge——EventRow 的 critical 徽标依旧 `bg-ink`。等对方落地后 0.1s 扫描在行级才完全成立。
2. **待处理 sparkline 首帧合成**：首屏 11 个点是形状播种（已注释），连续真实样本需等待 stats 轮询节奏（≥2s/次）。
3. **Home 对 ThreatNetwork 的包裹**：组件自带 360/440px 高度与圆角边框，Home 若再包一层需确认不产生双框（Home 文件归另一 agent，未动）。
4. **辉光性能**：56 节点 × 每帧实例矩阵/颜色更新 + Stars，低端核显 dpr 上限 2；未加 postprocessing bloom，若日后上 `@react-three/postprocessing` 需评估移动端。
5. **PipelineStrip 未被 Monitor 引用**：已同步换肤但仍是孤儿组件，后续若复用请直接取用。
