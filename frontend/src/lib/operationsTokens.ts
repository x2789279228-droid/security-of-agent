import { BRAND_COLORS } from './brand'

/**
 * 守望运营中心语义 token — 把所有运营态（严重度/状态/动作/关键性）映射到品牌色
 * 取代原先散落在 8 个 Tab 文件里的 iOS 系统色（#0A84FF/#FF375F/#BF5AF2/#FF9F0A/#34c759）
 * 白昼台账色位：暮青(accent) / 松绿(ok) / 柿黄(warn) / 朱砂(alert) / 灰青(signal) / 黛墨中性(faint)
 *
 * 用法：import { SEVERITY_TONE } from '@/lib/operationsTokens'
 *      <span style={{ color: SEVERITY_TONE.critical }} />
 *
 * 也提供完整 { fg, bg, ring } 三元组，便于直接渲染 chip（参考 badges.tsx 的 chip helper）
 */

const INK_FAINT = '#8A97A4' // = ink-faint（浅色账页上的弱标签 / 中性态）
const TRACK = '#E6ECF0'      // = mist（浅色条形图 / 进度条空底轨道）

/* ── 严重度 5 档 ── */
export const SEVERITY_TONE = {
  critical: BRAND_COLORS.alert, // 朱砂
  high: BRAND_COLORS.warn,      // 柿黄
  medium: BRAND_COLORS.signal,  // 灰青
  low: INK_FAINT,
  info: INK_FAINT,
} as const

/* ── 状态语义 5 档 ── */
export const STATUS_TONE = {
  success: BRAND_COLORS.ok,       // 松绿
  pending: BRAND_COLORS.warn,     // 柿黄
  failed: BRAND_COLORS.alert,     // 朱砂
  info: BRAND_COLORS.accent,      // 暮青
  neutral: INK_FAINT,
  active: BRAND_COLORS.signal,    // 灰青
} as const

/* ── chip 形态三元组 ── */
export function chipTone(hex: string, bgA = '1f', ringA = '4d') {
  return { fg: hex, bg: `${hex}${bgA}`, ring: `${hex}${ringA}` }
}

/* ── 案例状态 7 档 ── */
export const CASE_STATUS_TONE: Record<string, { label: string; color: string }> = {
  open: { label: '待处理', color: BRAND_COLORS.alert },
  investigating: { label: '调查中', color: BRAND_COLORS.signal },
  pending_approval: { label: '待审批', color: BRAND_COLORS.warn },
  responding: { label: '处置中', color: BRAND_COLORS.accent },
  resolved: { label: '已解决', color: BRAND_COLORS.accent },
  closed: { label: '已关闭', color: INK_FAINT },
  false_positive: { label: '误报', color: INK_FAINT },
}

/* ── 审计 trail 14 种 action 配色 ── */
export const ACTION_TONE: Record<string, string> = {
  'case.transition': BRAND_COLORS.accent,
  'case.assign': BRAND_COLORS.signal,
  'case.disposition': BRAND_COLORS.signal,
  'order.approve': BRAND_COLORS.ok,
  'order.reject': BRAND_COLORS.alert,
  'rule.publish': BRAND_COLORS.signal,
  'rule.rollback': BRAND_COLORS.warn,
  'asset.create': BRAND_COLORS.accent,
  'asset.update': BRAND_COLORS.signal,
  'asset.decommission': INK_FAINT,
  'source.register': BRAND_COLORS.accent,
  'source.revoke': BRAND_COLORS.alert,
}

/* ── 学习闭环状态 5 档 ── */
export const LEARN_STATUS_TONE: Record<string, { label: string; color: string }> = {
  proposed: { label: '待复核', color: BRAND_COLORS.warn },
  auto_applied: { label: '自动应用', color: BRAND_COLORS.ok },
  applied: { label: '已应用', color: BRAND_COLORS.accent },
  dismissed: { label: '已驳回', color: INK_FAINT },
  rolled_back: { label: '已回滚', color: BRAND_COLORS.signal },
}

/* ── 资产关键性 4 档（含背景色 + 中文标签）── */
export const CRITICALITY_TONE: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: BRAND_COLORS.alert, bg: `${BRAND_COLORS.alert}1a`, label: '核心' },
  high: { color: BRAND_COLORS.warn, bg: `${BRAND_COLORS.warn}1f`, label: '重要' },
  medium: { color: BRAND_COLORS.signal, bg: `${BRAND_COLORS.signal}1a`, label: '一般' },
  low: { color: INK_FAINT, bg: `${INK_FAINT}1a`, label: '低' },
}

/* ── KPI 卡片 6 张 ── */
export const KPI_TONE = {
  mttr: BRAND_COLORS.warn,            // MTTR 偏高则警示 → 柿黄
  mttd: BRAND_COLORS.accent,          // MTTD 中性的检测时间 → 暮青
  case_count: BRAND_COLORS.signal,    // 案例数 → 灰青（信息）
  fp_rate: BRAND_COLORS.signal,       // 误报率 → 灰青（注意力）
  sla_breach_rate: BRAND_COLORS.alert, // SLA 违约率 → 朱砂（警告）
  order_count: BRAND_COLORS.ok,       // 工单数 → 松绿（正常）
} as const

/* ── CostTab 6 张卡片（含动态 danger 切换）── */
export const COST_TONE = {
  todayUsage: BRAND_COLORS.accent,    // 今日用量 → 暮青
  dailyBudget: BRAND_COLORS.signal,   // 日预算 → 灰青
  remaining: BRAND_COLORS.ok,         // 剩余预算 → 松绿
  windowUsage: BRAND_COLORS.warn,     // 窗口用量 → 柿黄
  estimatedCost: BRAND_COLORS.signal, // 估算费用 → 灰青
  cacheHit: BRAND_COLORS.accent,      // 缓存命中 → 暮青
} as const

/* ── FeedbackTab 4 类计数 ── */
export const FEEDBACK_COUNT_TONE = {
  false_positive: BRAND_COLORS.alert,
  true_positive: BRAND_COLORS.ok,
  missed_threat: BRAND_COLORS.warn,
  rule_suggestion: BRAND_COLORS.accent,
} as const

/* ── OverviewTab 5 个指标卡 ── */
export const OVERVIEW_METRIC_TONE = {
  openCases: BRAND_COLORS.signal,     // 待处理案例 — 灰青（信息）
  slaBreached: BRAND_COLORS.alert,    // SLA 超时 — 朱砂
  fpRate: BRAND_COLORS.signal,        // 误报率 — 灰青（注意力）
  activeOrders: BRAND_COLORS.warn,    // 活跃工单 — 柿黄（待处理）
  pendingApprovals: BRAND_COLORS.accent, // 待审批 — 暮青（信息）
} as const

/* ── 时间线节点色（CaseDrawer / OverviewTab）── */
export const TIMELINE_NODE = {
  response: BRAND_COLORS.signal, // 响应 → 灰青
  other: BRAND_COLORS.accent,    // 其他 → 暮青
} as const

/* ── 图表渐变（暮青 → 灰青 → 松绿，无金）── */
export const CHART_GRADIENT =
  'linear-gradient(120deg, #3A6570 0%, #4A7A88 42%, #3E7A64 100%)'

export const CHART_GRADIENT_DIVERGING =
  'linear-gradient(90deg, #3E7A64 0%, #C08A3A 50%, #C23A32 100%)'

/** KpiTab/CostTab 单色折线（≥0 用品牌渐变，=0 用空底色） */
export const BAR_FILL_EMPTY = TRACK

/* ── 通用 token（语义 + 数值）── */
export { INK_FAINT, TRACK }

/** OverviewTab 实时活动流的竖向渐变线 */
export const ACTIVITY_LINE_GRADIENT = CHART_GRADIENT

/** 反馈类型计数（误报/确认/漏报/建议） — 同 FEEDBACK_COUNT_TONE，保留别名方便阅读 */
export const FEEDBACK_TONE = FEEDBACK_COUNT_TONE
