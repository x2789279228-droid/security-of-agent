import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { spring } from '../lib/constants'
import { tabOn, tabOff } from '../components/common/PageFrame'
import { OverviewTab } from '../components/operations/OverviewTab'
import { CasesTab } from '../components/operations/CasesTab'
import { WorkOrdersTab } from '../components/operations/WorkOrdersTab'
import { PostMortemsTab } from '../components/operations/PostMortemsTab'
import { FeedbackTab } from '../components/operations/FeedbackTab'
import { RulesTab } from '../components/operations/RulesTab'
import { AssetsTab } from '../components/operations/AssetsTab'
import { KpiTab } from '../components/operations/KpiTab'
import { AuditTrailTab } from '../components/operations/AuditTrailTab'
import { CostTab } from '../components/operations/CostTab'
import { TraceTab } from '../components/operations/TraceTab'

type Tab = 'overview' | 'cases' | 'orders' | 'postmortems' | 'feedback' | 'rules' | 'assets' | 'kpi' | 'audit-trail' | 'cost' | 'traces'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: '概览' },
  { id: 'cases', label: '案例' },
  { id: 'orders', label: '工单' },
  { id: 'postmortems', label: '复盘' },
  { id: 'feedback', label: '反馈调优' },
  { id: 'rules', label: '规则' },
  { id: 'assets', label: '资产' },
  { id: 'kpi', label: 'KPI' },
  { id: 'cost', label: 'Token 成本' },
  { id: 'audit-trail', label: '审计 trail' },
  { id: 'traces', label: '链路追踪' },
]

export default function Operations() {
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  return (
    <PageTransition>
      <div className="page-shell pt-4 pb-12">
        <header className="flex flex-col gap-2 border-b border-line pb-3 md:flex-row md:items-end md:justify-between">
          <div className="min-w-0 md:max-w-[44rem]">
            <h1 className="font-serif text-[28px] font-black tracking-[-0.04em] text-ink leading-[1.1]">
              运营中心
            </h1>
            <p className="mt-1 text-[13px] leading-snug text-ink-soft">
              事件运营闭环 — 告警 → 案例 → 工单 → 审批 → 处置 → 复盘 → 误报反馈 → 规则优化。
            </p>
            <p className="mt-1 hidden font-serif italic text-[12px] leading-snug text-ink-faint/80 md:block">
              <span aria-hidden className="mr-1 text-[#c9a574]/70">¶</span>
              ——运营让系统与现实对齐。
            </p>
          </div>
        </header>

        <nav className="mt-4 mb-5 flex flex-wrap gap-x-6 gap-y-3 border-b border-line">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={activeTab === tab.id ? tabOn : tabOff}
            >
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Tab 内容 */}
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -12 }}
            transition={spring.page}
          >
            {activeTab === 'overview' && <OverviewTab onNavigate={(t) => setActiveTab(t as Tab)} />}
            {activeTab === 'cases' && <CasesTab />}
            {activeTab === 'orders' && <WorkOrdersTab />}
            {activeTab === 'postmortems' && <PostMortemsTab />}
            {activeTab === 'feedback' && <FeedbackTab />}
            {activeTab === 'rules' && <RulesTab />}
            {activeTab === 'assets' && <AssetsTab />}
            {activeTab === 'kpi' && <KpiTab />}
            {activeTab === 'cost' && <CostTab />}
            {activeTab === 'audit-trail' && <AuditTrailTab />}
            {activeTab === 'traces' && <TraceTab />}
          </motion.div>
        </AnimatePresence>
      </div>
    </PageTransition>
  )
}
