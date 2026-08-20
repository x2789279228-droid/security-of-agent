import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { PageTransition } from '../components/common/PageTransition'
import { spring, AI_GRADIENT } from '../lib/constants'
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
      <div className="max-w-[1200px] mx-auto px-6 pt-12 pb-20">
        {/* 页头 */}
        <header className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-4xl font-extrabold tracking-tight text-ink">运营中心</h1>
            <span
              className="hidden sm:inline-block h-[3px] w-16 rounded-full mt-1.5"
              style={{ backgroundImage: AI_GRADIENT }}
            />
          </div>
          <p className="text-[15px] text-ink-soft">
            事件运营闭环 — 告警 → 案例 → 工单 → 审批 → 处置 → 复盘 → 误报反馈 → 规则优化
          </p>
        </header>

        {/* Tab 栏 — Apple 分段控件 */}
        <div className="flex gap-1 mb-8 p-1 bg-black/[0.05] rounded-full w-fit overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`relative px-5 py-2 text-[13px] font-medium rounded-full transition-all whitespace-nowrap ${
                activeTab === tab.id ? 'text-ink' : 'text-ink-soft hover:text-ink'
              }`}
            >
              {activeTab === tab.id && (
                <motion.span
                  layoutId="ops-tab-pill"
                  className="absolute inset-0 bg-white rounded-full shadow-[0_1px_4px_rgba(0,0,0,0.1)]"
                  transition={spring.stiff}
                />
              )}
              <span className="relative z-10">{tab.label}</span>
            </button>
          ))}
        </div>

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
