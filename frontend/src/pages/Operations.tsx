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
      <div className="page-shell pt-12 pb-20">
        <header className="mb-8 pb-6 border-b border-line">
          <h1 className="page-title">运营中心</h1>
          <p className="page-sub">
            事件运营闭环 — 告警 → 案例 → 工单 → 审批 → 处置 → 复盘 → 误报反馈 → 规则优化
          </p>
        </header>

        <div className="flex flex-wrap gap-2 mb-8">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={activeTab === tab.id ? tabOn : tabOff}
            >
              {tab.label}
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
