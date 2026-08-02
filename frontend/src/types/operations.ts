export type CaseStatus =
  | 'open'
  | 'investigating'
  | 'pending_approval'
  | 'responding'
  | 'resolved'
  | 'closed'
  | 'false_positive'

export type CasePriority = 'critical' | 'high' | 'medium' | 'low'

export interface SecurityCase {
  id: number
  case_number: string
  title: string
  status: CaseStatus
  priority: CasePriority
  threat_type: string
  severity: string
  confidence: number
  src_ips: string[]
  dst_ips: string[]
  event_ids: number[]
  event_count: number
  assignee: string
  sla_deadline: string | null
  disposition: string
  disposition_by: string
  tags: string[]
  created_at: string
  updated_at: string
  closed_at: string | null
}

export type OrderType = 'disposition' | 'approval' | 'review' | 'rollback'
export type OrderStatus = 'pending' | 'assigned' | 'in_progress' | 'completed' | 'cancelled'

export interface WorkOrder {
  id: number
  order_number: string
  case_id: number | null
  order_type: OrderType
  title: string
  description: string
  status: OrderStatus
  priority: string
  assignee: string
  created_by: string
  approval_status: string
  approved_by: string
  reject_reason: string
  sla_deadline: string | null
  sla_breached: boolean
  result: Record<string, unknown>
  created_at: string
  completed_at: string | null
}

export interface TimelineEntry {
  time: string
  type: 'event' | 'response'
  detail: string
  event_id?: number
  status?: string
  action?: string
}

export interface PostMortem {
  id: number
  case_id: number
  title: string
  summary: string
  timeline: { time: string; event: string; detail: string }[]
  root_cause: string
  impact_assessment: string
  lessons_learned: string[]
  action_items: { item: string; owner: string; deadline: string; done: boolean }[]
  false_positive_count: number
  detection_gaps: string
  rule_improvements: { rule_id: string; suggestion: string }[]
  author: string
  reviewer: string
  status: 'draft' | 'reviewed' | 'published'
  created_at: string
  updated_at: string
}

export type FeedbackType =
  | 'false_positive'
  | 'true_positive'
  | 'missed_threat'
  | 'rule_suggestion'

export interface FeedbackRecord {
  id: number
  event_id: number | null
  case_id: number | null
  feedback_type: FeedbackType
  original_conclusion: string
  operator_conclusion: string
  reason: string
  rule_id: string
  rule_suggestion: string
  submitted_by: string
  status: 'submitted' | 'reviewed' | 'applied' | 'dismissed'
  created_at: string
}

export interface FpStats {
  period_days: number
  total_feedback: number
  false_positive: number
  true_positive: number
  missed_threat: number
  rule_suggestion: number
  overall_fp_rate: number
  by_rule: Record<string, { total: number; false_positive: number; true_positive: number; fp_rate: number }>
}

export interface TuningSuggestion {
  type: 'high_fp_rate' | 'missed_threats' | 'user_suggestion'
  severity: string
  rule_id?: string
  fp_rate?: number
  total_feedback?: number
  count?: number
  suggestion: string
  actions?: string[]
  details?: { reason: string; rule_suggestion: string }[]
  feedback_id?: number
  submitted_by?: string
}

export interface SigmaRule {
  rule_id: string
  name: string
  description: string
  severity: string
  attack_type: string
  confidence: string
  action_recommend: string
  conditions?: Record<string, unknown>
  type?: string
}

export interface RuleVersion {
  id: number
  version: number
  change_summary: string
  changed_by: string
  is_active: boolean
  created_at: string
}

export interface SandboxResult {
  total_tested: number
  hit_count: number
  hit_rate: number
  false_positive_count: number
  fp_rate: number
  elapsed_ms: number
  hits: { event_id: number; event_type: string; src_ip: string; severity: string; status: string }[]
}
