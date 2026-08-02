const BASE = '/api'

function authHeaders(): Record<string, string> {
  const token = localStorage.getItem('sm_token')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    ...init,
  })
  if (res.status === 401) {
    localStorage.removeItem('sm_token')
    localStorage.removeItem('sm_user')
    window.location.href = '/login'
    throw new Error('认证已过期，请重新登录')
  }
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`)
  return res.json()
}

export const api = {
  login: (username: string, password: string) =>
    fetchJSON<{ access_token: string; token_type: string }>(
      `/auth/login?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
      { method: 'POST' },
    ),

  health: () => fetchJSON<{ status: string }>('/health'),

  stats: () => fetchJSON<any>('/stats'),

  /** 获取安全事件日志（按时间倒序） */
  logsEvents: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any[]>(`/logs/events${qs ? `?${qs}` : ''}`)
  },

  window: (sessionId: string) =>
    fetchJSON<any>(`/window/${sessionId}`),

  treeStats: () => fetchJSON<any>('/tree/stats'),
  treeNodes: () => fetchJSON<any[]>('/tree/nodes'),

  serviceStatus: () => fetchJSON<any>('/health'),

  // ── 安全审计端点 ──

  /** 注入单条安全日志 → 自动触发 Audit-LLM */
  ingestLog: (event: Record<string, any>, sessionId?: string) =>
    fetchJSON<any>('/logs/ingest', {
      method: 'POST',
      body: JSON.stringify({ message: event, session_id: sessionId || '' }),
    }),

  /** 批量注入 */
  ingestBatch: (logs: Record<string, any>[], sessionId?: string) =>
    fetchJSON<any>('/logs/ingest/batch', {
      method: 'POST',
      body: JSON.stringify({ logs, session_id: sessionId || '' }),
    }),

  /** 获取 Audit-LLM 流水线结果 */
  getPipeline: (eventId: number) =>
    fetchJSON<any>(`/audit-llm/pipeline/${eventId}`),

  /** 获取证据链追溯 */
  getEvidence: (eventId: number) =>
    fetchJSON<any>(`/audit-llm/evidence/${eventId}`),

  /** Audit-LLM 统计 */
  getAuditStats: () =>
    fetchJSON<any>('/audit-llm/stats'),

  /** 手动触发完整流水线 */
  runAuditLLM: (event: Record<string, any>) =>
    fetchJSON<any>('/audit-llm/run', {
      method: 'POST',
      body: JSON.stringify({ event }),
    }),

  // ── 安全事件查询 ──

  getAnomalies: (sessionId: string, minScore = 0.5) =>
    fetchJSON<any[]>(`/security/anomalies?session_id=${sessionId}&min_score=${minScore}`),

  getChains: (sessionId: string) =>
    fetchJSON<any>(`/security/chains?session_id=${sessionId}`),

  getEvents: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any[]>(`/security/events?${qs}`)
  },

  getEventDetail: (eventId: number) =>
    fetchJSON<any>(`/security/events/${eventId}`),

  // ── CAD 审计角色端点 ──

  getCadStatus: () =>
    fetchJSON<any>('/cad/status'),

  getCircuitBreaker: () =>
    fetchJSON<any>('/cad/circuit-breaker'),

  resetCircuitBreaker: () =>
    fetchJSON<any>('/cad/circuit-breaker/reset', { method: 'POST' }),

  triggerContextAudit: () =>
    fetchJSON<any>('/cad/audit-context', { method: 'POST' }),

  getCadVerification: (eventId: number) =>
    fetchJSON<any>(`/cad/verification/${eventId}`),

  // ── 响应引擎端点 ──

  /** 模拟威胁事件触发响应 */
  simulateThreat: (threat: Record<string, any>) =>
    fetchJSON<any>('/response/simulate', {
      method: 'POST',
      body: JSON.stringify(threat),
    }),

  /** 获取所有响应策略 */
  getResponsePolicies: () =>
    fetchJSON<any[]>('/response/policies'),

  /** 更新响应策略 */
  updateResponsePolicy: (policy: Record<string, any>) =>
    fetchJSON<any>('/response/policies', {
      method: 'PUT',
      body: JSON.stringify(policy),
    }),

  /** 获取所有可用响应动作 */
  getResponseActions: () =>
    fetchJSON<any[]>('/response/actions'),

  /** 手动执行响应动作 */
  executeResponse: (actionName: string, srcIp: string, reason: string) =>
    fetchJSON<any>(`/response/execute?action_name=${actionName}&src_ip=${srcIp}&reason=${encodeURIComponent(reason)}`, {
      method: 'POST',
    }),

  /** 回滚响应 */
  rollbackResponse: (token: string) =>
    fetchJSON<any>(`/response/rollback?rollback_token=${token}`, {
      method: 'POST',
    }),

  /** 获取审批队列 */
  getApprovals: (pendingOnly = false) =>
    fetchJSON<any[]>(`/response/approvals?pending_only=${pendingOnly}`),

  /** 批准工单 */
  approveTicket: (ticketId: string, approvedBy = 'admin') =>
    fetchJSON<any>(`/response/approvals/${ticketId}/approve?approved_by=${approvedBy}`, {
      method: 'POST',
    }),

  /** 拒绝工单 */
  rejectTicket: (ticketId: string, reason = '') =>
    fetchJSON<any>(`/response/approvals/${ticketId}/reject?reason=${encodeURIComponent(reason)}`, {
      method: 'POST',
    }),

  /** 查询响应日志 */
  getResponseLogs: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any[]>(`/response/logs?${qs}`)
  },

  /** 清除策略冷却 */
  clearCooldowns: () =>
    fetchJSON<any>('/response/clear-cooldowns', { method: 'POST' }),

  // ── RAG 知识库端点 ──

  /** 搜索知识库 */
  ragSearch: (params: Record<string, any>) =>
    fetchJSON<any>('/rag/search', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  /** 获取知识库统计 */
  ragStats: () =>
    fetchJSON<any>('/rag/stats'),

  /** 获取知识文档列表 */
  ragDocuments: (threatType = '', source = '') =>
    fetchJSON<any>(`/rag/documents?threat_type=${threatType}&source=${source}`),

  /** 获取知识文档详情 */
  ragDocument: (docId: number) =>
    fetchJSON<any>(`/rag/documents/${docId}`),

  /** 删除知识文档 */
  ragDeleteDocument: (docId: number) =>
    fetchJSON<any>(`/rag/documents/${docId}`, { method: 'DELETE' }),

  /** 添加知识文档 */
  ragAddDocument: (doc: Record<string, any>) =>
    fetchJSON<any>('/rag/documents', {
      method: 'POST',
      body: JSON.stringify(doc),
    }),

  /** 验证断言 */
  ragVerify: (params: Record<string, any>) =>
    fetchJSON<any>('/rag/verify', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  /** 重新播种知识库 */
  ragReseed: () =>
    fetchJSON<any>('/rag/reseed', { method: 'POST' }),

  /** 导入 MITRE ATT&CK 完整知识库 */
  ragImportMITRE: (limit = 0) =>
    fetchJSON<any>(`/rag/import/mitre?limit=${limit}`, { method: 'POST' }),

  /** 导入 CAPEC 完整攻击模式库 */
  ragImportCAPEC: (limit = 0) =>
    fetchJSON<any>(`/rag/import/capec?limit=${limit}`, { method: 'POST' }),

  /** 导入所有 MITRE 知识库 */
  ragImportAll: () =>
    fetchJSON<any>('/rag/import/all', { method: 'POST' }),

  /** 查询导入进度 */
  ragImportStatus: () =>
    fetchJSON<any>('/rag/import/status'),

  // ── 质量评估 ──

  /** 评估一次 RAG 检索质量 */
  evalRag: (params: { query: string; contexts: any[]; ground_truth?: string; retrieval_strategy?: string }) =>
    fetchJSON<any>('/eval/rag', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  /** 对真实知识库检索做自动质量评估 */
  evalRagAuto: (params: { query: string; threat_type?: string; severity?: string; top_k?: number; ground_truth?: string }) =>
    fetchJSON<any>('/eval/rag/auto', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  /** 评估回答忠实度 */
  evalFaithfulness: (params: { answer: string; contexts: any[]; query?: string }) =>
    fetchJSON<any>('/eval/faithfulness', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  /** 评估运行列表 */
  evalRuns: (runType = '', limit = 50) =>
    fetchJSON<any[]>(`/eval/runs?run_type=${encodeURIComponent(runType)}&limit=${limit}`),

  /** 评估聚合报告 */
  evalReport: (runType = '', limit = 200) =>
    fetchJSON<any>(`/eval/report?run_type=${encodeURIComponent(runType)}&limit=${limit}`),

  // ── Agent 轨迹 ──

  /** 查询 LLM 轨迹 */
  agentTraces: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any>(`/agent-traces${qs ? `?${qs}` : ''}`)
  },

  /** 轨迹聚合统计 */
  agentTraceStats: () =>
    fetchJSON<any>('/agent-traces/stats'),

  /** 获取最近实时事件 */
  eventsRecent: (limit = 50) =>
    fetchJSON<any[]>(`/events/recent?limit=${limit}`),

  /** 创建 SSE 事件流连接 */
  eventsStream: () => {
    const token = localStorage.getItem('sm_token')
    const url = `${BASE}/events/stream${token ? `?token=${token}` : ''}`
    return new EventSource(url)
  },

  // ── 钓鱼检测端点 ──

  phishingDetectEmail: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/email', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDetectWeb: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/web', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDetectDomain: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/domain', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingStats: () =>
    fetchJSON<any>('/phishing/stats'),

  phishingHistory: (limit = 10) =>
    fetchJSON<any[]>(`/phishing/history?limit=${limit}`),

  phishingDetectAttachment: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/attachment', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDetectSms: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/sms', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDetectQrcode: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/qrcode', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDetectBec: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/detect/bec', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  // ── 钓鱼演练端点 ──

  phishingDrillCreate: (data: Record<string, any>) =>
    fetchJSON<any>('/phishing/drill', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  phishingDrillList: (status = '') =>
    fetchJSON<any[]>(`/phishing/drill${status ? `?status=${status}` : ''}`),

  phishingDrillGet: (id: number) =>
    fetchJSON<any>(`/phishing/drill/${id}`),

  phishingDrillDelete: (id: number) =>
    fetchJSON<any>(`/phishing/drill/${id}`, { method: 'DELETE' }),

  phishingDrillLaunch: (id: number, targets: string[]) =>
    fetchJSON<any>(`/phishing/drill/${id}/launch`, {
      method: 'POST',
      body: JSON.stringify({ targets }),
    }),

  phishingDrillRecord: (id: number, targetIdentifier: string, eventType: string) =>
    fetchJSON<any>(`/phishing/drill/${id}/record`, {
      method: 'POST',
      body: JSON.stringify({ target_identifier: targetIdentifier, event_type: eventType }),
    }),

  // ── 事件运营闭环端点 ──

  /** 案例列表 */
  opsCases: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any[]>(`/cases${qs ? `?${qs}` : ''}`)
  },

  /** 创建案例 */
  opsCreateCase: (data: Record<string, any>) =>
    fetchJSON<any>('/cases', { method: 'POST', body: JSON.stringify(data) }),

  /** 案例详情 */
  opsCase: (caseId: number) => fetchJSON<any>(`/cases/${caseId}`),

  /** 案例状态流转 */
  opsCaseStatus: (caseId: number, status: string, by = 'admin') =>
    fetchJSON<any>(`/cases/${caseId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status, by }),
    }),

  /** 指派案例 */
  opsCaseAssign: (caseId: number, assignee: string) =>
    fetchJSON<any>(`/cases/${caseId}/assign`, {
      method: 'PUT',
      body: JSON.stringify({ assignee }),
    }),

  /** 写入处置结论 */
  opsCaseDisposition: (caseId: number, disposition: string, by = 'admin') =>
    fetchJSON<any>(`/cases/${caseId}/disposition`, {
      method: 'PUT',
      body: JSON.stringify({ disposition, by }),
    }),

  /** 案例时间线 */
  opsCaseTimeline: (caseId: number) => fetchJSON<any[]>(`/cases/${caseId}/timeline`),

  /** 工单列表 */
  opsWorkOrders: (params: Record<string, string> = {}) => {
    const qs = new URLSearchParams(params).toString()
    return fetchJSON<any[]>(`/work-orders${qs ? `?${qs}` : ''}`)
  },

  /** 创建工单 */
  opsCreateWorkOrder: (data: Record<string, any>) =>
    fetchJSON<any>('/work-orders', { method: 'POST', body: JSON.stringify(data) }),

  /** 更新工单状态 */
  opsWorkOrderStatus: (orderId: number, status: string) =>
    fetchJSON<any>(`/work-orders/${orderId}/status`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    }),

  /** 审批通过 */
  opsWorkOrderApprove: (orderId: number, approvedBy = 'admin') =>
    fetchJSON<any>(`/work-orders/${orderId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved_by: approvedBy }),
    }),

  /** 审批拒绝 */
  opsWorkOrderReject: (orderId: number, reason = '', rejectedBy = 'admin') =>
    fetchJSON<any>(`/work-orders/${orderId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason, rejected_by: rejectedBy }),
    }),

  /** 创建复盘 */
  opsCreatePostMortem: (caseId: number, author = 'admin') =>
    fetchJSON<any>('/post-mortems', {
      method: 'POST',
      body: JSON.stringify({ case_id: caseId, author }),
    }),

  /** 查看复盘 */
  opsPostMortem: (caseId: number) => fetchJSON<any>(`/post-mortems/${caseId}`),

  /** 编辑复盘 */
  opsUpdatePostMortem: (caseId: number, data: Record<string, any>) =>
    fetchJSON<any>(`/post-mortems/${caseId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),

  /** 发布复盘 */
  opsPublishPostMortem: (caseId: number, reviewer = 'admin') =>
    fetchJSON<any>(`/post-mortems/${caseId}/publish`, {
      method: 'PUT',
      body: JSON.stringify({ reviewer }),
    }),

  /** 提交反馈 */
  opsSubmitFeedback: (data: Record<string, any>) =>
    fetchJSON<any>('/feedback', { method: 'POST', body: JSON.stringify(data) }),

  /** 误报统计 */
  opsFeedbackStats: (ruleId = '', days = 30) =>
    fetchJSON<any>(`/feedback/stats?rule_id=${encodeURIComponent(ruleId)}&days=${days}`),

  /** 调优建议 */
  opsFeedbackSuggestions: () => fetchJSON<any[]>('/feedback/suggestions'),

  /** 规则列表 */
  opsRules: (ruleType = 'sigma') => fetchJSON<any[]>(`/rules?rule_type=${ruleType}`),

  /** 新增规则 */
  opsCreateRule: (ruleType: string, content: Record<string, any>, changedBy = 'admin') =>
    fetchJSON<any>('/rules', {
      method: 'POST',
      body: JSON.stringify({ rule_type: ruleType, content, changed_by: changedBy }),
    }),

  /** 修改规则 */
  opsUpdateRule: (ruleType: string, ruleId: string, content: Record<string, any>, changeSummary = '', changedBy = 'admin') =>
    fetchJSON<any>(`/rules/${ruleType}/${encodeURIComponent(ruleId)}`, {
      method: 'PUT',
      body: JSON.stringify({ content, change_summary: changeSummary, changed_by: changedBy }),
    }),

  /** 规则版本历史 */
  opsRuleVersions: (ruleType: string, ruleId: string) =>
    fetchJSON<any[]>(`/rules/${ruleType}/${encodeURIComponent(ruleId)}/versions`),

  /** 规则回滚 */
  opsRuleRollback: (ruleType: string, ruleId: string, targetVersion: number, changedBy = 'admin') =>
    fetchJSON<any>(`/rules/${ruleType}/${encodeURIComponent(ruleId)}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ target_version: targetVersion, changed_by: changedBy }),
    }),

  /** 规则沙箱测试 */
  opsRuleSandbox: (ruleContent: Record<string, any>, eventIds?: number[], limit = 100) =>
    fetchJSON<any>('/rules/sandbox', {
      method: 'POST',
      body: JSON.stringify({ rule_content: ruleContent, event_ids: eventIds, limit }),
    }),
}
