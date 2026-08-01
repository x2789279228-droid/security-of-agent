import { useState, useCallback, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { api } from '../../lib/api'

const THREAT_OPTIONS = [
  { value: '', label: '所有类型' },
  { value: 'C2_BEACON', label: 'C2回连' },
  { value: 'DATA_EXFIL', label: '数据外泄' },
  { value: 'BRUTE_FORCE', label: '暴力破解' },
  { value: 'PORT_SCAN', label: '端口扫描' },
  { value: 'MALWARE_DETECT', label: '恶意软件' },
  { value: 'DDoS_TRAFFIC', label: 'DDoS' },
  { value: 'LATERAL_MOVE', label: '横向移动' },
]

const METRIC_LABELS: Record<string, string> = {
  context_precision: '上下文精确率',
  context_recall: '上下文召回率',
  hit_rate_at_k: 'Top-K 命中率',
  top1_relevance: 'Top-1 相关度',
  semantic_relevance: '语义相关度',
  faithfulness: '忠实度',
  citation_coverage: '引用覆盖',
  answer_relevance: '回答相关度',
  unsupported_claim_ratio: '无支撑断言抑制',
  semantic_faithfulness: '语义忠实度',
}

function ScoreBadge({ score }: { score: number }) {
  return (
    <span className={`text-[10px] font-sans font-bold px-1.5 py-0.5 rounded ${score >= 0.7 ? 'bg-green-100 text-green-700' : score >= 0.4 ? 'bg-yellow-100 text-yellow-700' : 'bg-red-100 text-red-700'}`}>
      {(score * 100).toFixed(0)}%
    </span>
  )
}

function ScoreRow({ s }: { s: any }) {
  return (
    <div className={`flex items-center justify-between gap-3 px-3 py-2 rounded-lg ${s.passed ? 'bg-green-50/50' : 'bg-red-50/50'}`}>
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-sans font-medium text-ink">{METRIC_LABELS[s.metric] || s.metric}</span>
          <span className={`text-[10px] font-sans ${s.passed ? 'text-green-600' : 'text-red-600'}`}>
            {s.passed ? '✓ 通过' : '✗ 未达标'}
          </span>
        </div>
        <p className="text-[10px] text-ink-faint font-sans truncate mt-0.5">{s.reason}</p>
      </div>
      <div className="shrink-0 flex items-center gap-2">
        <div className="w-20 h-1.5 bg-gray-100 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${s.passed ? 'bg-ok' : 'bg-alert'}`} style={{ width: `${s.score * 100}%` }} />
        </div>
        <ScoreBadge score={s.score} />
        <span className="text-[10px] text-ink-faint font-sans">≥{s.threshold}</span>
      </div>
    </div>
  )
}

export function QualityPanel() {
  const [autoQuery, setAutoQuery] = useState('')
  const [autoThreat, setAutoThreat] = useState('')
  const [autoGroundTruth, setAutoGroundTruth] = useState('')
  const [topK, setTopK] = useState(5)
  const [evalResult, setEvalResult] = useState<any>(null)
  const [faithAnswer, setFaithAnswer] = useState('')
  const [faithQuery, setFaithQuery] = useState('')
  const [faithResult, setFaithResult] = useState<any>(null)
  const [report, setReport] = useState<any>(null)
  const [runs, setRuns] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const loadReport = useCallback(async () => {
    try {
      const [r, runs] = await Promise.all([api.evalReport(), api.evalRuns('', 10)])
      setReport(r)
      setRuns(runs)
    } catch (e: any) { setError(e.message) }
  }, [])

  useEffect(() => { loadReport() }, [loadReport])

  const runAutoEval = async () => {
    if (!autoQuery.trim()) { setError('请输入检索查询'); return }
    setLoading(true); setError(''); setEvalResult(null)
    try {
      const data = await api.evalRagAuto({
        query: autoQuery.trim(),
        threat_type: autoThreat,
        top_k: topK,
        ground_truth: autoGroundTruth.trim(),
      })
      setEvalResult(data)
      await loadReport()
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  const runFaithfulness = async () => {
    if (!faithAnswer.trim()) { setError('请输入要评估的回答'); return }
    setLoading(true); setError(''); setFaithResult(null)
    try {
      const contexts = evalResult?.search?.chunks || []
      if (contexts.length === 0) { setError('请先运行一次检索评估，或提供上下文'); setLoading(false); return }
      const data = await api.evalFaithfulness({
        answer: faithAnswer.trim(),
        query: faithQuery.trim() || autoQuery.trim(),
        contexts: contexts.map((c: any) => ({ title: c.title, content: c.content, source: c.source })),
      })
      setFaithResult(data)
      await loadReport()
    } catch (e: any) { setError(e.message) }
    finally { setLoading(false) }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-xs font-sans text-ink-faint">
          参考 RAGAS / studyagentplus 指标体系 — 检索质量（精确率/召回率/命中率）+ 忠实度（防幻觉）
        </p>
        <button onClick={loadReport} className="px-3 py-1.5 text-xs font-sans font-medium bg-gray-100 rounded-lg hover:bg-gray-200">刷新报告</button>
      </div>

      {/* 指标报告 */}
      {report && report.run_count > 0 && (
        <div className="border border-line rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-sans font-semibold">指标健康度</h3>
            <span className="text-[10px] font-sans text-ink-faint">共 {report.run_count} 次评估 · {Object.keys(report.metric_averages || {}).length} 个指标</span>
          </div>
          <div className="space-y-2">
            {Object.entries(report.metric_averages || {}).map(([metric, avg]: any) => (
              <div key={metric} className="flex items-center gap-3">
                <span className="w-36 shrink-0 text-xs font-sans text-ink-soft">{METRIC_LABELS[metric] || metric}</span>
                <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                  <div className="h-full bg-accent rounded-full" style={{ width: `${avg * 100}%` }} />
                </div>
                <span className="text-[10px] font-sans text-ink-faint shrink-0">
                  通过率 {(report.pass_rates?.[metric] ?? 0) * 100}%
                </span>
                <ScoreBadge score={avg} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 检索质量评估 */}
      <div className="border border-line rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-sans font-semibold">检索质量评估（对真实知识库）</h3>
        <div className="flex gap-2 flex-wrap">
          <input type="text" placeholder="检索查询（如：检测C2通信）" value={autoQuery}
            onChange={e => setAutoQuery(e.target.value)} onKeyDown={e => e.key === 'Enter' && runAutoEval()}
            className="flex-1 min-w-[200px] px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
          <select value={autoThreat} onChange={e => setAutoThreat(e.target.value)}
            className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
            {THREAT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          <select value={topK} onChange={e => setTopK(Number(e.target.value))}
            className="px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent">
            <option value={3}>Top 3</option>
            <option value={5}>Top 5</option>
            <option value={10}>Top 10</option>
          </select>
          <button onClick={runAutoEval} disabled={loading}
            className="px-5 py-2 text-xs font-sans font-medium bg-accent text-white rounded-lg hover:opacity-90 disabled:opacity-50">
            {loading ? '评估中...' : '运行评估'}
          </button>
        </div>
        <input type="text" placeholder="标准答案 Ground Truth（可选，用于召回率计算）" value={autoGroundTruth}
          onChange={e => setAutoGroundTruth(e.target.value)}
          className="w-full px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />

        {error && <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-700">{error}</div>}

        <AnimatePresence>
          {evalResult && (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-3">
              <div className="text-[10px] font-sans text-ink-faint">
                检索策略: {evalResult.search?.strategy} · 命中 {evalResult.search?.total} 条 · 评估ID: {evalResult.eval?.id}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {(evalResult.eval?.scores || []).map((s: any, i: number) => <ScoreRow key={i} s={s} />)}
              </div>
              <div className="pt-2 border-t border-line">
                <p className="text-[10px] font-sans text-ink-faint mb-2">检索到的上下文（前 {evalResult.search?.chunks?.length} 条）</p>
                <div className="max-h-40 overflow-y-auto space-y-1">
                  {(evalResult.search?.chunks || []).map((c: any, i: number) => (
                    <div key={i} className="flex items-start gap-2 px-3 py-1.5 bg-gray-50 rounded-lg text-[10px] font-sans">
                      <span className="text-ink-faint shrink-0">[{c.score.toFixed(2)}]</span>
                      <span className="text-ink-soft truncate">{c.title} — {c.content?.slice(0, 80)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* 忠实度评估 */}
      <div className="border border-line rounded-lg p-4 space-y-3">
        <h3 className="text-sm font-sans font-semibold">忠实度评估（防幻觉）</h3>
        <p className="text-[10px] font-sans text-ink-faint">使用最近一次检索评估的上下文作为支撑材料，评估回答的每个断言是否有据可依</p>
        <textarea placeholder="输入模型/Agent 的回答（如审计结论），逐句评估其忠实度" value={faithAnswer}
          onChange={e => setFaithAnswer(e.target.value)} rows={4}
          className="w-full px-3 py-2 text-xs font-sans border border-line rounded-lg resize-none focus:outline-none focus:ring-1 focus:ring-accent" />
        <div className="flex gap-2">
          <input type="text" placeholder="关联查询（可选，默认用检索查询）" value={faithQuery}
            onChange={e => setFaithQuery(e.target.value)}
            className="flex-1 px-3 py-2 text-xs font-sans border border-line rounded-lg focus:outline-none focus:ring-1 focus:ring-accent" />
          <button onClick={runFaithfulness} disabled={loading || !evalResult}
            className="px-5 py-2 text-xs font-sans font-medium bg-ink text-surface rounded-lg hover:bg-ink-soft disabled:opacity-40">
            {loading ? '评估中...' : '评估忠实度'}
          </button>
        </div>
        <AnimatePresence>
          {faithResult && (
            <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="space-y-2">
              <div className="text-[10px] font-sans text-ink-faint">评估ID: {faithResult.id} · 断言数: {faithResult.output_payload?.claim_count}</div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {(faithResult.scores || []).map((s: any, i: number) => <ScoreRow key={i} s={s} />)}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* 最近评估运行 */}
      <div className="border border-line rounded-lg p-4">
        <h3 className="text-sm font-sans font-semibold mb-3">最近评估运行</h3>
        {runs.length === 0 ? (
          <p className="text-xs text-ink-faint font-sans py-4 text-center">暂无评估记录 — 运行一次评估后显示</p>
        ) : (
          <div className="divide-y divide-line">
            {runs.map((run: any) => (
              <div key={run.id} className="flex items-center gap-3 py-2.5">
                <span className="text-[10px] font-sans font-medium px-2 py-0.5 rounded-full bg-gray-100 text-ink-soft shrink-0">
                  {run.run_type === 'rag' ? '检索质量' : '忠实度'}
                </span>
                <div className="flex-1 min-w-0 text-xs font-sans truncate text-ink-soft">
                  {run.query?.slice(0, 60) || '(无查询)'}
                </div>
                <div className="flex gap-1.5 shrink-0">
                  {(run.scores || []).map((s: any, i: number) => (
                    <span key={i} className={`text-[10px] font-sans px-1.5 py-0.5 rounded ${s.passed ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'}`}>
                      {METRIC_LABELS[s.metric] || s.metric}: {(s.score * 100).toFixed(0)}%
                    </span>
                  ))}
                </div>
                <span className="text-[10px] text-ink-faint font-sans shrink-0">
                  {run.created_at ? new Date(run.created_at).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : ''}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
