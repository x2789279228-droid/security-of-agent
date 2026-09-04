/**
 * 登录页品牌面板 — 桌面左栏 / 移动端顶部压缩版
 */
import { motion, useReducedMotion } from 'framer-motion'

const PIPELINE = [
  { step: '01', name: '接入' },
  { step: '02', name: '审计' },
  { step: '03', name: '响应' },
  { step: '04', name: '复盘' },
] as const

const HIGHLIGHTS = [
  'Audit-LLM 四层流水线交叉验证',
  'CAD 独立监督，防幻觉熔断',
  '发现威胁，自动响应闭环',
] as const

export default function BrandPanel({ compact = false }: { compact?: boolean }) {
  const reduceMotion = useReducedMotion()

  return (
    <div
      className={`relative overflow-hidden bg-ink text-white ${
        compact ? 'px-6 py-8' : 'flex h-full min-h-full flex-col justify-between px-10 py-12 lg:px-14 lg:py-16'
      }`}
    >
      {/* 灰阶网格纹理 */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            'linear-gradient(to right, #fff 1px, transparent 1px), linear-gradient(to bottom, #fff 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-white/5"
      />

      <div className="relative z-10">
        <motion.p
          initial={reduceMotion ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="text-[11px] font-light tracking-[0.32em] text-white/55 uppercase"
        >
          Shared Memory Platform
        </motion.p>
        <motion.h1
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.05 }}
          className={`mt-3 font-black tracking-tight ${compact ? 'text-[28px]' : 'text-[40px] lg:text-[48px]'}`}
        >
          共享记忆
        </motion.h1>
        <motion.p
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.1 }}
          className={`mt-3 max-w-md text-white/70 ${compact ? 'text-[13px]' : 'text-[15px] leading-relaxed'}`}
        >
          安全审计 Agent 平台 · 多 Agent 审查接力
        </motion.p>

        {/* 流水线 */}
        <motion.div
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.15 }}
          className={`flex flex-wrap items-center gap-x-2 gap-y-2 ${compact ? 'mt-5' : 'mt-10'}`}
        >
          {PIPELINE.map((p, i) => (
            <div key={p.step} className="flex items-center gap-2">
              <div className="border border-white/25 px-2.5 py-1.5">
                <span className="font-mono text-[10px] text-white/45">{p.step}</span>
                <span className="ml-2 text-[12px] font-medium tracking-wide">{p.name}</span>
              </div>
              {i < PIPELINE.length - 1 && (
                <span className="text-white/30" aria-hidden>
                  →
                </span>
              )}
            </div>
          ))}
        </motion.div>

        {!compact && (
          <motion.ul
            initial={reduceMotion ? false : { opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.22 }}
            className="mt-12 space-y-4"
          >
            {HIGHLIGHTS.map((text) => (
              <li key={text} className="flex items-start gap-3 text-[14px] text-white/80">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 bg-white" aria-hidden />
                {text}
              </li>
            ))}
          </motion.ul>
        )}
      </div>

      {!compact && (
        <p className="relative z-10 mt-16 text-[11px] tracking-[0.2em] text-white/40 uppercase">
          共享记忆 · Security Audit
        </p>
      )}
    </div>
  )
}
