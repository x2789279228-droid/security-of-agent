/**
 * 登录页品牌面板 — 石灰石浅色（白昼台账）+ 积木守望人；无暗色渐变
 */
import { motion, useReducedMotion } from 'framer-motion'
import { BrandMark } from '../brand/BrandMark'
import { BRAND } from '../../lib/brand'

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
      className={`relative overflow-hidden text-ink ${
        compact ? 'border-b border-line px-6 py-6' : 'flex h-full min-h-full flex-col justify-between border-r border-line px-10 py-12 lg:px-14 lg:py-16'
      }`}
      style={{
        background:
          'radial-gradient(120% 90% at 88% -8%, rgba(58,101,112,0.08), transparent 55%),' +
          'radial-gradient(100% 80% at 0% 110%, rgba(62,122,100,0.06), transparent 60%),' +
          '#f1f4f6',
      }}
    >
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-[0.55]"
        style={{
          backgroundImage:
            'linear-gradient(rgba(58,101,112,0.06) 1px, transparent 1px),' +
            'linear-gradient(90deg, rgba(58,101,112,0.06) 1px, transparent 1px)',
          backgroundSize: '44px 44px',
          maskImage: 'radial-gradient(ellipse at 70% 30%, #000 25%, transparent 78%)',
          WebkitMaskImage: 'radial-gradient(ellipse at 70% 30%, #000 25%, transparent 78%)',
        }}
      />

      {!compact && (
        <img
          src="/brand-mascot.jpg"
          alt=""
          aria-hidden
          className="pointer-events-none absolute -right-6 bottom-[-4%] h-[72%] max-h-[560px] w-auto object-contain drop-shadow-[0_18px_36px_rgba(28,40,56,0.18)]"
        />
      )}

      <div className="relative z-10 max-w-xl">
        <motion.div
          initial={reduceMotion ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex items-center gap-3"
        >
          <BrandMark size="lg" />
          <span className="hidden text-[11px] font-mono tracking-[0.3em] text-ink-faint uppercase sm:inline">
            Night Watch SOC
          </span>
        </motion.div>

        <motion.h1
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.05 }}
          className={`mt-4 font-serif font-black tracking-[-0.04em] text-ink ${compact ? 'text-[24px]' : 'text-[42px] lg:text-[52px]'}`}
        >
          {BRAND.name}
          <span className="ml-3 align-middle font-mono text-[13px] font-normal tracking-[0.26em] text-accent uppercase">
            {BRAND.nameEn}
          </span>
        </motion.h1>

        <motion.p
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.1 }}
          className={`mt-2 max-w-md text-ink-soft ${compact ? 'text-[13px]' : 'text-[15px] leading-relaxed'}`}
        >
          {BRAND.tagline}
        </motion.p>

        <motion.div
          initial={reduceMotion ? false : { opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.15 }}
          className={`flex flex-wrap items-center gap-x-2 gap-y-2 ${compact ? 'mt-5' : 'mt-9'}`}
        >
          {PIPELINE.map((p, i) => (
            <div key={p.step} className="flex items-center gap-2">
              <div className="flex items-center gap-2 rounded-lg border border-line bg-paper/70 px-2.5 py-1.5">
                <span className="font-mono text-[10px] text-accent">{p.step}</span>
                <span className="text-[12px] font-medium tracking-wide text-ink-soft">{p.name}</span>
              </div>
              {i < PIPELINE.length - 1 && (
                <span className="text-ink-faint" aria-hidden>
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
              <li key={text} className="flex items-start gap-3 text-[14px] text-ink-soft">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-accent" aria-hidden />
                {text}
              </li>
            ))}
          </motion.ul>
        )}
      </div>

      {!compact && (
        <p className="relative z-10 mt-16 font-mono text-[11px] tracking-[0.2em] text-ink-faint uppercase">
          {BRAND.footer}
        </p>
      )}
    </div>
  )
}
