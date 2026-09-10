import type { ReactNode } from 'react'
import { PageTransition } from './PageTransition'

/**
 * PageFrame · 守望 v3 标准页面框架
 *
 * 每个页面都套用这个统一头：
 * - 左：罗马数字 / 标题 / hint / marginalia
 * - 右：extra（操作区）
 * - 下：正文
 *
 * 升级路径：旧 PageFrame 只接 title/subtitle；现在接 num/label/hint/marginalia
 */

export function PageFrame({
  num,
  title,
  subtitle,
  hint,
  marginalia,
  extra,
  children,
}: {
  /** 罗马数字章节号，如 I / II / III */
  num?: string
  /** 中文标签，如「日志中心」 */
  title: string
  /** 副标题（保留兼容，建议优先用 hint） */
  subtitle?: string
  /** 编辑感 hint（用 — 顿句） */
  hint?: string
  /** marginalia 边注 */
  marginalia?: string
  /** 右侧操作区 */
  extra?: ReactNode
  children: ReactNode
}) {
  return (
    <PageTransition>
      <div className="page-shell pt-4 pb-12">
        <header className="relative flex flex-col gap-2 border-b border-line pb-3 md:flex-row md:items-end md:justify-between md:gap-8">
          <div className="min-w-0 md:max-w-[44rem]">
            {num && (
              <p className="font-serif text-[28px] font-black leading-none text-ink tabular-nums">
                {num}
              </p>
            )}
            <h1 className={`${num ? 'mt-1' : ''} font-serif text-[28px] font-black tracking-[-0.04em] text-ink leading-[1.1]`}>
              {title}
            </h1>
            {hint && (
              <p className="mt-1 text-[13px] leading-snug text-ink-soft">
                {hint}
              </p>
            )}
            {!hint && subtitle && (
              <p className="mt-1 text-[13px] leading-snug text-ink-soft">
                {subtitle}
              </p>
            )}
            {marginalia && (
              <p className="mt-1 hidden font-serif italic text-[12px] leading-snug text-ink-faint md:block">
                <span aria-hidden className="mr-1 text-ink-faint">¶</span>
                {marginalia}
              </p>
            )}
          </div>
          {extra && <div className="flex flex-wrap items-center gap-3 shrink-0">{extra}</div>}
        </header>

        <div className="pt-4">{children}</div>
      </div>
    </PageTransition>
  )
}

/** 下划线 tab（活跃 = 黑色底线 + 暮金字；非活跃 = 灰字悬停黑） */
export const tabOn =
  'relative pb-2 px-1 text-[13px] text-ink font-medium after:absolute after:left-1 after:right-1 after:bottom-0 after:h-px after:bg-[#0e1a26]'
export const tabOff =
  'relative pb-2 px-1 text-[13px] text-ink-soft hover:text-ink transition-colors'