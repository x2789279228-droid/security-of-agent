import type { ReactNode } from 'react'
import { PageTransition } from './PageTransition'

export function PageFrame({
  title,
  subtitle,
  extra,
  children,
}: {
  title: string
  subtitle?: string
  extra?: ReactNode
  children: ReactNode
}) {
  return (
    <PageTransition>
      <div className="page-shell pt-12 pb-20">
        <div className="flex flex-wrap items-end justify-between gap-4 mb-8 pb-6 border-b border-line">
          <div>
            <h1 className="page-title">{title}</h1>
            {subtitle && <p className="page-sub">{subtitle}</p>}
          </div>
          {extra}
        </div>
        {children}
      </div>
    </PageTransition>
  )
}

export const tabOn =
  'px-4 py-2 text-[13px] tracking-[0.08em] bg-ink text-white border border-ink'
export const tabOff =
  'px-4 py-2 text-[13px] tracking-[0.08em] bg-transparent text-ink border border-ink hover:bg-ink hover:text-white'
