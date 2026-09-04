/**
 * SSE 数据流管线图 — 过程展示核心画面
 *
 * 服务端事件总线 → SSE通道(心跳30s) → 接收 → 客户端缓冲 → 视图筛选
 * 各节点呈现真实计数值；业务事件到达时一个"数据包"沿传输线飞行（高频时节流，
 * 最多约每 300ms 一次），抵达视图节点时该节点短暂脉冲。
 */
import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { useEventStreamStore } from '../../lib/eventStream'
import RateHistogram from './RateHistogram'

function Node({
  label,
  value,
  sub,
  flashKey = 0,
}: {
  label: string
  value: string | number
  sub?: string
  flashKey?: number
}) {
  return (
    <div className="relative z-10 flex min-w-[86px] flex-col items-center gap-0.5 border border-line bg-white px-3 py-2">
      <span className="whitespace-nowrap text-[10px] tracking-wide text-ink-faint">{label}</span>
      <span className="font-mono text-[15px] font-semibold text-ink tabular-nums">{value}</span>
      {sub !== undefined && (
        <span className="whitespace-nowrap text-[10px] text-ink-faint">{sub}</span>
      )}
      {flashKey > 0 && (
        <motion.span
          key={flashKey}
          initial={{ opacity: 0.3 }}
          animate={{ opacity: 0 }}
          transition={{ duration: 0.7 }}
          className="pointer-events-none absolute inset-0 bg-qing"
        />
      )}
    </div>
  )
}

export default function PipelineStrip({ shownCount }: { shownCount: number }) {
  const status = useEventStreamStore((s) => s.status)
  const subscribers = useEventStreamStore((s) => s.subscribers)
  const receivedTotal = useEventStreamStore((s) => s.receivedTotal)
  const buffered = useEventStreamStore((s) => s.buffer.length)
  const overflow = useEventStreamStore((s) => s.overflow)
  const arrivalTick = useEventStreamStore((s) => s.arrivalTick)

  const [packet, setPacket] = useState<number | null>(null)
  const [viewPulse, setViewPulse] = useState(0)
  const lastRunRef = useRef(0)

  // 数据包飞行动画：arrivalTick 变化时触发，300ms 节流防止高频刷屏
  useEffect(() => {
    if (!arrivalTick) return
    const now = Date.now()
    if (now - lastRunRef.current < 300) return
    lastRunRef.current = now
    setPacket(arrivalTick)
  }, [arrivalTick])

  const channelSub =
    status === 'online' ? '在线' : status === 'reconnecting' ? '重连中' : status === 'connecting' ? '连接中' : '离线'

  return (
    <div className="flex flex-col gap-5 px-5 py-4 lg:flex-row lg:items-center lg:justify-between">
      {/* 管线区域 */}
      <div className="relative min-w-0 flex-1">
        {/* 传输线：位于节点纵向中点，两端留出半个节点的安全边距 */}
        <div className="absolute left-[43px] right-[43px] top-1/2 h-px bg-line" />

        {packet !== null && (
          <motion.span
            key={packet}
            className="absolute top-1/2 z-20 h-2 w-2 rounded-full bg-ink"
            style={{ marginLeft: -4 }}
            initial={{ left: '6%', opacity: 0 }}
            animate={{ left: '94%', opacity: [0, 1, 1, 0.85] }}
            transition={{ duration: 0.9, ease: 'linear' }}
            onAnimationComplete={() => {
              setPacket(null)
              setViewPulse((p) => p + 1)
            }}
          />
        )}

        <div className="relative flex items-start justify-between gap-2 overflow-x-auto pb-1">
          <Node
            label="服务端事件总线"
            value={subscribers || '—'}
            sub={`${subscribers || 0} 个订阅者`}
          />
          <Node label="SSE 通道" value="30s" sub={`心跳 · ${channelSub}`} />
          <Node
            label="接收"
            value={receivedTotal}
            sub="本会话累计"
            flashKey={arrivalTick}
          />
          <Node
            label="客户端缓冲"
            value={buffered}
            sub={overflow > 0 ? `上限500 · 溢出${overflow}` : '上限 500'}
          />
          <Node
            label="视图筛选"
            value={shownCount}
            sub="当前显示"
            flashKey={viewPulse}
          />
        </div>
      </div>

      {/* 右侧速率直方图 */}
      <RateHistogram />
    </div>
  )
}
