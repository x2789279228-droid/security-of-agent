/**
 * 连接状态条 — SSE 连接生命周期的一览与手动控制
 */
import { useEffect, useState } from 'react'
import {
  getLastActivityTs,
  streamClear,
  streamReconnect,
  useEventStreamStore,
  type StreamStatus,
} from '../../lib/eventStream'

const STATUS_META: Record<StreamStatus, { label: string; dot: string; pulse: boolean }> = {
  idle:         { label: '未连接',            dot: 'bg-dan',  pulse: false },
  connecting:   { label: '连接中…',           dot: 'bg-nong', pulse: true },
  online:       { label: '实时连接',          dot: 'bg-ink',  pulse: false },
  reconnecting: { label: '重连中',            dot: 'bg-nong', pulse: true },
  offline:      { label: '已断开·自动重试中', dot: 'bg-hui',  pulse: true },
}

function Chip({ label, value, title }: { label: string; value: string | number; title?: string }) {
  return (
    <span className="flex items-baseline gap-1.5 whitespace-nowrap" title={title}>
      <span className="text-[12px] text-ink-faint">{label}</span>
      <span className="font-mono text-[13px] font-semibold text-ink tabular-nums">{value}</span>
    </span>
  )
}

function ActionButton({ children, onClick }: { children: React.ReactNode; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="border border-line px-2.5 py-1 text-[12px] text-ink-soft transition-colors hover:border-ink hover:text-ink"
    >
      {children}
    </button>
  )
}

export default function StreamStatusBar({
  paused,
  onTogglePause,
}: {
  paused: boolean
  onTogglePause: () => void
}) {
  const status = useEventStreamStore((s) => s.status)
  const subscribers = useEventStreamStore((s) => s.subscribers)
  const attempts = useEventStreamStore((s) => s.attempts)
  const reconnects = useEventStreamStore((s) => s.reconnects)
  const receivedTotal = useEventStreamStore((s) => s.receivedTotal)
  const replayedTotal = useEventStreamStore((s) => s.replayedTotal)
  const buffered = useEventStreamStore((s) => s.buffer.length)
  const overflow = useEventStreamStore((s) => s.overflow)

  // 心跳年龄每秒重算
  const [heartAge, setHeartAge] = useState<number | null>(null)
  useEffect(() => {
    const update = () => {
      setHeartAge(
        status === 'online'
          ? Math.max(0, Math.round((Date.now() - getLastActivityTs()) / 1000))
          : null,
      )
    }
    update()
    const t = setInterval(update, 1000)
    return () => clearInterval(t)
  }, [status])

  const meta = STATUS_META[status]
  const statusLabel =
    status === 'reconnecting' && attempts > 0 ? `${meta.label}·第${attempts}次` : meta.label

  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 px-5 py-3">
      <span className="flex items-center gap-2">
        <span className={`h-2 w-2 rounded-full ${meta.dot} ${meta.pulse ? 'animate-pulse' : ''}`} />
        <span className="text-[13px] font-semibold text-ink">{statusLabel}</span>
        {reconnects > 0 && (
          <span className="text-[11px] text-ink-faint">(累计重连 {reconnects})</span>
        )}
      </span>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
        <Chip label="订阅者" value={subscribers || '—'} />
        <Chip label="心跳" value={heartAge === null ? '—' : `${heartAge}s前`} title="最近一次通道消息（含30s保活心跳）" />
        <Chip label="会话接收" value={receivedTotal} title={replayedTotal > 0 ? `含回放补发 ${replayedTotal} 条` : undefined} />
        {replayedTotal > 0 && <span className="text-[11px] text-ink-faint">回放 {replayedTotal}</span>}
        <Chip
          label="缓冲"
          value={`${buffered}/500`}
          title={overflow > 0 ? `已挤出最旧 ${overflow} 条` : undefined}
        />
        {overflow > 0 && <span className="text-[11px] text-ink-faint">溢出 {overflow}</span>}
      </div>

      <div className="ml-auto flex items-center gap-2">
        <ActionButton onClick={onTogglePause}>{paused ? '▶ 恢复推送' : '⏸ 暂停推送'}</ActionButton>
        <ActionButton onClick={() => streamReconnect()}>⟳ 重连</ActionButton>
        <ActionButton onClick={() => streamClear()}>✕ 清空</ActionButton>
      </div>
    </div>
  )
}
