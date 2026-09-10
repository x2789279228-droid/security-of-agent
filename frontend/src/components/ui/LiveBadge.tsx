export function LiveBadge({
  live = true,
  label,
  className = '',
}: {
  live?: boolean
  label?: string
  className?: string
}) {
  const text = label ?? (live ? '值班中' : '离线')
  return (
    <span className={`inline-flex items-center gap-1.5 text-[12px] ${live ? 'text-accent' : 'text-ink-faint'} ${className}`}>
      <span className="relative flex h-1.5 w-1.5">
        {live && (
          <span className="absolute inset-0 animate-ping rounded-full bg-accent opacity-60" />
        )}
        <span className={`relative h-1.5 w-1.5 rounded-full ${live ? 'bg-accent' : 'bg-ink-faint'}`} />
      </span>
      {text}
    </span>
  )
}
