/** 十二时辰 + 五更。夜巡用更次，白昼用时辰。 */
export type WatchShift = {
  earthly: string
  label: string
  night: boolean
}

const TABLE: { from: number; earthly: string; label: string; night: boolean }[] = [
  { from: 23, earthly: '子', label: '三更', night: true },
  { from: 1, earthly: '丑', label: '四更', night: true },
  { from: 3, earthly: '寅', label: '五更', night: true },
  { from: 5, earthly: '卯', label: '平旦', night: false },
  { from: 7, earthly: '辰', label: '食时', night: false },
  { from: 9, earthly: '巳', label: '隅中', night: false },
  { from: 11, earthly: '午', label: '日中', night: false },
  { from: 13, earthly: '未', label: '日昳', night: false },
  { from: 15, earthly: '申', label: '晡时', night: false },
  { from: 17, earthly: '酉', label: '日入', night: false },
  { from: 19, earthly: '戌', label: '一更', night: true },
  { from: 21, earthly: '亥', label: '二更', night: true },
]

export function watchShiftAt(d = new Date()): WatchShift {
  const h = d.getHours()
  let cur = TABLE[0]
  for (const row of TABLE) {
    if (h >= row.from) cur = row
  }
  if (h < 1) cur = TABLE[0]
  return { earthly: cur.earthly, label: cur.label, night: cur.night }
}

export function formatWatchClock(d = new Date()) {
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
