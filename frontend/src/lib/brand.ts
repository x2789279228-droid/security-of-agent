export const BRAND = {
  name: '守望',
  nameEn: 'SHOUWANG',
  lockup: 'SHOUWANG · Night Watch SOC',
  product: '自主安全运营',
  tagline: '灯火未熄。每一条日志，都在被守望。',
  manifesto: '第一秒看见威胁，下一秒它已被拦住。',
  footer: '守望 · Night Watch SOC',
} as const

/** 案卷深室（Vault Ledger）：深室底、黛墨字、暮青动作、松绿健康、朱砂只留给威胁、暮金唯一点缀。 */
export const BRAND_COLORS = {
  vault: '#0E1A26',
  night: '#1C2838',
  card: '#F5F7F5',
  paper: '#F5F7F5',
  surface: '#ECF0EE',
  ink: '#1C2838',
  accent: '#3A6570',
  ok: '#3E7A64',
  alert: '#B03A30',
  warn: '#B88940',
  signal: '#4A7A88',
  dusk: '#C9A574',
  onAccent: '#F5F7F5',
} as const

/** 暮青 → 灰青 → 松绿（dusk → pine）。无金。 */
export const AI_GRADIENT =
  'linear-gradient(120deg, #3A6570 0%, #4A7A88 45%, #3E7A64 100%)'
export const AI_GRADIENT_STOPS = ['#3A6570', '#4A7A88', '#3E7A64', '#C08A3A']
