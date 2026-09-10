export const spring = {
  ui: { type: 'spring' as const, stiffness: 300, damping: 20 },
  gentle: { type: 'spring' as const, stiffness: 200, damping: 22 },
  stiff: { type: 'spring' as const, stiffness: 400, damping: 30 },
  bouncy: { type: 'spring' as const, stiffness: 350, damping: 12 },
  tilt: { type: 'spring' as const, stiffness: 150, damping: 12, mass: 0.5 },
  page: { type: 'spring' as const, stiffness: 200, damping: 25 },
  stagger: { staggerChildren: 0.04 },
}

export const ROUTES = {
  HOME: '/',
  LOGS: '/logs',
  MONITOR: '/monitor',
  SECURITY_AUDIT: '/security-audit',
  RESPONSE: '/response',
  RAG: '/rag',
  OPERATIONS: '/operations',
  SELF_PLAY: '/self-play',
  // NDR 扩展
  TRAFFIC: '/traffic',
  ENCRYPTED: '/encrypted',
  INTEL: '/intel',
  SANDBOX: '/sandbox',
  EDR: '/edr',
  // B 类能力总览
  CAPABILITIES: '/capabilities',
} as const

/** 守望签名 — 暮青 → 灰青 → 松绿 → 柿黄 */
export { AI_GRADIENT, AI_GRADIENT_STOPS, BRAND, BRAND_COLORS } from './brand'
