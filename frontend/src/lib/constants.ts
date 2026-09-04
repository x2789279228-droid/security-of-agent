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
  // NDR 扩展
  TRAFFIC: '/traffic',
  ENCRYPTED: '/encrypted',
  INTEL: '/intel',
  SANDBOX: '/sandbox',
  EDR: '/edr',
  // B 类能力总览
  CAPABILITIES: '/capabilities',
} as const

/** 单色极简 — 运营中心签名（灰阶） */
export const AI_GRADIENT = 'linear-gradient(120deg, #111111 0%, #555555 50%, #c8c8c8 100%)'
export const AI_GRADIENT_STOPS = ['#111111', '#333333', '#555555', '#888888', '#c8c8c8']
