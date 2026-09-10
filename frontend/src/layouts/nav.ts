import { ROUTES } from '../lib/constants'

export const NAV_GROUPS: { title: string; items: { path: string; label: string; short: string }[] }[] = [
  {
    title: '值班',
    items: [
      { path: ROUTES.HOME, label: '首页', short: '首页' },
      { path: ROUTES.MONITOR, label: '监控', short: '监控' },
      { path: ROUTES.LOGS, label: '日志中心', short: '日志' },
    ],
  },
  {
    title: '处置',
    items: [
      { path: ROUTES.SECURITY_AUDIT, label: '安全审计', short: '审计' },
      { path: ROUTES.RESPONSE, label: '响应引擎', short: '响应' },
      { path: ROUTES.OPERATIONS, label: '运营中心', short: '运营' },
    ],
  },
  {
    title: '对抗',
    items: [
      { path: ROUTES.SELF_PLAY, label: '红蓝自博弈', short: '自博弈' },
      { path: ROUTES.RAG, label: '知识库', short: '知识' },
    ],
  },
  {
    title: '感知',
    items: [
      { path: ROUTES.TRAFFIC, label: '流量采集', short: '流量' },
      { path: ROUTES.ENCRYPTED, label: '加密流量', short: '加密' },
      { path: ROUTES.INTEL, label: '威胁情报', short: '情报' },
      { path: ROUTES.SANDBOX, label: '沙箱检测', short: '沙箱' },
      { path: ROUTES.EDR, label: '终端检测', short: '终端' },
      { path: ROUTES.CAPABILITIES, label: '能力总览', short: '总览' },
    ],
  },
]

export const PATH_LABEL: Record<string, string> = Object.fromEntries(
  NAV_GROUPS.flatMap((g) => g.items.map((i) => [i.path, i.label])),
)
