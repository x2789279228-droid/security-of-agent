/**
 * Blueprint · 系统架构工程蓝图
 *
 * 真正的工程图纸美学：
 * - 浅蓝底（#dde6ec）+ 深蓝墨线条（#0a2540）
 * - 薄线、点划线、callout 编号、尺寸标、双语标签
 * - 8 个核心节点 + 3 个 callout + 标注「数据旅程」
 *
 * 不依赖任何外部库；尺寸按 viewBox 自适应
 */

type Node = {
  id: string
  cn: string
  en: string
  x: number
  y: number
  w: number
  h: number
  callout?: number
  group: 'ingest' | 'stream' | 'audit' | 'response'
}

const NODES: Node[] = [
  // 接入
  { id: 'src', cn: '日志源', en: 'SOURCES', x: 40, y: 90, w: 130, h: 56, group: 'ingest' },
  // 流
  { id: 'kafka', cn: 'Kafka 总线', en: 'KAFKA 3.7', x: 230, y: 90, w: 150, h: 56, group: 'stream', callout: 1 },
  { id: 'flink', cn: 'Flink CEP', en: 'FLINK 1.19.3', x: 440, y: 90, w: 150, h: 56, group: 'stream', callout: 2 },
  // 审计
  { id: 'audit', cn: 'Audit-LLM', en: '4-LAYER AGENT', x: 650, y: 60, w: 170, h: 56, group: 'audit', callout: 3 },
  { id: 'cad', cn: 'CAD 监督', en: 'INDEPENDENT', x: 650, y: 130, w: 170, h: 46, group: 'audit' },
  // 响应
  { id: 'rag', cn: 'RAG 知识库', en: 'MITRE / CAPEC', x: 880, y: 60, w: 140, h: 46, group: 'audit' },
  { id: 'resp', cn: '响应引擎', en: 'RESPONSE', x: 880, y: 130, w: 140, h: 56, group: 'response', callout: 4 },
  // 反馈闭环
  { id: 'self', cn: '红蓝自博弈', en: 'SELF-PLAY', x: 440, y: 230, w: 150, h: 50, group: 'response' },
]

const CALLOUTS = [
  { n: 1, x: 305, y: 175, label: 'KRaft 模式，无 ZK 依赖', en: 'KRaft mode · no ZK' },
  { n: 2, x: 515, y: 175, label: 'CEP 攻击链 · 多维评分', en: 'CEP patterns · multi-dim score' },
  { n: 3, x: 735, y: 200, label: '分解·构建·执行·复核', en: 'Decomposer → Builder → Exec → Reviewer' },
  { n: 4, x: 950, y: 215, label: '封禁·隔离·限速 · 可回滚', en: 'Block · Isolate · Throttle · Rollback' },
]

export function Blueprint() {
  const w = 1080
  const h = 360

  return (
    <div className="relative">
      {/* 蓝图框 */}
      <div
        className="relative w-full overflow-hidden border border-[#0a2540]/30"
        style={{
          background: '#dde6ec',
          backgroundImage:
            'repeating-linear-gradient(0deg, rgba(10,37,64,0.04) 0 1px, transparent 1px 24px),' +
            'repeating-linear-gradient(90deg, rgba(10,37,64,0.04) 0 1px, transparent 1px 24px)',
        }}
      >
        {/* 蓝图眉栏 */}
        <div className="flex items-center justify-between border-b border-[#0a2540]/40 bg-[#0a2540] px-5 py-2 font-mono text-[10px] tracking-[0.26em] uppercase text-[#cbd5dc]">
          <div className="flex items-center gap-4">
            <span className="text-[#c9a574]">DWG · S-01</span>
            <span>SYSTEM ARCHITECTURE / 数据旅程</span>
          </div>
          <div className="flex items-center gap-4">
            <span>SCALE 1:1</span>
            <span>SHEET 1 / 1</span>
            <span>REV · A</span>
          </div>
        </div>

        <svg
          viewBox={`0 0 ${w} ${h}`}
          className="block w-full"
          role="img"
          aria-label="守望系统架构蓝图"
        >
          {/* 主流程横线（点划线） */}
          <line
            x1={40} y1={118} x2={1020} y2={118}
            stroke="#0a2540" strokeWidth={0.6} strokeDasharray="6 4" opacity={0.4}
          />

          {/* 节点 */}
          {NODES.map((n) => (
            <g key={n.id}>
              <rect
                x={n.x} y={n.y}
                width={n.w} height={n.h}
                fill="#dde6ec"
                stroke="#0a2540"
                strokeWidth={1}
              />
              <line
                x1={n.x} y1={n.y + 18}
                x2={n.x + n.w} y2={n.y + 18}
                stroke="#0a2540"
                strokeWidth={0.5}
                opacity={0.5}
              />
              <text
                x={n.x + 8} y={n.y + 13}
                fill="#0a2540"
                fontSize="9"
                fontFamily="ui-monospace, monospace"
                letterSpacing="0.18em"
                opacity={0.6}
              >
                {n.en}
              </text>
              <text
                x={n.x + n.w / 2}
                y={n.y + n.h / 2 + 14}
                fill="#0a2540"
                fontSize="14"
                fontFamily="Noto Serif SC, serif"
                fontWeight="700"
                textAnchor="middle"
              >
                {n.cn}
              </text>
              {/* 节点编号（小圆角方） */}
              {n.callout && (
                <g>
                  <circle
                    cx={n.x + n.w - 8}
                    cy={n.y - 6}
                    r={9}
                    fill="#0a2540"
                  />
                  <text
                    x={n.x + n.w - 8}
                    y={n.y - 5}
                    fill="#cbd5dc"
                    fontSize="10"
                    fontFamily="ui-monospace, monospace"
                    fontWeight="700"
                    textAnchor="middle"
                    dominantBaseline="central"
                  >
                    {n.callout}
                  </text>
                </g>
              )}
            </g>
          ))}

          {/* 流向箭头 */}
          <FlowArrow from="src" to="kafka" />
          <FlowArrow from="kafka" to="flink" />
          <FlowArrow from="flink" to="audit" />
          <FlowArrow from="audit" to="cad" mode="down" />
          <FlowArrow from="audit" to="rag" />
          <FlowArrow from="rag" to="resp" />
          <FlowArrow from="flink" to="self" mode="down" />
          <FlowArrow from="self" to="resp" mode="diag" />
          {/* 反馈闭环：响应 → 自博弈 */}
          <path
            d="M 880 158 Q 600 280 580 270"
            fill="none"
            stroke="#a8392f"
            strokeWidth={0.7}
            strokeDasharray="3 3"
            opacity={0.7}
          />
          <text
            x={620}
            y={295}
            fill="#a8392f"
            fontSize="9"
            fontFamily="ui-monospace, monospace"
            letterSpacing="0.18em"
          >
            FEEDBACK · 漏报回到检测
          </text>

          {/* Callout 引线 + 注脚 */}
          {CALLOUTS.map((c) => (
            <g key={c.n}>
              <line
                x1={c.x}
                y1={c.y - 6}
                x2={c.x + (c.n === 4 ? -90 : 0)}
                y2={c.y - 6}
                stroke="#0a2540"
                strokeWidth={0.5}
                opacity={0.5}
              />
              <text
                x={c.x}
                y={c.y + 6}
                fill="#0a2540"
                fontSize="11"
                fontFamily="Noto Serif SC, serif"
              >
                {c.label}
              </text>
              <text
                x={c.x}
                y={c.y + 19}
                fill="#0a2540"
                fontSize="9"
                fontFamily="ui-monospace, monospace"
                letterSpacing="0.16em"
                opacity={0.55}
              >
                {c.en}
              </text>
            </g>
          ))}

          {/* 尺寸标（左下角的小规范） */}
          <g opacity={0.45}>
            <line x1={40} y1={40} x2={70} y2={40} stroke="#0a2540" strokeWidth={0.4} />
            <line x1={40} y1={36} x2={40} y2={44} stroke="#0a2540" strokeWidth={0.4} />
            <line x1={70} y1={36} x2={70} y2={44} stroke="#0a2540" strokeWidth={0.4} />
            <text x={55} y={32} fill="#0a2540" fontSize="8" fontFamily="ui-monospace, monospace" textAnchor="middle">
              30 px
            </text>
          </g>

          {/* 角落标题戳 */}
          <text x={40} y={h - 16} fill="#0a2540" fontSize="10" fontFamily="ui-monospace, monospace" letterSpacing="0.22em" opacity={0.55}>
            DRAWN · S.W.SOC
          </text>
          <text x={w - 40} y={h - 16} fill="#0a2540" fontSize="10" fontFamily="ui-monospace, monospace" letterSpacing="0.22em" opacity={0.55} textAnchor="end">
            MMXXVI / SHEET 01
          </text>
        </svg>
      </div>
    </div>
  )
}

function FlowArrow({
  from,
  to,
  mode,
}: {
  from: string
  to: string
  mode?: 'down' | 'diag'
}) {
  const a = NODES.find((n) => n.id === from)!
  const b = NODES.find((n) => n.id === to)!
  let x1: number, y1: number, x2: number, y2: number
  if (mode === 'down') {
    x1 = a.x + a.w / 2; y1 = a.y + a.h
    x2 = b.x + b.w / 2; y2 = b.y
  } else if (mode === 'diag') {
    x1 = a.x + a.w; y1 = a.y + a.h / 2
    x2 = b.x; y2 = b.y + b.h / 2
  } else {
    x1 = a.x + a.w; y1 = a.y + a.h / 2
    x2 = b.x; y2 = b.y + b.h / 2
  }
  return (
    <g>
      <line
        x1={x1} y1={y1} x2={x2} y2={y2}
        stroke="#0a2540" strokeWidth={0.8} opacity={0.65}
      />
      {/* 箭头 */}
      <polygon
        points={`${x2},${y2} ${x2 - 4},${y2 - 3} ${x2 - 4},${y2 + 3}`}
        fill="#0a2540"
        opacity={0.7}
      />
    </g>
  )
}