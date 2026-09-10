import { Component, useEffect, useMemo, useRef, type ReactNode } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls } from '@react-three/drei'
import * as THREE from 'three'

/**
 * 威胁态势网络 — 守望 · 白昼台账 主视觉
 *
 * 白昼雾场 #E8EEF2 上的节点网：松绿/暮青健康节点、暮青灰正常脉冲、
 * 朱砂攻击脉冲（更大、更多、命中点亮目标），攻击时连线提亮。
 * NormalBlending 低透明度辉光（加法混合只在黑底上成立）。
 * OrbitControls 缓慢自转，可拖拽/缩放。
 * 守望色板：暮青 #3A6570 / 松绿 #3E7A64 / 朱砂 #C23A32 / 青底 #E8EEF2。
 * attackCount 变化时注入一波攻击脉冲（保持既有 API）。
 */

const NODE_COUNT = 56
const PULSE_POOL = 64
const ATTACK_BURST = 4

const COLOR_OK = new THREE.Color('#3E7A64')
const COLOR_OK_DIM = new THREE.Color('#5C7A82')
const COLOR_ATTACK = new THREE.Color('#C23A32')

interface Pulse {
  edge: number
  t: number
  speed: number
  attack: boolean
  active: boolean
}

function buildGraph() {
  const nodes: THREE.Vector3[] = []
  for (let i = 0; i < NODE_COUNT; i++) {
    // 扁平椭球云，适配宽幅容器
    const a = Math.random() * Math.PI * 2
    const r = Math.pow(Math.random(), 0.6)
    nodes.push(new THREE.Vector3(
      Math.cos(a) * r * 7.2,
      (Math.random() - 0.5) * 3.4,
      Math.sin(a) * r * 3.2,
    ))
  }
  // 每个节点连接最近的 1-2 个邻居
  const edgeSet = new Set<string>()
  const edges: [number, number][] = []
  for (let i = 0; i < NODE_COUNT; i++) {
    const dists = nodes
      .map((n, j) => ({ j, d: nodes[i].distanceTo(n) }))
      .filter((x) => x.j !== i)
      .sort((a, b) => a.d - b.d)
    const k = 1 + (i % 2)
    for (let m = 0; m < k; m++) {
      const j = dists[m].j
      const key = i < j ? `${i}-${j}` : `${j}-${i}`
      if (!edgeSet.has(key)) {
        edgeSet.add(key)
        edges.push([i, j])
      }
    }
  }
  // 度数 → 枢纽节点更大更亮，避免"全员同款小球"
  const degree = new Array(NODE_COUNT).fill(0)
  for (const [a, b] of edges) {
    degree[a] += 1
    degree[b] += 1
  }
  return { nodes, edges, degree }
}

function NetworkGraph({ attackCount }: { attackCount: number }) {
  const groupRef = useRef<THREE.Group>(null)
  const nodeMeshRef = useRef<THREE.InstancedMesh>(null)
  const glowMeshRef = useRef<THREE.InstancedMesh>(null)
  const pulseMeshRef = useRef<THREE.InstancedMesh>(null)
  const edgeMatRef = useRef<THREE.LineBasicMaterial>(null)

  const { nodes, edges, degree } = useMemo(buildGraph, [])

  // 每节点基色 / 基础尺度 / 辉光相位
  const nodeBase = useMemo(() => {
    const colors: THREE.Color[] = []
    const scales: number[] = []
    const phases: number[] = []
    for (let i = 0; i < NODE_COUNT; i++) {
      colors.push(
        new THREE.Color().copy(COLOR_OK_DIM).lerp(COLOR_OK, 0.45 + Math.random() * 0.55),
      )
      scales.push(0.05 + degree[i] * 0.03 + Math.random() * 0.025)
      phases.push(Math.random() * Math.PI * 2)
    }
    return { colors, scales, phases }
  }, [degree])

  const pulses = useRef<Pulse[]>(
    Array.from({ length: PULSE_POOL }, () => ({
      edge: 0, t: 0, speed: 0, attack: false, active: false,
    })),
  )
  const nodeFlash = useRef(new Float32Array(NODE_COUNT))
  const attackEnergy = useRef(0)
  const spawnTimer = useRef(0)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const tmpColor = useMemo(() => new THREE.Color(), [])

  // 初始化节点与辉光实例
  useEffect(() => {
    if (!nodeMeshRef.current || !glowMeshRef.current) return
    nodes.forEach((n, i) => {
      const s = nodeBase.scales[i]
      dummy.position.copy(n)
      dummy.scale.setScalar(s)
      dummy.updateMatrix()
      nodeMeshRef.current!.setMatrixAt(i, dummy.matrix)
      nodeMeshRef.current!.setColorAt(i, tmpColor.copy(nodeBase.colors[i]))

      dummy.scale.setScalar(s * 3.6)
      dummy.updateMatrix()
      glowMeshRef.current!.setMatrixAt(i, dummy.matrix)
      glowMeshRef.current!.setColorAt(i, tmpColor.copy(nodeBase.colors[i]))
    })
    nodeMeshRef.current.instanceMatrix.needsUpdate = true
    if (nodeMeshRef.current.instanceColor) nodeMeshRef.current.instanceColor.needsUpdate = true
    glowMeshRef.current.instanceMatrix.needsUpdate = true
    if (glowMeshRef.current.instanceColor) glowMeshRef.current.instanceColor.needsUpdate = true
  }, [nodes, nodeBase, dummy, tmpColor])

  // 攻击信号 → 注入一波朱砂脉冲并抬升连线能量
  useEffect(() => {
    if (attackCount <= 0) return
    let spawned = 0
    for (const p of pulses.current) {
      if (spawned >= ATTACK_BURST) break
      if (p.active) continue
      p.active = true
      p.edge = Math.floor(Math.random() * edges.length)
      p.t = 0
      p.speed = 0.5 + Math.random() * 0.4
      p.attack = true
      spawned++
    }
    attackEnergy.current = Math.min(1.4, attackEnergy.current + 0.6)
  }, [attackCount, edges.length])

  const spawnNormal = () => {
    const p = pulses.current.find((x) => !x.active)
    if (p) {
      p.active = true
      p.edge = Math.floor(Math.random() * edges.length)
      p.t = 0
      p.speed = 0.25 + Math.random() * 0.35
      p.attack = false
    }
  }

  useFrame(({ clock }, delta) => {
    if (!groupRef.current || !pulseMeshRef.current) return

    // 呼吸浮动（自转交给 OrbitControls.autoRotate，避免双重旋转）
    groupRef.current.position.y = Math.sin(clock.getElapsedTime() * 0.5) * 0.08

    // 定时生成正常脉冲
    spawnTimer.current += delta
    if (spawnTimer.current > 0.15) {
      spawnTimer.current = 0
      spawnNormal()
      spawnNormal()
    }

    // 攻击能量衰减 → 连线提亮
    attackEnergy.current = Math.max(0, attackEnergy.current - delta * 0.55)
    if (edgeMatRef.current) {
      edgeMatRef.current.opacity = Math.min(0.42, 0.16 + attackEnergy.current * 0.3)
    }

    // 更新脉冲
    let visible = 0
    for (let i = 0; i < PULSE_POOL; i++) {
      const p = pulses.current[i]
      if (!p.active) continue
      p.t += p.speed * delta
      if (p.t >= 1) {
        // 到达终点：攻击则点亮目标节点
        if (p.attack) {
          const [, b] = edges[p.edge]
          nodeFlash.current[b] = 1
          attackEnergy.current = Math.min(1.4, attackEnergy.current + 0.12)
        }
        p.active = false
        continue
      }
      const [a, b] = edges[p.edge]
      dummy.position.lerpVectors(nodes[a], nodes[b], p.t)
      dummy.scale.setScalar(p.attack ? 0.16 : 0.07)
      dummy.updateMatrix()
      pulseMeshRef.current.setMatrixAt(visible, dummy.matrix)
      pulseMeshRef.current.setColorAt(visible, tmpColor.copy(p.attack ? COLOR_ATTACK : COLOR_OK))
      visible++
    }
    // 隐藏多余实例
    for (let i = visible; i < PULSE_POOL; i++) {
      dummy.position.set(0, 0, -9999)
      dummy.scale.setScalar(0.0001)
      dummy.updateMatrix()
      pulseMeshRef.current.setMatrixAt(i, dummy.matrix)
    }
    pulseMeshRef.current.count = PULSE_POOL
    pulseMeshRef.current.instanceMatrix.needsUpdate = true
    if (pulseMeshRef.current.instanceColor) pulseMeshRef.current.instanceColor.needsUpdate = true

    // 节点闪烁衰减 + 辉光呼吸
    if (nodeMeshRef.current && glowMeshRef.current) {
      const t = clock.getElapsedTime()
      for (let i = 0; i < NODE_COUNT; i++) {
        const f = nodeFlash.current[i]
        if (f > 0.001) {
          nodeFlash.current[i] = Math.max(0, f - delta * 1.2)
        }
        const base = nodeBase.colors[i]
        const breathe = 1 + Math.sin(t * 2 + nodeBase.phases[i]) * 0.08

        nodeMeshRef.current.setColorAt(i, tmpColor.copy(base).lerp(COLOR_ATTACK, nodeFlash.current[i]))

        dummy.position.copy(nodes[i])
        dummy.scale.setScalar(nodeBase.scales[i] * 3.6 * breathe * (1 + nodeFlash.current[i] * 1.4))
        dummy.updateMatrix()
        glowMeshRef.current.setMatrixAt(i, dummy.matrix)
        glowMeshRef.current.setColorAt(i, tmpColor.copy(base).lerp(COLOR_ATTACK, nodeFlash.current[i]))
      }
      if (nodeMeshRef.current.instanceColor) nodeMeshRef.current.instanceColor.needsUpdate = true
      glowMeshRef.current.instanceMatrix.needsUpdate = true
      if (glowMeshRef.current.instanceColor) glowMeshRef.current.instanceColor.needsUpdate = true
    }
  })

  // 连线几何
  const edgeGeometry = useMemo(() => {
    const geo = new THREE.BufferGeometry()
    const pos = new Float32Array(edges.length * 6)
    edges.forEach(([a, b], i) => {
      pos[i * 6] = nodes[a].x; pos[i * 6 + 1] = nodes[a].y; pos[i * 6 + 2] = nodes[a].z
      pos[i * 6 + 3] = nodes[b].x; pos[i * 6 + 4] = nodes[b].y; pos[i * 6 + 5] = nodes[b].z
    })
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
    return geo
  }, [edges, nodes])

  return (
    <group ref={groupRef}>
      <lineSegments geometry={edgeGeometry}>
        <lineBasicMaterial
          ref={edgeMatRef}
          color="#5C7A82"
          transparent
          opacity={0.16}
          depthWrite={false}
        />
      </lineSegments>
      {/* 辉光层：大半径低透明度法向混合，白昼雾场上以柔和色晕呈现节点 */}
      <instancedMesh ref={glowMeshRef} args={[undefined, undefined, NODE_COUNT]}>
        <sphereGeometry args={[1, 12, 12]} />
        <meshBasicMaterial
          toneMapped={false}
          transparent
          opacity={0.1}
          blending={THREE.NormalBlending}
          depthWrite={false}
        />
      </instancedMesh>
      <instancedMesh ref={nodeMeshRef} args={[undefined, undefined, NODE_COUNT]}>
        <sphereGeometry args={[1, 12, 12]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
      <instancedMesh ref={pulseMeshRef} args={[undefined, undefined, PULSE_POOL]}>
        <sphereGeometry args={[1, 10, 10]} />
        <meshBasicMaterial
          toneMapped={false}
          transparent
          opacity={0.85}
          blending={THREE.NormalBlending}
          depthWrite={false}
        />
      </instancedMesh>
    </group>
  )
}

/** WebGL 失败时的兜底：不阻断监控页其余部分 */
class CanvasGuard extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  render() {
    if (this.state.failed) {
      return (
        <div className="flex h-full w-full items-center justify-center bg-qing text-[12px] text-ink-faint">
          威胁态势网络渲染不可用（WebGL 初始化失败），事件流监控不受影响。
        </div>
      )
    }
    return this.props.children
  }
}

export default function ThreatNetwork({
  attackCount,
  chrome = true,
  className = '',
}: {
  attackCount: number
  chrome?: boolean
  className?: string
}) {
  return (
    <div
      className={`relative w-full overflow-hidden bg-qing ${
        chrome ? 'h-[360px] rounded-2xl border border-line/70 lg:h-[440px]' : 'h-full'
      } ${className}`}
    >
      <CanvasGuard>
        <Canvas
          camera={{ position: [0, 1.4, 11.5], fov: 50 }}
          dpr={[1, 2]}
          gl={{ antialias: true, alpha: true }}
        >
          <color attach="background" args={['#E8EEF2']} />
          <fog attach="fog" args={['#E8EEF2', 13, 26]} />
          <NetworkGraph attackCount={attackCount} />
          <OrbitControls
            enablePan={false}
            enableDamping
            dampingFactor={0.08}
            autoRotate
            autoRotateSpeed={0.4}
            minDistance={7}
            maxDistance={18}
          />
        </Canvas>
      </CanvasGuard>

      {chrome && (
        <div className="pointer-events-none absolute inset-0 z-10">
          <div className="absolute left-4 top-3 flex items-center gap-2 font-mono text-[10px] tracking-[0.22em] text-accent/80">
            <span className="relative flex h-1.5 w-1.5">
              <span className="absolute inset-0 animate-ping rounded-full bg-accent opacity-60" />
              <span className="relative h-1.5 w-1.5 rounded-full bg-accent" />
            </span>
            威胁态势 · THREAT NETWORK
          </div>
          <div className="absolute bottom-3 right-4 font-mono text-[10px] text-ink-faint">
            拖拽旋转 · 滚轮缩放
          </div>
        </div>
      )}
    </div>
  )
}
