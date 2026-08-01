import { useMemo, useRef, useEffect } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * 威胁态势网络 — 节点(主机) + 连线(流量) + 脉冲(事件)
 * 正常流量为蓝色脉冲，攻击事件为红色脉冲并点亮目标节点。
 * attackCount 变化时注入一次红色攻击脉冲。
 */

const NODE_COUNT = 56
const PULSE_POOL = 64
const COLOR_NODE = new THREE.Color('#8fb4e8')
const COLOR_NODE_DIM = new THREE.Color('#c3c9d4')
const COLOR_PULSE = new THREE.Color('#0071e3')
const COLOR_ATTACK = new THREE.Color('#ff3b30')
const COLOR_FLASH = new THREE.Color('#ff3b30')

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
  return { nodes, edges }
}

function NetworkGraph({ attackCount }: { attackCount: number }) {
  const groupRef = useRef<THREE.Group>(null)
  const nodeMeshRef = useRef<THREE.InstancedMesh>(null)
  const pulseMeshRef = useRef<THREE.InstancedMesh>(null)

  const { nodes, edges } = useMemo(buildGraph, [])

  const pulses = useRef<Pulse[]>(
    Array.from({ length: PULSE_POOL }, () => ({
      edge: 0, t: 0, speed: 0, attack: false, active: false,
    })),
  )
  const nodeFlash = useRef(new Float32Array(NODE_COUNT))
  const spawnTimer = useRef(0)
  const dummy = useMemo(() => new THREE.Object3D(), [])
  const tmpColor = useMemo(() => new THREE.Color(), [])

  // 初始化节点实例
  useEffect(() => {
    if (!nodeMeshRef.current) return
    nodes.forEach((n, i) => {
      dummy.position.copy(n)
      dummy.scale.setScalar(0.055 + Math.random() * 0.03)
      dummy.updateMatrix()
      nodeMeshRef.current!.setMatrixAt(i, dummy.matrix)
      nodeMeshRef.current!.setColorAt(i, tmpColor.copy(COLOR_NODE_DIM).lerp(COLOR_NODE, Math.random()))
    })
    nodeMeshRef.current.instanceMatrix.needsUpdate = true
    if (nodeMeshRef.current.instanceColor) nodeMeshRef.current.instanceColor.needsUpdate = true
  }, [nodes, dummy, tmpColor])

  // 攻击信号 → 注入红色脉冲
  useEffect(() => {
    if (attackCount <= 0) return
    for (let n = 0; n < 3; n++) {
      const p = pulses.current.find((x) => !x.active)
      if (p) {
        p.active = true
        p.edge = Math.floor(Math.random() * edges.length)
        p.t = 0
        p.speed = 0.5 + Math.random() * 0.4
        p.attack = true
      }
    }
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
    // 缓慢自转 + 呼吸浮动
    groupRef.current.rotation.y = clock.getElapsedTime() * 0.06
    groupRef.current.position.y = Math.sin(clock.getElapsedTime() * 0.5) * 0.08

    // 定时生成正常脉冲
    spawnTimer.current += delta
    if (spawnTimer.current > 0.18) {
      spawnTimer.current = 0
      spawnNormal()
      spawnNormal()
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
        }
        p.active = false
        continue
      }
      const [a, b] = edges[p.edge]
      dummy.position.lerpVectors(nodes[a], nodes[b], p.t)
      dummy.scale.setScalar(p.attack ? 0.11 : 0.07)
      dummy.updateMatrix()
      pulseMeshRef.current.setMatrixAt(visible, dummy.matrix)
      pulseMeshRef.current.setColorAt(visible, tmpColor.copy(p.attack ? COLOR_ATTACK : COLOR_PULSE))
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

    // 节点闪烁衰减
    if (nodeMeshRef.current) {
      let changed = false
      for (let i = 0; i < NODE_COUNT; i++) {
        if (nodeFlash.current[i] > 0.001) {
          nodeFlash.current[i] = Math.max(0, nodeFlash.current[i] - delta * 1.2)
          const f = nodeFlash.current[i]
          nodeMeshRef.current.setColorAt(
            i,
            tmpColor.copy(COLOR_NODE).lerp(COLOR_FLASH, f),
          )
          changed = true
        }
      }
      if (changed && nodeMeshRef.current.instanceColor) {
        nodeMeshRef.current.instanceColor.needsUpdate = true
      }
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
        <lineBasicMaterial color="#0071e3" transparent opacity={0.1} />
      </lineSegments>
      <instancedMesh ref={nodeMeshRef} args={[undefined, undefined, NODE_COUNT]}>
        <sphereGeometry args={[1, 12, 12]} />
        <meshBasicMaterial toneMapped={false} />
      </instancedMesh>
      <instancedMesh ref={pulseMeshRef} args={[undefined, undefined, PULSE_POOL]}>
        <sphereGeometry args={[1, 10, 10]} />
        <meshBasicMaterial toneMapped={false} transparent opacity={0.9} />
      </instancedMesh>
    </group>
  )
}

export default function ThreatNetwork({ attackCount }: { attackCount: number }) {
  return (
    <div className="relative w-full h-[420px] overflow-hidden">
      {/* 柔和径向背景，突出中心网络 */}
      <div
        className="absolute inset-0"
        style={{
          background: 'radial-gradient(ellipse 70% 60% at 50% 45%, rgba(0,113,227,0.06) 0%, rgba(245,245,247,0) 70%)',
        }}
      />
      <Canvas
        camera={{ position: [0, 0.6, 11], fov: 50 }}
        dpr={[1, 2]}
        gl={{ antialias: true, alpha: true }}
      >
        <NetworkGraph attackCount={attackCount} />
      </Canvas>
      {/* 底部渐隐，融入页面 */}
      <div className="absolute bottom-0 left-0 right-0 h-16 bg-gradient-to-t from-surface to-transparent pointer-events-none" />
    </div>
  )
}
