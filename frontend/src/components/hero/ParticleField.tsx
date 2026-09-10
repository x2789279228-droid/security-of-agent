import { useMemo, useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { useReducedMotion } from 'framer-motion'
import * as THREE from 'three'

export function ParticleField() {
  const count = 240
  const meshRef = useRef<THREE.Points>(null)
  const reduced = useReducedMotion()

  const geometry = useMemo(() => {
    const geo = new THREE.BufferGeometry()
    const positions = new Float32Array(count * 3)
    const sizes = new Float32Array(count)
    for (let i = 0; i < count; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 10
      positions[i * 3 + 1] = (Math.random() - 0.5) * 6
      positions[i * 3 + 2] = (Math.random() - 0.5) * 6
      sizes[i] = Math.random() * 3 + 1
    }
    geo.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geo.setAttribute('size', new THREE.BufferAttribute(sizes, 1))
    return geo
  }, [count])

  useFrame(({ clock }) => {
    if (reduced || !meshRef.current) return
    const t = clock.getElapsedTime()
    const pos = meshRef.current.geometry.attributes.position.array as Float32Array
    for (let i = 0; i < count; i++) {
      const i3 = i * 3
      pos[i3 + 1] += Math.sin(t + i) * 0.0003
      pos[i3] += Math.cos(t + i * 0.5) * 0.0003
    }
    meshRef.current.geometry.attributes.position.needsUpdate = true
  })

  return (
    <points ref={meshRef} geometry={geometry}>
      <pointsMaterial
        size={0.06}
        color="#3A6570"
        transparent
        opacity={0.28}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.NormalBlending}
      />
    </points>
  )
}
