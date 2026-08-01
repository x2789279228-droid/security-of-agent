import { Canvas } from '@react-three/fiber'
import { ParticleField } from './ParticleField'

export default function HeroScene() {
  return (
    <div className="relative w-full h-[360px] overflow-hidden rounded-2xl bg-gradient-to-b from-[#f0f2ff] to-surface">
      <Canvas
        camera={{ position: [0, 0, 4], fov: 60 }}
        dpr={[1, 1.5]}
        gl={{ antialias: false, alpha: true }}
        className="will-change-transform"
      >
        <ParticleField />
      </Canvas>
    </div>
  )
}
