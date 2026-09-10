import { Canvas } from '@react-three/fiber'
import { ParticleField } from './ParticleField'

export default function HeroScene({ className = '' }: { className?: string }) {
  return (
    <div
      className={`relative w-full h-full overflow-hidden bg-gradient-to-b from-surface to-qing ${className}`}
    >
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
