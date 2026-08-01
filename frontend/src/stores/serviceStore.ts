import { create } from 'zustand'
import type { ServiceHealth } from '../types'

interface ServiceState {
  services: Record<string, ServiceHealth>
  setService: (id: string, health: ServiceHealth) => void
  setAll: (services: Record<string, ServiceHealth>) => void
}

export const useServiceStore = create<ServiceState>((set) => ({
  services: { pgvector: 'ok', redis: 'ok', llm: 'ok' },
  setService: (id, health) =>
    set((s) => ({ services: { ...s.services, [id]: health } })),
  setAll: (services) => set({ services }),
}))
