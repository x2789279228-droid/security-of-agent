import { create } from 'zustand'

interface AuthState {
  token: string | null
  username: string | null
  setAuth: (token: string, username: string) => void
  logout: () => void
  isAuthenticated: () => boolean
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: localStorage.getItem('sm_token'),
  username: localStorage.getItem('sm_user'),

  setAuth: (token, username) => {
    localStorage.setItem('sm_token', token)
    localStorage.setItem('sm_user', username)
    set({ token, username })
  },

  logout: () => {
    localStorage.removeItem('sm_token')
    localStorage.removeItem('sm_user')
    set({ token: null, username: null })
  },

  isAuthenticated: () => !!get().token,
}))
