import { lazy, Suspense, type ReactNode } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { RootLayout } from './layouts/RootLayout'
import { ROUTES } from './lib/constants'
import { PageTransition } from './components/common/PageTransition'
import { useAuthStore } from './stores/authStore'


const Login = lazy(() => import('./pages/Login'))
const Register = lazy(() => import('./pages/Register'))
const Home = lazy(() => import('./pages/Home'))
const Logs = lazy(() => import('./pages/Logs'))
const Monitor = lazy(() => import('./pages/Monitor'))
const SecurityAudit = lazy(() => import('./pages/SecurityAudit'))
const Response = lazy(() => import('./pages/Response'))
const RAG = lazy(() => import('./pages/RAG'))
const Operations = lazy(() => import('./pages/Operations'))
const SelfPlay = lazy(() => import('./pages/SelfPlay'))
const Traffic = lazy(() => import('./pages/Traffic'))
const Encrypted = lazy(() => import('./pages/Encrypted'))
const Intel = lazy(() => import('./pages/Intel'))
const Sandbox = lazy(() => import('./pages/Sandbox'))
const EDR = lazy(() => import('./pages/EDR'))
const CapabilitiesDashboard = lazy(() => import('./pages/CapabilitiesDashboard'))

function PageLoader() {
  return (
    <PageTransition>
      <div className="flex h-[60vh] flex-col items-center justify-center gap-3">
        <p className="font-serif text-[28px] font-black text-ink">守望</p>
        <p className="text-sm text-ink-faint">加载中</p>
      </div>
    </PageTransition>
  )
}

function Guard({ children }: { children: ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

function page(el: ReactNode, auth = true) {
  const inner = <Suspense fallback={<PageLoader />}>{el}</Suspense>
  return auth ? <Guard>{inner}</Guard> : inner
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Suspense fallback={<PageLoader />}><Login /></Suspense>} />
        <Route path="/register" element={<Suspense fallback={<PageLoader />}><Register /></Suspense>} />
        <Route element={<RootLayout />}>
          <Route index element={page(<Home />, false)} />
          <Route path={ROUTES.LOGS} element={page(<Logs />, false)} />
          <Route path={ROUTES.MONITOR} element={page(<Monitor />, false)} />
          <Route path={ROUTES.SECURITY_AUDIT} element={page(<SecurityAudit />, false)} />
          <Route path={ROUTES.RESPONSE} element={page(<Response />, false)} />
          <Route path={ROUTES.OPERATIONS} element={page(<Operations />, false)} />
          <Route path={ROUTES.SELF_PLAY} element={page(<SelfPlay />, false)} />
          <Route path={ROUTES.RAG} element={page(<RAG />, false)} />
          <Route path={ROUTES.TRAFFIC} element={page(<Traffic />, false)} />
          <Route path={ROUTES.ENCRYPTED} element={page(<Encrypted />, false)} />
          <Route path={ROUTES.INTEL} element={page(<Intel />, false)} />
          <Route path={ROUTES.SANDBOX} element={page(<Sandbox />, false)} />
          <Route path={ROUTES.EDR} element={page(<EDR />, false)} />
          <Route path={ROUTES.CAPABILITIES} element={page(<CapabilitiesDashboard />, false)} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}

