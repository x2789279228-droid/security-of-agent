import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { RootLayout } from './layouts/RootLayout'
import { ROUTES } from './lib/constants'
import { PageTransition } from './components/common/PageTransition'
import { useAuthStore } from './stores/authStore'

const Login = lazy(() => import('./pages/Login'))
const Home = lazy(() => import('./pages/Home'))
const Logs = lazy(() => import('./pages/Logs'))
const Monitor = lazy(() => import('./pages/Monitor'))
const SecurityAudit = lazy(() => import('./pages/SecurityAudit'))
const Response = lazy(() => import('./pages/Response'))
const RAG = lazy(() => import('./pages/RAG'))
const Operations = lazy(() => import('./pages/Operations'))
// NDR 扩展
const Traffic = lazy(() => import('./pages/Traffic'))
const Encrypted = lazy(() => import('./pages/Encrypted'))
const Intel = lazy(() => import('./pages/Intel'))
const Sandbox = lazy(() => import('./pages/Sandbox'))
const EDR = lazy(() => import('./pages/EDR'))

function PageLoader() {
  return (
    <PageTransition>
      <div className="flex items-center justify-center h-[60vh] text-sm text-ink-faint font-sans">
        加载中…
      </div>
    </PageTransition>
  )
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Suspense fallback={<PageLoader />}><Login /></Suspense>} />
        <Route element={<RequireAuth><RootLayout /></RequireAuth>}>
          <Route index element={<Suspense fallback={<PageLoader />}><Home /></Suspense>} />
          <Route path={ROUTES.LOGS} element={<Suspense fallback={<PageLoader />}><Logs /></Suspense>} />
          <Route path={ROUTES.MONITOR} element={<Suspense fallback={<PageLoader />}><Monitor /></Suspense>} />
          <Route path={ROUTES.SECURITY_AUDIT} element={<Suspense fallback={<PageLoader />}><SecurityAudit /></Suspense>} />
          <Route path={ROUTES.RESPONSE} element={<Suspense fallback={<PageLoader />}><Response /></Suspense>} />
          <Route path={ROUTES.OPERATIONS} element={<Suspense fallback={<PageLoader />}><Operations /></Suspense>} />
          <Route path={ROUTES.RAG} element={<Suspense fallback={<PageLoader />}><RAG /></Suspense>} />
          {/* NDR 扩展 */}
          <Route path={ROUTES.TRAFFIC} element={<Suspense fallback={<PageLoader />}><Traffic /></Suspense>} />
          <Route path={ROUTES.ENCRYPTED} element={<Suspense fallback={<PageLoader />}><Encrypted /></Suspense>} />
          <Route path={ROUTES.INTEL} element={<Suspense fallback={<PageLoader />}><Intel /></Suspense>} />
          <Route path={ROUTES.SANDBOX} element={<Suspense fallback={<PageLoader />}><Sandbox /></Suspense>} />
          <Route path={ROUTES.EDR} element={<Suspense fallback={<PageLoader />}><EDR /></Suspense>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
