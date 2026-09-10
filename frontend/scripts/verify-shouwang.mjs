/**
 * Headless Chrome: screenshot login / home / monitor for 守望 visual QA
 */
import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')
const CHROME =
  process.env.CHROME_PATH ||
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const BASE = process.env.MONITOR_URL || 'http://127.0.0.1:5173'
const PORT = 9340
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-shouwang-verify')

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms))
}

async function waitPort(port, tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json/version`)
      if (r.ok) return r.json()
    } catch {}
    await sleep(250)
  }
  throw new Error('Chrome CDP not ready')
}

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl)
    this.id = 0
    this.pending = new Map()
    this.ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString())
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id)
        this.pending.delete(msg.id)
        if (msg.error) reject(new Error(JSON.stringify(msg.error)))
        else resolve(msg.result)
      }
    })
  }
  ready() {
    if (this.ws.readyState === WebSocket.OPEN) return Promise.resolve()
    return new Promise((resolve, reject) => {
      this.ws.addEventListener('open', () => resolve(), { once: true })
      this.ws.addEventListener('error', (e) => reject(e), { once: true })
    })
  }
  send(method, params = {}) {
    const id = ++this.id
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.ws.send(JSON.stringify({ id, method, params }))
    })
  }
  close() {
    this.ws.close()
  }
}

async function bodyText(cdp) {
  const r = await cdp.send('Runtime.evaluate', { expression: `document.body?.innerText || ''` })
  return r.result?.value || ''
}

async function shot(cdp, name) {
  const img = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  const dest = path.join(ROOT, 'scripts', name)
  fs.writeFileSync(dest, Buffer.from(img.data, 'base64'))
  return dest
}

async function main() {
  fs.mkdirSync(USER_DATA, { recursive: true })
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--proxy-server=direct://',
      '--proxy-bypass-list=<-loopback>',
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${USER_DATA}`,
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'ignore'] },
  )

  const fail = []
  try {
    await waitPort(PORT)
    const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then((r) => r.json())
    const page = targets.find((t) => t.type === 'page') || targets[0]
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 1100, deviceScaleFactor: 1, mobile: false,
    })

    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(4000)
    const loginBody = await bodyText(cdp)
    await shot(cdp, 'shouwang-login.png')
    if (!/守望/.test(loginBody)) fail.push('login missing 守望')
    if (/共享记忆/.test(loginBody)) fail.push('login still has 共享记忆')

    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(2800)
    const homeBody = await bodyText(cdp)
    await shot(cdp, 'shouwang-home.png')
    await cdp.send('Runtime.evaluate', { expression: 'window.scrollTo(0, 720)' })
    await sleep(800)
    await shot(cdp, 'shouwang-home-kpis.png')
    if (!/守望/.test(homeBody)) fail.push('home missing 守望')
    if (!/SHOUWANG|Night Watch/.test(homeBody)) fail.push('home missing english lockup')
    if (/共享记忆|Monochrome/.test(homeBody)) fail.push('home leftover old brand')
    if (!/待处理|进入控制台/.test(homeBody)) fail.push('home missing KPI/CTA')

    const USER = process.env.ADMIN_USER || 'admin'
    const PASS = process.env.ADMIN_PASS || 'StudyAgent2024!DB'
    await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(async () => {
        const r = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: ${JSON.stringify(USER)}, password: ${JSON.stringify(PASS)} }),
        })
        const d = await r.json().catch(() => ({}))
        if (d.access_token) {
          localStorage.setItem('sm_token', d.access_token)
          localStorage.setItem('sm_user', ${JSON.stringify(USER)})
          return 'ok'
        }
        return 'fail:' + r.status
      })()`,
    })

    await cdp.send('Page.navigate', { url: BASE + '/monitor' })
    await sleep(4000)
    const monBody = await bodyText(cdp)
    await shot(cdp, 'shouwang-monitor.png')
    if (!/系统监控|审查接力/.test(monBody)) fail.push('monitor missing title')
    if (!/待处理|已分析/.test(monBody)) fail.push('monitor missing KPIs')
    if (/共享记忆/.test(monBody)) fail.push('monitor leftover old brand')

    await cdp.send('Page.navigate', { url: BASE + '/register' })
    await sleep(1800)
    await shot(cdp, 'shouwang-register.png')

    await cdp.send('Page.navigate', { url: BASE + '/logs' })
    await sleep(2200)
    await shot(cdp, 'shouwang-logs.png')

    await cdp.send('Page.navigate', { url: BASE + '/operations' })
    await sleep(2200)
    await shot(cdp, 'shouwang-operations.png')

    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
    })
    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(2200)
    await shot(cdp, 'shouwang-home-mobile.png')
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(1600)
    await shot(cdp, 'shouwang-login-mobile.png')

    cdp.close()
    console.log(JSON.stringify({
      ok: fail.length === 0,
      fail,
      loginHasShouwang: /守望/.test(loginBody),
      homeHasShouwang: /守望/.test(homeBody),
      monitorHasPending: /待处理/.test(monBody),
      shots: [
        'shouwang-login.png',
        'shouwang-home.png',
        'shouwang-monitor.png',
        'shouwang-register.png',
        'shouwang-logs.png',
        'shouwang-operations.png',
        'shouwang-home-mobile.png',
        'shouwang-login-mobile.png',
      ],
    }, null, 2))
    if (fail.length) process.exit(1)
  } finally {
    chrome.kill()
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
