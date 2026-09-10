import { spawn } from 'child_process'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..')
const CHROME = process.env.CHROME_PATH || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const BASE = process.env.MONITOR_URL || 'http://127.0.0.1:5173'
const PORT = 9345
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-selfplay-refresh')
const USER = process.env.ADMIN_USER || 'admin'
const PASS = process.env.ADMIN_PASS || 'StudyAgent2024!DB'

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

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
  close() { this.ws.close() }
}

const SNAP = `(() => {
  const url = location.href
  const match = (url.match(/match=([^&]+)/) || [])[1] || ''
  const stored = sessionStorage.getItem('sm_selfplay_match') || ''
  const selected = [...document.querySelectorAll('button')].find(b => b.className.includes('bg-ink') && /sp-/.test(b.innerText || ''))
  const selId = ((selected?.innerText || '').match(/sp-[a-z0-9]+/) || [])[0] || ''
  const body = document.body.innerText || ''
  return JSON.stringify({
    url,
    match,
    stored,
    selId,
    hasTimeline: /回合时间线/.test(body),
    emptyRounds: /尚无回合/.test(body),
    waitingRed: /等待红队出招/.test(body),
    hasStatus: /对局进行中|结束 · 胜者|状态 completed|状态 running/.test(body),
    matchCount: (body.match(/sp-/g) || []).length,
  })
})()`

async function main() {
  fs.mkdirSync(USER_DATA, { recursive: true })
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-first-run',
    '--proxy-server=direct://', '--proxy-bypass-list=<-loopback>',
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${USER_DATA}`, 'about:blank',
  ], { stdio: ['ignore', 'ignore', 'ignore'] })
  try {
    await waitPort(PORT)
    const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then((r) => r.json())
    const page = targets.find((t) => t.type === 'page') || targets[0]
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false })
    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(1200)
    await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(async () => {
        const r = await fetch('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:${JSON.stringify(USER)}, password:${JSON.stringify(PASS)}})})
        const d = await r.json().catch(()=>({}))
        if (d.access_token) { localStorage.setItem('sm_token', d.access_token); localStorage.setItem('sm_user', ${JSON.stringify(USER)}); return 'ok' }
        return 'fail:'+r.status
      })()`,
    })
    await cdp.send('Page.navigate', { url: BASE + '/self-play' })
    await sleep(2800)
    const before = JSON.parse((await cdp.send('Runtime.evaluate', { expression: SNAP })).result?.value || '{}')
    const img1 = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'selfplay-before-refresh.png'), Buffer.from(img1.data, 'base64'))
    await cdp.send('Page.reload', { ignoreCache: true })
    await sleep(2800)
    const after = JSON.parse((await cdp.send('Runtime.evaluate', { expression: SNAP })).result?.value || '{}')
    const img2 = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'selfplay-after-refresh.png'), Buffer.from(img2.data, 'base64'))
    cdp.close()
    const ok = Boolean(after.match || after.selId || after.stored) && after.hasTimeline && !after.waitingRed
    console.log(JSON.stringify({ before, after, ok }, null, 2))
    if (!ok) process.exit(1)
  } finally {
    chrome.kill()
  }
}

main().catch((e) => { console.error(e); process.exit(1) })
