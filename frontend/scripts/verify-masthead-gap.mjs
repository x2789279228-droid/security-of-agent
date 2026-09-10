/**
 * Measure masthead-to-content gap and screenshot key routes.
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
const PORT = 9341
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-masthead-gap')
const OUT = path.join(ROOT, 'scripts')

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

async function shot(cdp, name) {
  const img = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  const dest = path.join(OUT, name)
  fs.writeFileSync(dest, Buffer.from(img.data, 'base64'))
  return dest
}

const GAP_JS = `(() => {
  const nav = document.querySelector('#root > div > header')
    || document.querySelector('header.sticky')
    || document.querySelector('header')
  const main = document.querySelector('main')
  const h1 = document.querySelector('main h1')
  const navR = nav ? nav.getBoundingClientRect() : null
  const mainR = main ? main.getBoundingClientRect() : null
  const h1R = h1 ? h1.getBoundingClientRect() : null
  const first = main && main.firstElementChild
  const firstR = first ? first.getBoundingClientRect() : null
  return JSON.stringify({
    path: location.pathname,
    nav: navR && { top: Math.round(navR.top), bottom: Math.round(navR.bottom), height: Math.round(navR.height) },
    main: mainR && { top: Math.round(mainR.top), paddingTop: getComputedStyle(main).paddingTop },
    first: firstR && { top: Math.round(firstR.top), tag: first.tagName, cls: first.className?.slice?.(0, 80) },
    h1: h1R && { top: Math.round(h1R.top), text: (h1.innerText || '').slice(0, 40) },
    gapNavToH1: navR && h1R ? Math.round(h1R.top - navR.bottom) : null,
    gapNavToMain: navR && mainR ? Math.round(mainR.top - navR.bottom) : null,
    innerTextHas: {
      title: !!(h1 && h1.innerText),
    }
  })
})()`

async function measure(cdp) {
  const r = await cdp.send('Runtime.evaluate', { expression: GAP_JS })
  try {
    return JSON.parse(r.result?.value || '{}')
  } catch {
    return { raw: r.result?.value }
  }
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

  try {
    await waitPort(PORT)
    const targets = await fetch(`http://127.0.0.1:${PORT}/json/list`).then((r) => r.json())
    const page = targets.find((t) => t.type === 'page') || targets[0]
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')

    const USER = process.env.ADMIN_USER || 'admin'
    const PASS = process.env.ADMIN_PASS || 'StudyAgent2024!DB'

    const report = { desktop: {}, mobile: {} }

    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 900, deviceScaleFactor: 1, mobile: false,
    })

    // login token into localStorage via home first
    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(1800)
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

    const routes = [
      ['/', 'gap-home.png'],
      ['/logs', 'gap-logs.png'],
      ['/monitor', 'gap-monitor.png'],
      ['/operations', 'gap-operations.png'],
      ['/response', 'gap-response.png'],
      ['/rag', 'gap-rag.png'],
      ['/self-play', 'gap-selfplay.png'],
      ['/security-audit', 'gap-audit.png'],
      ['/traffic', 'gap-traffic.png'],
    ]

    for (const [pathName, file] of routes) {
      await cdp.send('Page.navigate', { url: BASE + pathName })
      await sleep(2200)
      report.desktop[pathName] = await measure(cdp)
      await shot(cdp, file)
    }

    // click operations tab to confirm not broken
    await cdp.send('Page.navigate', { url: BASE + '/operations' })
    await sleep(1800)
    await cdp.send('Runtime.evaluate', {
      expression: `([...document.querySelectorAll('button')].find(b => b.textContent.trim() === '案例') || {click(){}}).click()`,
    })
    await sleep(800)
    report.desktop['/operations#cases'] = await measure(cdp)
    await shot(cdp, 'gap-operations-cases.png')

    await cdp.send('Page.navigate', { url: BASE + '/logs' })
    await sleep(1400)
    await cdp.send('Runtime.evaluate', {
      expression: `([...document.querySelectorAll('button')].find(b => b.textContent.trim() === '感知') || {click(){}}).click()`,
    })
    await sleep(400)
    report.desktop['sense'] = await measure(cdp)
    await shot(cdp, 'gap-sense-open.png')

    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
    })
    for (const [pathName, file] of [
      ['/', 'gap-home-mobile.png'],
      ['/logs', 'gap-logs-mobile.png'],
      ['/monitor', 'gap-monitor-mobile.png'],
    ]) {
      await cdp.send('Page.navigate', { url: BASE + pathName })
      await sleep(1800)
      report.mobile[pathName] = await measure(cdp)
      await shot(cdp, file)
    }

    await cdp.send('Runtime.evaluate', {
      expression: `([...document.querySelectorAll('button')].find(b => /Menu/i.test(b.textContent)) || {click(){}}).click()`,
    })
    await sleep(500)
    report.mobile.menu = await measure(cdp)
    await shot(cdp, 'gap-menu-mobile.png')

    cdp.close()
    const outPath = path.join(OUT, 'gap-report.json')
    fs.writeFileSync(outPath, JSON.stringify(report, null, 2))
    console.log(JSON.stringify(report, null, 2))
  } finally {
    chrome.kill()
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
