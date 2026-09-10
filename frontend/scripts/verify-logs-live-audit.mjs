/**
 * Watch Logs page audit column over a few seconds without clicking 刷新.
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
const PORT = 9343
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-logs-live-audit')

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

const SNAP_JS = `(() => {
  const rows = [...document.querySelectorAll('tbody tr')].map(tr => ({
    id: Number(tr.getAttribute('data-event-id') || 0),
    analyzed: tr.getAttribute('data-analyzed') === '1',
    audit: (tr.querySelector('td:nth-child(5)')?.innerText || '').trim(),
  }))
  const counts = { pending: 0, rule: 0, llm: 0, degraded: 0, other: 0 }
  for (const r of rows) {
    if (r.audit === '审核中') counts.pending++
    else if (r.audit === '规则') counts.rule++
    else if (r.audit === 'LLM') counts.llm++
    else if (r.audit === '降级') counts.degraded++
    else counts.other++
  }
  const bar = (document.body.innerText.match(/审计\\s+(\\d+)\\s*·\\s*降级\\s+(\\d+)\\s*·\\s*待审\\s+(\\d+)/) || [])
  return JSON.stringify({
    rows: rows.length,
    counts,
    pendingIds: rows.filter(r => !r.analyzed).map(r => r.id),
    analyzedIds: rows.filter(r => r.analyzed).map(r => r.id),
    bar: bar.length ? { reviewed: Number(bar[1]), degraded: Number(bar[2]), pending: Number(bar[3]) } : null,
    connected: /实时连接/.test(document.body.innerText),
  })
})()`

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
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 900, deviceScaleFactor: 1, mobile: false,
    })
    const USER = process.env.ADMIN_USER || 'admin'
    const PASS = process.env.ADMIN_PASS || 'StudyAgent2024!DB'
    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(1500)
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
    await cdp.send('Page.navigate', { url: BASE + '/logs' })
    await sleep(2200)
    const marker = 'LIVE-AUDIT-' + Date.now()
    const ingest = await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(async () => {
        const token = localStorage.getItem('sm_token')
        const r = await fetch('/api/logs/ingest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) },
          body: JSON.stringify({
            message: {
              event: 'PORT_SCAN',
              severity: 'medium',
              src_ip: '10.66.66.66',
              dst_ip: '10.0.0.1',
              message: ${JSON.stringify(marker)},
            },
          }),
        })
        const d = await r.json().catch(() => ({}))
        return JSON.stringify({ status: r.status, marker: ${JSON.stringify(marker)}, body: d })
      })()`,
    })
    const ingestInfo = JSON.parse(ingest.result?.value || '{}')
    const FIND_JS = `(() => {
      const tr = [...document.querySelectorAll('tbody tr')].find(row => (row.innerText || '').includes(${JSON.stringify(marker)}))
      if (!tr) return JSON.stringify({ found: false, marker: ${JSON.stringify(marker)} })
      return JSON.stringify({
        found: true,
        id: Number(tr.getAttribute('data-event-id') || 0),
        analyzed: tr.getAttribute('data-analyzed') === '1',
        audit: (tr.querySelector('td:nth-child(5)')?.innerText || '').trim(),
        connected: /实时连接/.test(document.body.innerText),
      })
    })()`
    const probes = []
    for (const wait of [800, 2000, 2500, 3000]) {
      await sleep(wait)
      const r = await cdp.send('Runtime.evaluate', { expression: FIND_JS })
      probes.push(JSON.parse(r.result?.value || '{}'))
    }
    const snaps = []
    for (const wait of [0, 4000, 4000]) {
      if (wait) await sleep(wait)
      const r = await cdp.send('Runtime.evaluate', { expression: SNAP_JS })
      snaps.push(JSON.parse(r.result?.value || '{}'))
    }
    const img = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'logs-live-audit.png'), Buffer.from(img.data, 'base64'))
    cdp.close()
    const firstIds = snaps[0]?.pendingIds || []
    const lastBySnap = snaps[snaps.length - 1]
    const lastAnalyzed = new Set(lastBySnap?.analyzedIds || [])
    const lastPresent = new Set([...(lastBySnap?.pendingIds || []), ...(lastBySnap?.analyzedIds || [])])
    const flipped = firstIds.filter((id) => lastAnalyzed.has(id))
    const vanished = firstIds.filter((id) => id && !lastPresent.has(id))
    const sawPending = probes.some((p) => p.found && p.audit === '审核中')
    const sawDone = probes.some((p) => p.found && p.analyzed)
    const maxId = (s) => Math.max(0, ...[...(s.analyzedIds || []), ...(s.pendingIds || [])])
    const idMoved = maxId(lastBySnap || {}) > maxId(snaps[0] || {})
    console.log(JSON.stringify({
      ingestInfo,
      probes,
      markerFlip: { sawPending, sawDone },
      snaps: snaps.map((s) => ({
        rows: s.rows, counts: s.counts, bar: s.bar, connected: s.connected,
        pendingN: (s.pendingIds || []).length,
        maxId: maxId(s),
      })),
      trackedPending: firstIds.length,
      flippedN: flipped.length,
      vanishedN: vanished.length,
      idMoved,
      liveOk: flipped.length > 0 || sawDone || idMoved,
    }, null, 2))
  } finally {
    chrome.kill()
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
