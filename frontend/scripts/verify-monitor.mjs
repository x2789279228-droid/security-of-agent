/**
 * Headless Chrome CDP smoke: login → /monitor → assert Agent relay UI text
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
const BASE = process.env.MONITOR_URL || 'http://127.0.0.1:3010'
const USER = process.env.ADMIN_USER || 'admin'
const PASS = process.env.ADMIN_PASS || 'StudyAgent2024!DB'
const PORT = 9333
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-mon-verify2')

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

async function main() {
  fs.mkdirSync(USER_DATA, { recursive: true })
  const chrome = spawn(
    CHROME,
    [
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
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
    if (!page?.webSocketDebuggerUrl) throw new Error('no page target: ' + JSON.stringify(targets))
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('DOM.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 1600, deviceScaleFactor: 1, mobile: false,
    })
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(1500)

    const loginRes = await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(async () => {
        const r = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: ${JSON.stringify(USER)}, password: ${JSON.stringify(PASS)} }),
        })
        const d = await r.json()
        if (!d.access_token) return 'fail:' + r.status
        localStorage.setItem('sm_token', d.access_token)
        localStorage.setItem('sm_user', ${JSON.stringify(USER)})
        return 'ok'
      })()`,
    })
    console.log('api-login', loginRes.result?.value || loginRes)

    await cdp.send('Page.navigate', { url: BASE + '/monitor' })
    await sleep(3500)

    const text = await cdp.send('Runtime.evaluate', {
      expression: `document.body?.innerText || ''`,
    })
    const body = text.result?.value || ''
    const checks = {
      hasRelayTitle: /多\s*Agent|审查接力|Agent/.test(body),
      hasStages: /分解|工具|执行|复核|CAD|响应/.test(body),
      notOldPipeline: !/服务端事件总线/.test(body),
      hasStream: /实时|事件|缓冲|连接/.test(body),
      hasIdleOrRecent: /最近完成|当前没有进行中的审查接力|跑一条演示审查|思维链/.test(body),
      hasThoughtOrDemo: /思维链|#\d+|跑一条演示审查/.test(body),
    }
    console.log(JSON.stringify({ checks, bodyPreview: body.slice(0, 600) }, null, 2))

    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' })
    const out = path.join(ROOT, 'scripts', 'monitor-verify.png')
    fs.writeFileSync(out, Buffer.from(shot.data, 'base64'))
    console.log('screenshot', out)

    const clickDemo = await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const btn = [...document.querySelectorAll('button')].find(b => /跑一条演示审查/.test(b.textContent || ''))
        if (!btn) return 'no-btn'
        btn.click()
        return 'clicked'
      })()`,
    })
    console.log('demo-click', clickDemo.result?.value)
    await sleep(4000)
    const after = await cdp.send('Runtime.evaluate', {
      expression: `document.body?.innerText || ''`,
    })
    const afterBody = after.result?.value || ''
    checks.demoStarted = /演示启动|演示审查启动|进行中的审查接力|思维链\s*#/.test(afterBody)
    console.log('after-demo', {
      demoStarted: checks.demoStarted,
      preview: afterBody.replace(/\s+/g, ' ').slice(0, 800),
    })
    const shot2 = await cdp.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'monitor-verify-demo.png'), Buffer.from(shot2.data, 'base64'))

    const ok = checks.hasRelayTitle && checks.hasStages && checks.notOldPipeline && checks.hasIdleOrRecent && checks.hasThoughtOrDemo
    if (!ok) {
      console.error('VERIFY_FAILED')
      process.exitCode = 1
    } else {
      console.log('VERIFY_OK')
    }
    cdp.close()
  } finally {
    chrome.kill()
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
