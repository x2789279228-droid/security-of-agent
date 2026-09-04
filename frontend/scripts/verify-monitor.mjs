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
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(2000)

    // Fill login form via DOM
    await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(() => {
        const inputs = [...document.querySelectorAll('input')];
        const user = inputs.find(i => i.type === 'text' || i.name?.includes('user') || i.placeholder?.includes('用户') || i.placeholder?.toLowerCase().includes('user')) || inputs[0];
        const pass = inputs.find(i => i.type === 'password') || inputs[1];
        if (!user || !pass) return 'no-inputs:' + inputs.length;
        const set = (el, v) => {
          const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          proto.set.call(el, v);
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        };
        set(user, ${JSON.stringify(USER)});
        set(pass, ${JSON.stringify(PASS)});
        const btn = [...document.querySelectorAll('button')].find(b => /登录|login/i.test(b.textContent || ''));
        if (btn) btn.click();
        else (user.form && user.form.requestSubmit()) || document.querySelector('form')?.requestSubmit();
        return 'submitted';
      })()`,
    })

    // Wait for navigation / token
    for (let i = 0; i < 20; i++) {
      await sleep(500)
      const loc = await cdp.send('Runtime.evaluate', {
        expression: `location.pathname + '|' + (localStorage.getItem('sm_token') ? 'authed' : 'anon')`,
      })
      const val = loc.result?.value || ''
      if (val.includes('authed') && !val.includes('/login')) break
      if (i === 19) console.log('login state:', val)
    }

    await cdp.send('Page.navigate', { url: BASE + '/monitor' })
    await sleep(2500)

    const text = await cdp.send('Runtime.evaluate', {
      expression: `document.body?.innerText || ''`,
    })
    const body = text.result?.value || ''
    const checks = {
      hasRelayTitle: /多\s*Agent|审查接力|Agent/.test(body),
      hasStages: /分解|工具|执行|复核|CAD|响应/.test(body),
      notOldPipeline: !/服务端事件总线/.test(body),
      hasStream: /实时|事件|缓冲|连接/.test(body),
    }
    console.log(JSON.stringify({ checks, bodyPreview: body.slice(0, 600) }, null, 2))

    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' })
    const out = path.join(ROOT, 'scripts', 'monitor-verify.png')
    fs.writeFileSync(out, Buffer.from(shot.data, 'base64'))
    console.log('screenshot', out)

    const ok = checks.hasRelayTitle && checks.hasStages && checks.notOldPipeline
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
