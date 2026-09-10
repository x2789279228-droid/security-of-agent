/**
 * Headless Chrome: /register UI + submit → authed home; /login link present
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
const PORT = 9335
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-reg-verify')
const USER = `u_${Date.now().toString(36)}`
const PASS = 'TestPass123!'

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
    const cdp = new CDP(page.webSocketDebuggerUrl)
    await cdp.ready()
    await cdp.send('Page.enable')
    await cdp.send('Runtime.enable')
    await cdp.send('Emulation.setDeviceMetricsOverride', {
      width: 1280,
      height: 800,
      deviceScaleFactor: 1,
      mobile: false,
    })

    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(600)
    await cdp.send('Runtime.evaluate', {
      expression: `localStorage.removeItem('sm_token'); localStorage.removeItem('sm_user');`,
    })
    await cdp.send('Page.navigate', { url: BASE + '/register' })
    let body = ''
    for (let i = 0; i < 20; i++) {
      await sleep(400)
      body = (
        await cdp.send('Runtime.evaluate', { expression: `document.body?.innerText || ''` })
      ).result?.value || ''
      if (/创建账号|确认密码/.test(body)) break
    }

    const ui = {
      hasBrand: /守望/.test(body),
      hasRegister: /注册|创建账号/.test(body),
      hasConfirm: /确认密码/.test(body),
      hasLoginLink: /去登录|已有账号/.test(body),
      hasPipeline: /接入/.test(body) && /审计/.test(body),
      bodyPreview: body.slice(0, 280),
    }

    const shot = await cdp.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'register-desktop.png'), Buffer.from(shot.data, 'base64'))

    // mismatch passwords
    await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const inputs = [...document.querySelectorAll('input')];
        const set = (el, v) => {
          const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          proto.set.call(el, v);
          el.dispatchEvent(new Event('input', { bubbles: true }));
        };
        set(inputs[0], ${JSON.stringify(USER)});
        set(inputs[1], 'aaaaaaaa');
        set(inputs[2], 'bbbbbbbb');
        document.querySelector('button[type="submit"]')?.click();
        return 'ok';
      })()`,
    })
    await sleep(800)
    body = (
      await cdp.send('Runtime.evaluate', { expression: `document.body?.innerText || ''` })
    ).result?.value || ''
    const mismatchError = /不一致/.test(body)

    // successful register
    await cdp.send('Runtime.evaluate', {
      expression: `(() => {
        const inputs = [...document.querySelectorAll('input')];
        const set = (el, v) => {
          const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          proto.set.call(el, v);
          el.dispatchEvent(new Event('input', { bubbles: true }));
        };
        set(inputs[0], ${JSON.stringify(USER)});
        set(inputs[1], ${JSON.stringify(PASS)});
        set(inputs[2], ${JSON.stringify(PASS)});
        document.querySelector('button[type="submit"]')?.click();
        return 'ok';
      })()`,
    })

    let registered = false
    for (let i = 0; i < 24; i++) {
      await sleep(500)
      const st = await cdp.send('Runtime.evaluate', {
        expression: `location.pathname + '|' + (localStorage.getItem('sm_token') ? 'authed' : 'anon')`,
      })
      const val = st.result?.value || ''
      if (val.includes('authed') && !val.startsWith('/register') && !val.startsWith('/login')) {
        registered = true
        break
      }
    }

    // login page has register link
    await cdp.send('Runtime.evaluate', {
      expression: `localStorage.removeItem('sm_token'); localStorage.removeItem('sm_user');`,
    })
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(1500)
    body = (
      await cdp.send('Runtime.evaluate', { expression: `document.body?.innerText || ''` })
    ).result?.value || ''
    const loginHasRegisterLink = /去注册|还没有账号/.test(body)

    const result = { ui, mismatchError, registered, loginHasRegisterLink, user: USER }
    console.log(JSON.stringify(result, null, 2))

    const ok =
      ui.hasBrand &&
      ui.hasRegister &&
      ui.hasConfirm &&
      ui.hasLoginLink &&
      ui.hasPipeline &&
      mismatchError &&
      registered &&
      loginHasRegisterLink

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
