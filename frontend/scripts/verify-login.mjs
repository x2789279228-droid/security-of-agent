/**
 * Headless Chrome: /login desktop + mobile checks
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
const PORT = 9334
const USER_DATA = path.join(process.env.TEMP || '/tmp', 'chrome-login-verify')

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

async function setViewport(cdp, width, height) {
  await cdp.send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: 1,
    mobile: width < 800,
  })
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

    // Desktop — clear auth before opening login (avoid authed redirect to Home)
    await setViewport(cdp, 1280, 800)
    await cdp.send('Page.navigate', { url: BASE + '/' })
    await sleep(800)
    await cdp.send('Runtime.evaluate', {
      expression: `localStorage.removeItem('sm_token'); localStorage.removeItem('sm_user');`,
    })
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(2000)

    let body = await bodyText(cdp)
    const desktop = {
      hasBrand: /守望/.test(body),
      hasSlogan: /多 Agent|审查接力|安全审计/.test(body),
      hasPipeline: /接入/.test(body) && /审计/.test(body) && /响应/.test(body),
      hasLogin: /进入系统|登录/.test(body),
      notOldPlaceholder: !/搜索身份/.test(body),
    }

    const shotDesk = await cdp.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'login-desktop.png'), Buffer.from(shotDesk.data, 'base64'))

    // Wrong password
    await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(() => {
        const inputs = [...document.querySelectorAll('input')];
        const user = inputs.find(i => i.type === 'text' || i.autocomplete === 'username') || inputs[0];
        const pass = inputs.find(i => i.type === 'password' || i.autocomplete === 'current-password') || inputs[1];
        const set = (el, v) => {
          const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          proto.set.call(el, v);
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        };
        set(user, 'admin');
        set(pass, 'wrong-password-xxx');
        document.querySelector('button[type="submit"]')?.click();
        return 'ok';
      })()`,
    })
    await sleep(2500)
    body = await bodyText(cdp)
    const errorShown = /用户名或密码错误|无法连接|错误/.test(body)

    // Toggle show password
    await cdp.send('Runtime.evaluate', {
      expression: `([...document.querySelectorAll('button')].find(b => /显示|隐藏/.test(b.textContent||''))||{click:()=>{}}).click(); 'toggled'`,
    })
    await sleep(300)
    const passType = await cdp.send('Runtime.evaluate', {
      expression: `document.querySelector('input[autocomplete="current-password"]')?.type || document.querySelectorAll('input')[1]?.type || ''`,
    })

    // Correct login
    await cdp.send('Runtime.evaluate', {
      awaitPromise: true,
      expression: `(() => {
        const inputs = [...document.querySelectorAll('input')];
        const user = inputs[0];
        const pass = inputs[1];
        const set = (el, v) => {
          const proto = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
          proto.set.call(el, v);
          el.dispatchEvent(new Event('input', { bubbles: true }));
          el.dispatchEvent(new Event('change', { bubbles: true }));
        };
        set(user, ${JSON.stringify(USER)});
        set(pass, ${JSON.stringify(PASS)});
        // ensure password type for submit
        if (pass && pass.type === 'text') {
          ([...document.querySelectorAll('button')].find(b => /隐藏/.test(b.textContent||''))||{}).click?.();
        }
        document.querySelector('button[type="submit"]')?.click();
        return 'submitted';
      })()`,
    })
    let loggedIn = false
    for (let i = 0; i < 20; i++) {
      await sleep(500)
      const st = await cdp.send('Runtime.evaluate', {
        expression: `location.pathname + '|' + (localStorage.getItem('sm_token') ? 'authed' : 'anon')`,
      })
      const val = st.result?.value || ''
      if (val.includes('authed') && !val.startsWith('/login')) {
        loggedIn = true
        break
      }
    }

    // Already-authed redirect
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(1500)
    const afterAuth = await cdp.send('Runtime.evaluate', {
      expression: `location.pathname`,
    })
    const redirected = (afterAuth.result?.value || '') !== '/login'

    // Mobile viewport
    await cdp.send('Runtime.evaluate', {
      expression: `localStorage.removeItem('sm_token'); localStorage.removeItem('sm_user');`,
    })
    await setViewport(cdp, 390, 844)
    await cdp.send('Page.navigate', { url: BASE + '/login' })
    await sleep(2000)
    body = await bodyText(cdp)
    const mobile = {
      hasBrand: /守望/.test(body),
      hasLogin: /进入系统|登录/.test(body),
      hasPipeline: /接入/.test(body),
    }
    const shotMob = await cdp.send('Page.captureScreenshot', { format: 'png' })
    fs.writeFileSync(path.join(ROOT, 'scripts', 'login-mobile.png'), Buffer.from(shotMob.data, 'base64'))

    const result = {
      desktop,
      errorShown,
      passTypeAfterToggle: passType.result?.value,
      loggedIn,
      redirectedWhenAuthed: redirected,
      mobile,
    }
    console.log(JSON.stringify(result, null, 2))

    const ok =
      desktop.hasBrand &&
      desktop.hasSlogan &&
      desktop.hasPipeline &&
      desktop.hasLogin &&
      desktop.notOldPlaceholder &&
      errorShown &&
      loggedIn &&
      redirected &&
      mobile.hasBrand &&
      mobile.hasLogin

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
