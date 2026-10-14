// The page's handle on the Privacy Cash worker (plan W6): one worker per unlocked session, a WATCHDOG on every call, and a hard
// stop. A stuck request is the SDK's normal failure mode (its spent-note check retries forever, 3 s apart; a relayer can hang),
// so nothing here trusts the worker to finish:
//   · idle watchdog  no message at all from the worker for `idleMs` → the worker is terminated and the call fails pc.watchdog;
//                    any status event resets it, so a long scan that keeps reporting is not killed
//   · hard cap       `maxMs` per call, whatever it reports
//   · stop()         the operator's Stop / Lock: terminates the worker (the key is gone with it)
// After a stop the client is DEAD (alive === false): a new unlock makes a new client and a new worker.
// `sentAtStop` is true when the /withdraw request had left DURING THAT CALL before it ended in a stop or an error: funds may have moved, the
// page says so. It is tracked per call (a later, unrelated error never claims it), and an error after a /withdraw left also STOPS the client
// (m-4): the session is not reused, the key is forgotten, and a fresh unlock and balance check come first.
export const DEFAULT_LIMITS = Object.freeze({
  unlock: { idleMs: 60_000, maxMs: 120_000 },
  balance: { idleMs: 6 * 60_000, maxMs: 60 * 60_000 },
  quote: { idleMs: 120_000, maxMs: 5 * 60_000 },
  withdraw: { idleMs: 5 * 60_000, maxMs: 30 * 60_000 },
  lock: { idleMs: 10_000, maxMs: 15_000 },
})

export class PcCallError extends Error {
  constructor(code, message, extra = {}) { super(message); this.name = 'PcCallError'; this.code = code; Object.assign(this, extra) }
}

export function createPcClient({ makeWorker = () => new Worker(new URL('./worker.js', import.meta.url), { type: 'module' }), limits = DEFAULT_LIMITS, onStatus = () => {}, setT = setTimeout, clearT = clearTimeout } = {}) {
  let worker = makeWorker()
  let alive = true, nextId = 1, sent = false
  const pending = new Map()      // id → { resolve, reject, idle, hard, cmd, limits, sent }

  const settle = (id, fn, v) => { const p = pending.get(id); if (!p) return; clearT(p.idle); clearT(p.hard); pending.delete(id); fn(p, v) }
  const kill = (code, message) => {
    if (!alive) return
    alive = false
    try { worker.terminate() } catch { /* already gone */ }
    worker.onmessage = null; worker.onerror = null; worker.onmessageerror = null
    for (const id of [...pending.keys()]) settle(id, (p) => p.reject(new PcCallError(code, message, { sentAtStop: p.sent, stopped: true })))
  }
  const arm = (id) => {
    const p = pending.get(id); if (!p) return
    clearT(p.idle)
    p.idle = setT(() => kill('pc.watchdog', `no sign of life from the Privacy Cash worker for ${Math.round(p.limits.idleMs / 1000)} s: it was stopped and the key forgotten`), p.limits.idleMs)
  }
  worker.onmessage = (e) => {
    const m = e?.data
    if (!m || typeof m !== 'object') return
    if (m.type === 'sent') { sent = true; for (const [id, p] of pending) { p.sent = true; arm(id) } return }
    if (m.type === 'status') { if (typeof m.msg === 'string') onStatus(m.msg.slice(0, 120)); for (const id of pending.keys()) arm(id); return }
    if (m.type === 'ready') { for (const id of pending.keys()) arm(id); return }
    if (!pending.has(m.id)) return
    if (m.ok === true) settle(m.id, (p, v) => p.resolve(v), m.result)
    else {
      const wasSent = pending.get(m.id).sent === true
      settle(m.id, (p, v) => p.reject(new PcCallError(v?.code ?? 'pc.sdk', v?.message ?? 'failed', wasSent ? { sentAtStop: true, stopped: true } : { sentAtStop: false })), m.error)
      if (wasSent) kill('pc.stopped', 'the Privacy Cash worker was stopped after an error with the withdrawal request already sent: the key is forgotten')
    }
  }
  worker.onerror = () => kill('pc.worker-error', 'the Privacy Cash worker failed to load or crashed: it was stopped')
  worker.onmessageerror = () => kill('pc.worker-error', 'the Privacy Cash worker sent something unreadable: it was stopped')

  return {
    get alive() { return alive },
    get sentAtStop() { return sent },
    call(cmd, args = {}) {
      if (!alive) return Promise.reject(new PcCallError('pc.stopped', 'the Privacy Cash worker is stopped: unlock again', { sentAtStop: sent, stopped: true }))
      const lim = limits[cmd] ?? { idleMs: 60_000, maxMs: 120_000 }
      const id = nextId++
      sent = false
      return new Promise((resolve, reject) => {
        pending.set(id, { resolve, reject, cmd, limits: lim, sent: false, idle: null, hard: setT(() => kill('pc.watchdog', `the Privacy Cash ${cmd} ran past ${Math.round(lim.maxMs / 60000)} min: the worker was stopped and the key forgotten`), lim.maxMs) })
        arm(id)
        worker.postMessage({ id, cmd, args })
      })
    },
    stop(code = 'pc.stopped', message = 'stopped by you: the worker was terminated and the key forgotten') { kill(code, message) },
  }
}
