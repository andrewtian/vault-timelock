// SSE client over fetch (W1). The API streams one event per journal line: `id: <seq>` + `data: <line>`, and a
// `: hb <ms>` comment every SSE_HEARTBEAT_MS. subscribe() reconnects with `Last-Event-ID` set to the last seq seen
// (the server then resumes at seq + 1), so nothing is missed and nothing is delivered twice.
import { P, SSE_HEARTBEAT_MS } from '@vault-timelock/core/contracts'

const FATAL = new Set([400, 401, 403, 404])

// Split a text buffer into complete SSE blocks; returns [blocks, rest].
function blocks(buf) {
  const parts = buf.replace(/\r\n?/g, '\n').split('\n\n')
  return [parts.slice(0, -1), parts[parts.length - 1]]
}

export function parseBlock(block) {
  let id = null
  const data = []
  for (const line of block.split('\n')) {
    if (line === '' || line.startsWith(':')) continue
    const i = line.indexOf(':')
    const field = i < 0 ? line : line.slice(0, i)
    const value = i < 0 ? '' : line.slice(i + 1).replace(/^ /, '')
    if (field === 'id') id = /^[0-9]+$/.test(value) ? Number(value) : id
    else if (field === 'data') data.push(value)
  }
  return data.length ? { id, line: data.join('\n') } : null
}

// subscribe(jobId, from, on, opts?) -> close()
//   on({ id, line, event })  event = JSON.parse(line) (null when the line is not JSON)
//   opts: onError({ guard, status }) for a non-retryable refusal; onState('open'|'retrying'|'closed');
//         fetch (tests); retryMs (base delay, default 1000; doubles up to 10 s); stallMs (default 2 x heartbeat).
export function subscribe(jobId, from, on, opts = {}) {
  const doFetch = opts.fetch || ((...a) => fetch(...a))
  const base = opts.retryMs ?? 1000
  const stallMs = opts.stallMs ?? SSE_HEARTBEAT_MS * 2
  let closed = false
  let last = null
  let ctl = null
  let timer = null
  let delay = base

  const state = (s) => { if (opts.onState) opts.onState(s) }
  const retry = () => {
    if (closed) return
    state('retrying')
    timer = setTimeout(run, delay)
    delay = Math.min(delay * 2, 10_000)
  }

  async function run() {
    timer = null
    if (closed) return
    ctl = new AbortController()
    let stall = null
    const arm = () => { clearTimeout(stall); stall = setTimeout(() => ctl.abort(), stallMs) }
    try {
      const headers = { accept: 'text/event-stream' }
      let start = from
      if (last !== null) { headers['last-event-id'] = String(last); start = last + 1 }
      arm()
      const res = await doFetch('/api' + P.stream(jobId, start), { headers, cache: 'no-store', credentials: 'same-origin', signal: ctl.signal })
      if (!res.ok) {
        if (FATAL.has(res.status)) {
          let guard = 'api.http'
          try { const b = JSON.parse(await res.text()); if (typeof b?.error?.guard === 'string') guard = b.error.guard } catch { /* keep */ }
          closed = true
          clearTimeout(stall)
          if (opts.onError) opts.onError({ guard, status: res.status })
          state('closed')
          return
        }
        throw new Error('retry')
      }
      state('open')
      const reader = res.body.getReader()
      const dec = new TextDecoder('utf-8')
      let buf = ''
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        arm()
        delay = base
        buf += dec.decode(value, { stream: true })
        const [done_, rest] = blocks(buf)
        buf = rest
        for (const b of done_) {
          const m = parseBlock(b)
          if (!m) continue
          if (m.id !== null) {
            if (last !== null && m.id <= last) continue // never deliver a seq twice
            last = m.id
          }
          let event = null
          try { event = JSON.parse(m.line) } catch { /* not JSON */ }
          on({ id: m.id, line: m.line, event })
        }
      }
    } catch {
      // network error, stall abort or a retryable status: fall through to retry
    }
    clearTimeout(stall)
    retry()
  }

  run()
  return function close() {
    closed = true
    clearTimeout(timer)
    if (ctl) ctl.abort()
    state('closed')
  }
}
