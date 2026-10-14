// Same-origin API client (W1). The page server injects the bearer token; the page never holds it.
// Paths are the API's own (contracts P.*); this module prefixes '/api'.
import { P } from '@vault-timelock/core/contracts'

export class ApiError extends Error {
  constructor(guard, status, message) {
    super(message || guard)
    this.name = 'ApiError'
    this.guard = guard
    this.status = status
  }
}

async function request(path, init = {}) {
  let res
  try {
    res = await fetch('/api' + path, { cache: 'no-store', credentials: 'same-origin', redirect: 'error', ...init })
  } catch {
    throw new ApiError('api.unreachable', 0, 'the API is not reachable')
  }
  return res
}

// Maps { error: { guard, message } } to ApiError; a non-JSON failure (proxy error page) becomes api.http.
async function failure(res) {
  let body = null
  try { body = JSON.parse(await res.text()) } catch { /* not JSON */ }
  const e = body && typeof body === 'object' ? body.error : null
  if (e && typeof e.guard === 'string') return new ApiError(e.guard, res.status, typeof e.message === 'string' ? e.message : e.guard)
  return new ApiError('api.http', res.status, `HTTP ${res.status}`)
}

export async function api(path, init = {}) {
  const headers = { accept: 'application/json', ...(init.headers || {}) }
  const res = await request(path, { ...init, headers })
  if (!res.ok) throw await failure(res)
  const text = await res.text()
  if (text === '') return null
  try { return JSON.parse(text) } catch { throw new ApiError('api.http', res.status, 'the API answered with something that is not JSON') }
}

export async function apiText(path, init = {}) {
  const res = await request(path, init)
  if (!res.ok) throw await failure(res)
  return res.text()
}

// Message upload by digest (idempotent). The body is the text itself, UTF-8, exactly as chosen.
export function putMessage(sha, text) {
  return api(P.message(sha), { method: 'PUT', headers: { 'content-type': 'text/plain; charset=utf-8' }, body: text })
}

// The response bytes exactly as the API sent them (W4: the receipt is saved byte for byte, never re-serialised).
export async function apiBytes(path, init = {}) {
  const res = await request(path, init)
  if (!res.ok) throw await failure(res)
  return new Uint8Array(await res.arrayBuffer())
}
