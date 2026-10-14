// api/src/clock.ts — the API's test seams, in one place: the clock (time + repeating timers) and the gate that every
// other seam (the journal's fs, main's --port 0) passes through.
//
// A seam is accepted only when NODE_ENV=test (api.test-only). The production wrappers start the API under env -i, so
// NODE_ENV is never set there, and a seam handed to a production process is refused instead of silently honoured.
import { refuse } from 'vt-broadcast/src/guard.ts'

export interface Clock {
  now(): number
  // Calls fn every ms milliseconds until the returned function is called.
  every(ms: number, fn: () => void): () => void
}

export const systemClock: Clock = {
  now: () => Date.now(),
  every(ms, fn) {
    const t = setInterval(fn, ms)
    return () => clearInterval(t)
  },
}

// Refuses unless this process runs as a test (NODE_ENV=test). Every test-only seam calls this before it is used.
export function assertTestMode(): void {
  const ok = process.env.NODE_ENV === 'test'
  if (!ok) refuse('api.test-only', 'a test-only option was given to a process that is not running as a test') // @guard:api.test-only
}
