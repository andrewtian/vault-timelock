// api/src/sse.ts — GET /jobs/:id/events (spec §5.2): one SSE event per journal line, `id: <seq>`, `data: <the line>`.
//
// The stream first replays every journaled event with seq ≥ from, then sends each new one as it is appended (the
// replay and the subscription happen in the same tick, so nothing is missed or sent twice), and a `: hb <serverNowMs>`
// comment every SSE_HEARTBEAT_MS. When the client goes away, its subscription and heartbeat timer are removed.
// The replay is written with backpressure. A subscriber that stops reading is cut off once more than SSE_MAX_BUFFER bytes wait unsent for it (S1 review m6): its stream
// is destroyed, never the journal; the client resumes with Last-Event-ID.
//
// Resume (resumeFrom): a `Last-Event-ID: <seq>` header wins and resumes at seq + 1; otherwise `?from=<seq>`; otherwise
// 0. This is the contract replay server's rule. A client that sends both (Last-Event-ID n and from=n+1) gets the same
// answer either way. A malformed Last-Event-ID is ignored (as in the replay server); a malformed `from` is api.args.
import type { IncomingMessage, ServerResponse } from 'node:http'
import { SSE_CONTENT_TYPE, SSE_HEARTBEAT_MS, sseFrame, sseHeartbeat } from '@vault-timelock/core/contracts'
import { assertArgs, parseSeq } from './args.ts'
import { single } from './http.ts'
import type { Clock } from './clock.ts'
import type { Journal } from './journal.ts'

export const SSE_MAX_BUFFER = 1 << 20

export interface SseHub {
  stream(res: ServerResponse, journal: Journal, from: number): void
  count(): number
}

export function resumeFrom(req: IncomingMessage, url: URL): number {
  const last = single(req, 'last-event-id')
  const lastSeq = typeof last === 'string' ? parseSeq(last) : null
  if (lastSeq !== null) return lastSeq + 1
  const from = url.searchParams.getAll('from')
  const seq = from.length === 1 ? parseSeq(from[0]) : null
  assertArgs(from.length === 0 || seq !== null)
  return seq ?? 0
}

export function createSse(o: { clock: Clock }): SseHub {
  const subscribers = new Set<object>()
  return {
    count: () => subscribers.size,
    stream(res, journal, from) {
      res.writeHead(200, { 'content-type': SSE_CONTENT_TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' })
      res.flushHeaders()
      res.on('error', () => {}) // a client that vanished mid-write is handled by 'close'
      // The initial replay is written with backpressure (a frame at a time, waiting for 'drain'), so a journal of any size reaches a
      // reader that keeps up; the slow-reader cap applies to what is queued OUTSIDE the replay (live events and heartbeats), and to the
      // live events that arrive while the replay is still being written. The snapshot and the subscription are taken in one tick.
      let replaying = true
      const held: string[] = []
      let heldBytes = 0
      const write = (text: string): void => {
        if (res.destroyed || res.writableEnded) return
        res.write(text)
        if (res.writableLength > SSE_MAX_BUFFER) res.destroy()   // a reader that stopped reading: cut it off (it resumes with Last-Event-ID)
      }
      const live = (text: string): void => {
        if (!replaying) return write(text)
        held.push(text)
        heldBytes += Buffer.byteLength(text)
        if (heldBytes > SSE_MAX_BUFFER) res.destroy()
      }
      const replay = journal.all().filter((e) => e.seq >= from)
      const unsubscribe = journal.subscribe((e) => { if (e.seq >= from) live(sseFrame(e.seq, JSON.stringify(e))) })
      void (async () => {
        for (const e of replay) {
          if (res.destroyed || res.writableEnded) return
          if (!res.write(sseFrame(e.seq, JSON.stringify(e)))) {
            await new Promise<void>((r) => { const done = (): void => { res.off('drain', done); res.off('close', done); r() }; res.once('drain', done); res.once('close', done) })
          }
        }
        replaying = false
        for (const t of held.splice(0)) write(t)
      })()
      const stopBeat = o.clock.every(SSE_HEARTBEAT_MS, () => { if (!replaying) write(sseHeartbeat(o.clock.now())) })
      const sub = {}
      subscribers.add(sub)
      res.on('close', () => {
        unsubscribe()
        stopBeat()
        subscribers.delete(sub)
      })
    },
  }
}
