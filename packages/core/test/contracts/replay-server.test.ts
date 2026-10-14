// The replay server (contract/replay-server.ts): matching, `after`, refusals, body caps and SSE resume.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { request } from 'node:http'
import { REPLAY_TOKEN, startReplayServer } from '../../contract/replay-server.ts'

const auth = { authorization: `Bearer ${REPLAY_TOKEN}` }
const job = JSON.parse((await import('node:fs')).readFileSync(new URL('../../contract/fixtures/jobs/valid/eth-drain-null.json', import.meta.url), 'utf8')) as unknown

test('replays status, refusals, create 201 then 200, body cap, unmatched', async () => {
  const s = await startReplayServer()
  try {
    let r = await fetch(`${s.url}/status`, { headers: auth })
    assert.equal(r.status, 200); assert.equal((await r.json() as { network: string }).network, 'local')
    r = await fetch(`${s.url}/status`)
    assert.equal(r.status, 401); assert.equal((await r.json() as { error: { guard: string } }).error.guard, 'api.token')
    r = await fetch(`${s.url}/status`, { headers: { ...auth, 'sec-fetch-site': 'cross-site' } })
    assert.equal((await r.json() as { error: { guard: string } }).error.guard, 'api.fetch-site')
    const post = { method: 'POST', headers: { ...auth, 'content-type': 'application/json' }, body: JSON.stringify(job) }
    r = await fetch(`${s.url}/jobs`, post); assert.equal(r.status, 201); await r.arrayBuffer()
    r = await fetch(`${s.url}/jobs`, post); assert.equal(r.status, 200); await r.arrayBuffer()
    r = await fetch(`${s.url}/jobs`, { ...post, body: 'a'.repeat(65_537) }); assert.equal(r.status, 413); await r.arrayBuffer()
    r = await fetch(`${s.url}/nowhere`, { headers: auth }); assert.equal(r.status, 501); await r.arrayBuffer()
  } finally { await s.close() }
})

function sseIds(url: string, headers: Record<string, string>, want: number): Promise<number[]> {
  return new Promise((resolve, reject) => {
    const req = request(url, { headers }, (res) => {
      let buf = ''
      res.setEncoding('utf8')
      res.on('data', (c: string) => {
        buf += c
        const ids = [...buf.matchAll(/^id: (\d+)$/gm)].map((m) => Number(m[1]))
        if (ids.length >= want) { req.destroy(); resolve(ids) }
      })
    })
    req.on('error', (e) => { if ((e as NodeJS.ErrnoException).code !== 'ECONNRESET') reject(e) })
    req.end()
  })
}

test('SSE replays from ?from= and from Last-Event-ID', async () => {
  const s = await startReplayServer()
  try {
    const { readFileSync } = await import('node:fs')
    const first = JSON.parse(readFileSync(new URL('../../contract/fixtures/journals/05a-copies-done.jsonl', import.meta.url), 'utf8').split('\n')[0]) as { data: { jobId: string } }
    const path = `${s.url}/jobs/${first.data.jobId}/events`
    assert.deepEqual((await sseIds(`${path}?from=3`, auth, 3)).slice(0, 3), [3, 4, 5])
    assert.deepEqual((await sseIds(`${path}?from=0`, { ...auth, 'last-event-id': '5' }, 2)).slice(0, 2), [6, 7])
    // A malformed Last-Event-ID is ignored (from= decides), as the API does.
    assert.deepEqual((await sseIds(`${path}?from=4`, { ...auth, 'last-event-id': '05' }, 2)).slice(0, 2), [4, 5])
    assert.deepEqual((await sseIds(path, { ...auth, 'last-event-id': '-1' }, 2)).slice(0, 2), [0, 1])
  } finally { await s.close() }
})

test('SSE: a malformed or repeated from is 400 api.args, as the API answers (CC-1); a valid Last-Event-ID still wins', async () => {
  const s = await startReplayServer()
  try {
    const { readFileSync } = await import('node:fs')
    const first = JSON.parse(readFileSync(new URL('../../contract/fixtures/journals/05a-copies-done.jsonl', import.meta.url), 'utf8').split('\n')[0]) as { data: { jobId: string } }
    const path = `${s.url}/jobs/${first.data.jobId}/events`
    for (const q of ['from=abc', 'from=-1', 'from=01', 'from=1.5', 'from=', 'from=1&from=2', 'from=1234567890123456']) {
      const r = await fetch(`${path}?${q}`, { headers: auth })
      assert.equal(r.status, 400, q)
      assert.match(r.headers.get('content-type') ?? '', /^application\/json/, q)
      assert.equal((await r.json() as { error: { guard: string } }).error.guard, 'api.args', q)
    }
    assert.deepEqual((await sseIds(`${path}?from=abc`, { ...auth, 'last-event-id': '5' }, 1)).slice(0, 1), [6])
  } finally { await s.close() }
})
