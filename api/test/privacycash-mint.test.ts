// Sfix-PC item 1: POST /jobs/<id>/privacycash/lane — the API's mint of the v2 single-use Privacy Cash withdrawal authorization,
// after RESERVING against the lane cap in the API's own ledger (fail closed), mainnet only while the funding lock refuses.
// A real API in process (startApi), synthetic jobs, a fake clock, a FAKE funding lock. No relay, no network, no real key.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { appendFileSync, chmodSync, fsyncSync, readFileSync, statSync, symlinkSync, writeFileSync, writeSync } from 'node:fs'
import { join } from 'node:path'
import type { Network } from '@vault-timelock/core/contracts'
import { MINT_LEDGER_FILE, MINT_TTL_MS, mintNetworkAllowed, validMint } from '../src/privacycash-mint.ts'
import { decodeLine, encodeLine } from '../src/pc-record.ts'
import type { MintIo } from '../src/privacycash-mint.ts'
import { WITHDRAW_AUTH_WINDOW_MS, verifyWithdrawAuth } from '../src/privacycash.ts'
import { JOB, KEYS, TICKET_KEY, call, idOf, jobFixture, onNetwork, startApi } from './helpers.ts'
import type { Reply, TestApi } from './helpers.ts'

process.env.NODE_ENV = 'test'

const SOL_INPUT = jobFixture('sol-copies')
const SOL_JOB = idOf(SOL_INPUT)
const LANE2 = 'Vote111111111111111111111111111111111111111'
const SOL2_INPUT = { ...SOL_INPUT, name: 'sol lane two', chains: { sol: { ...(SOL_INPUT.chains as { sol: object }).sol, keyAddress: LANE2 } } }
const SOL2_JOB = idOf(SOL2_INPUT)
const MINT_REC = (n: number): Record<string, unknown> => ({ v: 1, t: 'mint', lane: KEYS.sol, job: SOL_JOB, try: n, h: SHA(n), amount: '1', cum: '1', n: 'ab'.repeat(16).replace(/^../, n.toString(16).padStart(2, '0')), exp: 1, at: 1 })
const SHA = (n: number): string => n.toString(16).padStart(64, '0')
const guardOf = (r: Reply): string | undefined => (r.json as { error?: { guard?: string } } | null)?.error?.guard
const mint = (a: TestApi, id: string, body: unknown, network: Network = 'local'): Promise<Reply> => call(a.port, { path: `/jobs/${id}/privacycash/lane`, body, network })
const ask = (n: number, amount: string | number = '1000000', over: Record<string, unknown> = {}): Record<string, unknown> => ({ bodySha256: SHA(n), allowanceLamports: amount, tryIndex: n, ...over })
const ledgerLines = (a: TestApi): Array<Record<string, unknown>> => readFileSync(join(a.state, MINT_LEDGER_FILE), 'utf8').split('\n').filter((l) => l !== '').map((l) => JSON.parse(l) as Record<string, unknown>)
const hasAuth = (r: Reply): boolean => typeof (r.json as { authorization?: unknown } | null)?.authorization === 'string'
const auth = (r: Reply): string => (r.json as { authorization: string }).authorization
const verify = (a: TestApi, r: Reply, n: number, network: Network = 'local') => verifyWithdrawAuth(auth(r), TICKET_KEY, network, a.clock.now(), SHA(n))

test('the contract: POST /jobs/<id>/privacycash/lane { bodySha256, allowanceLamports, tryIndex } → { authorization }, the relay\'s v2 header for exactly this network, lane, job, try and body, expiring within 120 s', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    const r = await mint(a, SOL_JOB, ask(7, '2500000000'))
    assert.equal(r.status, 200)
    assert.deepEqual(Object.keys(r.json as object), ['authorization'])
    assert.equal(r.headers['cache-control'], 'no-store')
    const h = auth(r)
    const v = verify(a, r, 7)
    assert.ok(v !== null, 'the relay\'s verifier accepts it (MAC under relay-ticket.key, this network, this body)')
    assert.deepEqual([v.recipient, v.job, v.tryIndex, v.allowance, v.bodySha256, v.network], [KEYS.sol, SOL_JOB, 7, 2_500_000_000n, SHA(7), 'local'])
    assert.match(v.nonce, /^[0-9a-f]{32}$/)
    assert.equal(v.exp, a.clock.now() + MINT_TTL_MS)
    assert.ok(MINT_TTL_MS <= WITHDRAW_AUTH_WINDOW_MS && MINT_TTL_MS <= 120_000)
    // bound to the network, the body and the key
    assert.equal(verifyWithdrawAuth(h, TICKET_KEY, 'mainnet', a.clock.now(), SHA(7)), null)
    assert.equal(verifyWithdrawAuth(h, TICKET_KEY, 'local', a.clock.now(), SHA(8)), null)
    assert.equal(verifyWithdrawAuth(h, Buffer.alloc(32, 1), 'local', a.clock.now(), SHA(7)), null)
    assert.equal(verifyWithdrawAuth(h, TICKET_KEY, 'local', a.clock.now() + MINT_TTL_MS, SHA(7)), null, 'expired at exp')
    // a fresh nonce per mint; a number allowance is accepted too
    const r2 = await mint(a, SOL_JOB, ask(8, 1000))
    assert.equal(r2.status, 200)
    assert.notEqual(verify(a, r2, 8)!.nonce, v.nonce)
    // the log line carries no digest, address or authorization
    assert.ok(a.logs.some((l) => l.startsWith('api POST privacycash-lane 200')))
    assert.ok(!a.logs.some((l) => l.includes(SHA(7)) || l.includes(KEYS.sol) || l.includes(h)))
  } finally { await a.close() }
})

test('RESERVE first: each mint reserves its amount against the lane cap in the API\'s own ledger; the authorization\'s allowance is the lane\'s cumulative reservation; one mint per (job, try); lanes are separate; a restart keeps it all', async () => {
  const a = await startApi({ jobs: [SOL_INPUT, SOL2_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  const cap = { privacyCash: { capLamports: 5_000_000_000n } }
  let b: TestApi | null = null
  try {
    const m1 = await mint(a, SOL_JOB, ask(0, '3000000000'))
    const m2 = await mint(a, SOL_JOB, ask(1, '1500000000'))
    assert.deepEqual([m1.status, m2.status], [200, 200])
    assert.deepEqual([verify(a, m1, 0)!.allowance, verify(a, m2, 1)!.allowance], [3_000_000_000n, 4_500_000_000n], 'cumulative')
    const over = await mint(a, SOL_JOB, ask(2, '500000001'))                                        // 4.5 + 0.500000001 > 5
    assert.deepEqual([over.status, guardOf(over)], [409, 'api.pc-allowance'])
    assert.ok(!('authorization' in (over.json as object)))
    const again = await mint(a, SOL_JOB, ask(1, '1'))                                              // the same (job, try) never again
    assert.deepEqual([again.status, guardOf(again)], [409, 'api.pc-allowance'])
    const exact = await mint(a, SOL_JOB, ask(3, '500000000'))                                      // exactly the cap
    assert.equal(exact.status, 200); assert.equal(verify(a, exact, 3)!.allowance, 5_000_000_000n)
    assert.equal(guardOf(await mint(a, SOL_JOB, ask(4, '1'))), 'api.pc-allowance', 'full')
    // the other lane has its own reservations
    const other = await mint(a, SOL2_JOB, ask(0, '5000000000'))
    assert.equal(other.status, 200); assert.equal(verify(a, other, 0)!.recipient, LANE2)
    // the ledger: private, one line per successful mint, nothing for a refusal
    assert.deepEqual(ledgerLines(a).filter((l) => l.lane === KEYS.sol).map((l) => [l.try, l.amount, l.cum]), [[0, '3000000000', '3000000000'], [1, '1500000000', '4500000000'], [3, '500000000', '5000000000']])
    assert.equal(ledgerLines(a).length, 4)
    assert.equal(statSync(join(a.state, MINT_LEDGER_FILE)).mode & 0o777, 0o600)
    // a restart: the reservations are reloaded from the file
    await a.close(true)
    b = await startApi({ jobs: [SOL_INPUT, SOL2_INPUT], reuse: a, ...cap })
    assert.equal(guardOf(await mint(b, SOL_JOB, ask(0, '1'))), 'api.pc-allowance', 'a burned try stays burned')
    assert.equal(guardOf(await mint(b, SOL_JOB, ask(9, '1'))), 'api.pc-allowance', 'the lane is still full')
    assert.equal(guardOf(await mint(b, SOL2_JOB, ask(1, '1'))), 'api.pc-allowance', 'lane two is full too (5 of 5 SOL)')
  } finally { await (b ?? a).close() }
})

test('fail closed: no lane cap, a corrupt / symlinked / group-readable / torn ledger, an unwritable one — api.pc-ledger 503, no authorization, nothing reserved', async () => {
  // no cap configured
  const n = await startApi({ jobs: [SOL_INPUT] })
  try {
    const r = await mint(n, SOL_JOB, ask(0))
    assert.deepEqual([r.status, guardOf(r)], [503, 'api.pc-ledger'])
    assert.ok(!hasAuth(r))
  } finally { await n.close() }
  for (const [why, setup] of [
    ['corrupt line', (f: string) => writeFileSync(f, 'not json\n', { mode: 0o600 })],
    ['wrong shape', (f: string) => writeFileSync(f, `${JSON.stringify({ v: 1, t: 'mint', lane: 'x' })}\n`, { mode: 0o600 })],
    ['checksum mismatch', (f: string) => { const l = encodeLine(MINT_REC(0))!; writeFileSync(f, l.replace(/"amount":"1"/, '"amount":"2"'), { mode: 0o600 }) }],
    ['bad line in the middle', (f: string) => writeFileSync(f, `${encodeLine(MINT_REC(0))!}garbage\n${encodeLine(MINT_REC(1))!}`, { mode: 0o600 })],
    ['group-readable', (f: string) => { writeFileSync(f, '', { mode: 0o644 }); chmodSync(f, 0o644) }],
    ['symlink', (f: string) => { writeFileSync(`${f}.real`, '', { mode: 0o600 }); symlinkSync(`${f}.real`, f) }],
    ['duplicate try', (f: string) => writeFileSync(f, `${encodeLine(MINT_REC(0))!}${encodeLine({ ...MINT_REC(0), n: 'cd'.repeat(16) })!}`, { mode: 0o600 })],
  ] as const) {
    const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
    try {
      setup(join(a.state, MINT_LEDGER_FILE))
      const r = await mint(a, SOL_JOB, ask(0))
      assert.deepEqual([r.status, guardOf(r)], [503, 'api.pc-ledger'], why)
      assert.ok(!hasAuth(r), why)
    } finally { await a.close() }
  }
  // the state dir is read-only: the ledger cannot be created
  const ro = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    chmodSync(ro.state, 0o500)
    const r = await mint(ro, SOL_JOB, ask(0))
    assert.deepEqual([r.status, guardOf(r)], [503, 'api.pc-ledger'])
  } finally { chmodSync(ro.state, 0o700); await ro.close() }
})

test('the reserve line is written AND fsynced before the authorization exists (io seam); a failing write / fsync answers 503, mints nothing, reserves nothing and breaks the mint for the process', async () => {
  const events: string[] = []
  const io: MintIo = { write: (fd, b) => { events.push('write'); return writeSync(fd, b, 0, b.length) }, fsync: (fd) => { events.push('fsync'); fsyncSync(fd) } }
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n, io, nonce: () => { events.push('nonce'); return 'ab'.repeat(16) } } })
  try {
    const r = await mint(a, SOL_JOB, ask(0))
    assert.equal(r.status, 200)
    assert.deepEqual(events, ['nonce', 'write', 'fsync'], 'reserve = write then fsync, and only then the response (the authorization)')
    assert.equal(verify(a, r, 0)!.nonce, 'ab'.repeat(16))
  } finally { await a.close() }
  for (const [why, io2] of [
    ['fsync fails', { write: (fd: number, b: Buffer) => writeSync(fd, b, 0, b.length), fsync: () => { throw new Error('EIO') } }],
    ['short write', { write: () => 1, fsync: (fd: number) => fsyncSync(fd) }],
    ['write throws', { write: () => { throw new Error('ENOSPC') }, fsync: (fd: number) => fsyncSync(fd) }],
  ] as const) {
    const b = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n, io: io2 } })
    try {
      const r = await mint(b, SOL_JOB, ask(0, '4000000000'))
      assert.deepEqual([r.status, guardOf(r)], [503, 'api.pc-ledger'], why)
      assert.ok(!hasAuth(r), why)
      const r2 = await mint(b, SOL_JOB, ask(1, '1'))
      assert.deepEqual([r2.status, guardOf(r2)], [503, 'api.pc-ledger'], `${why}: broken for the rest of the process`)
    } finally { await b.close() }
  }
})

test('the request: exactly { bodySha256: 64 lower-case hex, allowanceLamports: canonical positive decimal ≤ 18 digits, tryIndex: 0..1000000 } — anything else is api.json, nothing is reserved', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 999_999_999_999_999_999n } })
  try {
    const bad: Array<[string, unknown]> = [
      ['not an object', 5], ['array', [ask(0)]], ['null', null], ['empty', {}],
      ['missing sha', { allowanceLamports: '1', tryIndex: 0 }], ['missing allowance', { bodySha256: SHA(0), tryIndex: 0 }], ['missing try', { bodySha256: SHA(0), allowanceLamports: '1' }],
      ['extra key', ask(0, '1', { recipient: KEYS.sol })], ['extra key network', ask(0, '1', { network: 'mainnet' })],
      ['upper-case sha', ask(0, '1', { bodySha256: SHA(255).toUpperCase() })], ['short sha', ask(0, '1', { bodySha256: 'ab'.repeat(31) })], ['long sha', ask(0, '1', { bodySha256: 'ab'.repeat(33) })],
      ['sha not a string', ask(0, '1', { bodySha256: 5 })], ['0x sha', ask(0, '1', { bodySha256: `0x${'ab'.repeat(32)}` })],
      ['allowance 0', ask(0, '0')], ['allowance leading zero', ask(0, '01')], ['allowance negative', ask(0, '-5')], ['allowance float', ask(0, 1.5)], ['allowance number 0', ask(0, 0)],
      ['allowance exp', ask(0, '1e3')], ['allowance hex', ask(0, '0x10')], ['allowance spaces', ask(0, ' 5')], ['allowance 19 digits', ask(0, '1000000000000000000')], ['allowance unsafe number', ask(0, 2 ** 60)],
      ['allowance null', ask(0, null as unknown as string)], ['try negative', ask(0, '1', { tryIndex: -1 })], ['try float', ask(0, '1', { tryIndex: 1.5 })], ['try string', ask(0, '1', { tryIndex: '1' })],
      ['try too big', ask(0, '1', { tryIndex: 1_000_001 })], ['try unsafe', ask(0, '1', { tryIndex: 2 ** 60 })],
    ]
    for (const [why, body] of bad) {
      const r = await mint(a, SOL_JOB, body)
      assert.deepEqual([r.status, guardOf(r)], [400, 'api.json'], why)
    }
    assert.throws(() => ledgerLines(a), /ENOENT/, 'nothing was reserved by any of them')
    assert.equal((await mint(a, SOL_JOB, ask(0, 5))).status, 200, 'a safe-integer number is accepted')
    assert.equal((await mint(a, SOL_JOB, ask(1_000_000, '999999999999999994'))).status, 200, 'the largest values (try 1000000, 18 digits; the cap)')
    assert.equal(ledgerLines(a).length, 2, 'only the good ones were reserved')
  } finally { await a.close() }
})

test('the job: a job with no SOL lane, an unknown job and a wrong method are refused; the recipient is the job\'s SOL lane address, never a request value', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    const noSol = await call(a.port, { path: `/jobs/${JOB}/privacycash/lane`, body: ask(0) })      // JOB (eth only) is not in this API
    assert.deepEqual([noSol.status, guardOf(noSol)], [404, 'job.missing'])
    const unknown = await mint(a, 'ffffffffffffffff', ask(0))
    assert.deepEqual([unknown.status, guardOf(unknown)], [404, 'job.missing'])
    const get = await call(a.port, { path: `/jobs/${SOL_JOB}/privacycash/lane` })
    assert.equal(get.status, 404)
    const noToken = await call(a.port, { path: `/jobs/${SOL_JOB}/privacycash/lane`, body: ask(0), headers: { authorization: null } })
    assert.equal(noToken.status, 401)
    assert.throws(() => ledgerLines(a), /ENOENT/, 'nothing reserved by any of them')
    const ok = await mint(a, SOL_JOB, ask(0))
    assert.equal(verify(a, ok, 0)!.recipient, KEYS.sol)
  } finally { await a.close() }
  // an eth-only job on its own API
  const e = await startApi({ privacyCash: { capLamports: 5_000_000_000n } })
  try {
    const r = await mint(e, JOB, ask(0))
    assert.deepEqual([r.status, guardOf(r)], [404, 'job.missing'])
  } finally { await e.close() }
})

test('THE LOCK (controller ruling, review I-2): EVERY mainnet mint is refused api.pc-lock 423, whatever the funding lock says; nothing is reserved; testnet and local mint', async () => {
  const input = onNetwork(SOL_INPUT, 'mainnet')
  const id = idOf(input, 'mainnet')
  const a = await startApi({ network: 'mainnet', jobs: [input], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    for (let n = 0; n < 3; n++) {
      const r = await mint(a, id, ask(n), 'mainnet')
      assert.deepEqual([r.status, guardOf(r)], [423, 'api.pc-lock'], `mainnet try ${n}`)
      assert.ok(!hasAuth(r))
    }
    assert.throws(() => ledgerLines(a), /ENOENT/, 'nothing reserved, no ledger created')
  } finally { await a.close() }
  assert.equal(mintNetworkAllowed('mainnet'), false)
  assert.equal(mintNetworkAllowed('testnet'), true); assert.equal(mintNetworkAllowed('local'), true)
  const tIn = onNetwork(SOL_INPUT, 'testnet')
  const t = await startApi({ network: 'testnet', jobs: [tIn], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    const r = await mint(t, idOf(tIn, 'testnet'), ask(0), 'testnet')
    assert.equal(r.status, 200); assert.ok(verify(t, r, 0, 'testnet') !== null)
    assert.equal(verifyWithdrawAuth(auth(r), TICKET_KEY, 'mainnet', t.clock.now(), SHA(0)), null, 'a testnet authorization is not a mainnet one')
  } finally { await t.close() }
})

test('the mint goes through the shared gate (review M-5): the gate runs; a job whose journal is corrupt is refused and nothing is reserved', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  let b: TestApi | null = null
  try {
    const g0 = a.api.registry.gates()
    assert.equal((await mint(a, SOL_JOB, ask(0))).status, 200)
    assert.ok(a.api.registry.gates() > g0, 'the gate ran')
    await a.close(true)
    appendFileSync(join(a.state, 'jobs', SOL_JOB, 'journal.jsonl'), 'garbage\n')
    b = await startApi({ jobs: [], reuse: a, privacyCash: { capLamports: 5_000_000_000n } })
    const r = await mint(b, SOL_JOB, ask(1))
    assert.ok(r.status >= 400 && !hasAuth(r), `refused (${r.status} ${guardOf(r)})`)
    assert.equal(ledgerLines(b).length, 1, 'the refused mint reserved nothing')
  } finally { await (b ?? a).close() }
})

// ---- ledger format (review I-1): one validator, checksum, printable ASCII, torn tail, failed write
test('the mint ledger: lines are checksummed printable ASCII; the writer\'s lines decode and validate; a tampered / bad line cannot decode', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  try {
    assert.equal((await mint(a, SOL_JOB, ask(0))).status, 200)
    const text = readFileSync(join(a.state, MINT_LEDGER_FILE), 'utf8')
    assert.ok(text.endsWith('\n') && /^[\x20-\x7e\n]+$/.test(text))
    const d = decodeLine(text.trimEnd())
    assert.ok(d.ok && validMint(d.rec))
    assert.equal(decodeLine(text.trimEnd().replace('\"amount\":\"1000000\"', '\"amount\":\"1000001\"')).ok, false, 'a changed member fails the checksum')
    assert.equal(decodeLine(text.trimEnd().replace(/,\"c\":\"[0-9a-f]{16}\"/, '')).ok, false, 'no checksum')
    assert.equal(encodeLine({ ...MINT_REC(0), x: 'caf\u00e9' }), null, 'a non-ASCII value is refused before the write')
    assert.ok(encodeLine({ ...MINT_REC(0), x: 'a\nb' })!.split('\n').length === 2, 'a newline in a value is JSON-escaped: one line')
  } finally { await a.close() }
})

test('the mint ledger: a TORN last line (no newline: a crash mid-append, never acknowledged) is cut on load and minting works; the reservation of the whole lines stays', async () => {
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n } })
  const f = join(a.state, MINT_LEDGER_FILE)
  try {
    assert.equal((await mint(a, SOL_JOB, ask(0, '4000000000'))).status, 200)
    await a.close(true)
    const whole = readFileSync(f, 'utf8')
    writeFileSync(f, `${whole}${encodeLine(MINT_REC(5))!.slice(0, 60)}`, { mode: 0o600 })     // a fragment
    const b = await startApi({ jobs: [SOL_INPUT], reuse: a, privacyCash: { capLamports: 5_000_000_000n } })
    try {
      assert.equal(guardOf(await mint(b, SOL_JOB, ask(1, '1000000001'))), 'api.pc-allowance', '4 SOL stays reserved: no under-count')
      assert.equal((await mint(b, SOL_JOB, ask(1, '1000000000'))).status, 200)
      assert.equal(readFileSync(f, 'utf8').split('\n').filter((l) => l !== '').length, 2, 'the fragment is gone, the new line is whole')
    } finally { await b.close() }
  } finally { await a.close().catch(() => undefined) }
})

test('the mint ledger: after a failed write nothing more is appended (fail closed until restart); a retry stays refused and writes nothing; the file is cut on the next start', async () => {
  let failNext = true
  const writes: number[] = []
  const io: MintIo = { write: (fd, b) => { writes.push(b.length); if (failNext) { failNext = false; return writeSync(fd, b, 0, 10) } return writeSync(fd, b, 0, b.length) }, fsync: (fd) => fsyncSync(fd) }
  const a = await startApi({ jobs: [SOL_INPUT], privacyCash: { capLamports: 5_000_000_000n, io } })
  const f = join(a.state, MINT_LEDGER_FILE)
  try {
    assert.equal(guardOf(await mint(a, SOL_JOB, ask(0))), 'api.pc-ledger')
    assert.equal(guardOf(await mint(a, SOL_JOB, ask(1))), 'api.pc-ledger', 'the retry is refused')
    assert.equal(writes.length, 1, 'no second write was attempted')
    assert.equal(readFileSync(f, 'utf8').length, 10, 'only the torn fragment is on disk')
    await a.close(true)
    const b = await startApi({ jobs: [SOL_INPUT], reuse: a, privacyCash: { capLamports: 5_000_000_000n } })
    try {
      assert.equal((await mint(b, SOL_JOB, ask(0))).status, 200, 'after a restart the fragment is cut and the try was never acknowledged')
    } finally { await b.close() }
  } finally { await a.close().catch(() => undefined) }
})
