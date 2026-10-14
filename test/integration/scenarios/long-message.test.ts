// E4 scenario long-message (M1; R72; Review Focus 5): long and odd texts end "reassembled ✓" on both chains, read back
// from the chain's own bytes, through S2's REAL API (PUT /messages for anything over POST /jobs' 64 KiB) and S4's REAL
// relay on the harness's own chains. The CLI's adapter, in this process.
//   L-10k     10 KB synthetic text                     ETH 1 part,  SOL ~11 parts
//   L-100k    100 KB synthetic text                    ETH 2 parts, SOL ~100 parts; at SOL part 37 the operator STOPS
//             and RESUMES while that part is in flight (its send held at the relay's door): the Stop never takes effect,
//             part 37 is sent once, the copy completes
//   L-mb5k    the multibyte-5k.txt fixture (accents, CJK, emoji, Greek, Cyrillic: no split inside a code point)
//   L-sealed  a 19.5 KiB synthetic SEALED-style text (the sealed-like.txt header + an armored synthetic body)
//   L-stop    40 KB, SOL: Stop between parts — at part 37 in flight: part 37 resolves, then `stopped` (latched); part 38 is
//             not signed by that run; R79 (c), replacing W3: the operator's resume lifts the latch, a new executor reopens the
//             chain (`resumed`) and continues at part 38 — stopped again right after it so the case stays short
// Asserts: every part on chain once with the planned bytes, nothing else from the keys; the copy reassembled from the
// chain bytes INDEPENDENTLY (the reader rules: headers k/N, digest) equals the text; the engine's reassembled ✓.
// OWN SANDBOX. ALL DATA IS SYNTHETIC.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { Chain, JobDef } from '../../../packages/core/src/contracts/index.ts'
import { startAnvil, startValidator, fundEth, fundSol, reassembleFromChain, sha256, sleep, solTxIdOf, REPO } from '../harness/chains.ts'
import { apiCall, armOk, capOf, createJob, evidence, executor, jobOf, journalOf, startStack, uploadMessage, waitChains, waitReady } from '../harness/stack.ts'
import type { Stack } from '../harness/stack.ts'
import { assertPublished, keyOf, lifecycle, ms, scratch, syntheticText } from '../harness/kit.ts'

const T = lifecycle()

// 19.5 KiB in the shape of a sealed package's published text: the synthetic header, then an armored body of synthetic
// base64 (a seeded generator; never key-like: 64-character lines, no 87/88-character base58 run, no BIP-39 run).
function sealedStyle(bytes: number): string {
  const head = readFileSync(join(REPO, 'packages/core/contract/fixtures/messages/sealed-like.txt'), 'utf8')
  const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let x = 0x9e3779b9, s = `${head}${head.endsWith('\n') ? '' : '\n'}-----BEGIN SYNTHETIC ARMOR (test data, not a key)-----\n`
  const end = '-----END SYNTHETIC ARMOR-----\n'
  while (s.length + end.length < bytes) {
    let line = ''
    for (let i = 0; i < 64; i++) { x ^= x << 13; x ^= x >>> 17; x ^= x << 5; line += B64[(x >>> 0) % 64] }
    s += `${line.slice(0, Math.min(64, bytes - s.length - end.length - 1))}\n`
  }
  return s + end
}

test('long-message: 10 KB, 100 KB (ETH 2 parts, SOL ~100), multibyte-5k, a 19.5 KiB SEALED-style text — reassembled ✓ on both chains; Stop/Resume at SOL part 37; Stop between parts', { timeout: 1_500_000 }, async () => {
  const t0 = Date.now()
  const home = scratch(T)
  const [anvil, sol] = await Promise.all([startAnvil(T, { home, blockTime: 1, baseFee: 7n }), startValidator(T, { home, dir: home })])
  const s: Stack = await startStack(T, { network: 'local', ethRpc: anvil.url, solRpc: sol.url, page: false })
  const ports = { anvil: anvil.port, sol: sol.port }

  // holds at the relay's door: the first send of (job, chain sol, copy 1, part 37) waits until the test releases it
  const holds = new Map<string, { txId: string | null; reached: Promise<void>; hit: () => void; release: () => void; gate: Promise<void>; done: boolean }>()
  const holdOn = (jobId: string) => {
    let hit!: () => void, release!: () => void
    const h = { txId: null as string | null, reached: new Promise<void>((r) => { hit = r }), hit: () => hit(), gate: new Promise<void>((r) => { release = r }), release: () => release(), done: false }
    holds.set(jobId, h)
    return h
  }
  s.hooks.after = (r) => {
    const m = /^\/jobs\/([0-9a-f]{16})\/chains\/sol\/events$/.exec(r.path)
    const h = m ? holds.get(m[1]) : undefined
    if (h && r.body?.type === 'intent' && r.body.data.copy === 1 && r.body.data.part === 37) h.txId = String(r.body.data.txId)
    return 'deliver'
  }
  s.hooks.before = async (r) => {
    if (r.target !== 'relay' || r.path !== '/relay/sol' || r.body?.method !== 'sendTransaction') return
    const id = solTxIdOf(String(r.body.params[0]))
    for (const h of holds.values()) if (!h.done && h.txId === id) { h.done = true; h.hit(); await h.gate }
  }

  async function job(name: string, text: string, chains: Chain[]) {
    const keys = Object.fromEntries(chains.map((c) => [c, keyOf(c)])) as Record<Chain, ReturnType<typeof keyOf>>
    if (keys.eth) await fundEth(anvil.port, keys.eth.address, 10n ** 18n)
    if (keys.sol) await fundSol(sol.port, keys.sol.address, 500_000_000)
    const msg = Buffer.byteLength(text) > 60_000 ? await uploadMessage(s, text) : { message: text }
    const def0: Record<string, unknown> = {}
    if (keys.eth) def0.eth = { mode: { copies: 1 }, publishMode: 'eth.calldata.null', feeStrategy: 'economy', distinctCopies: true, keyAddress: keys.eth.address, budgetUsd: 10, maxTipGwei: 3, clawbackTo: null }
    if (keys.sol) def0.sol = { mode: { copies: 1 }, feeStrategy: 'economy', distinctCopies: true, keyAddress: keys.sol.address, budgetUsd: 5, maxCuPrice: 2_000_000, clawbackTo: null }
    const { id, def } = await createJob(s, { format: 'vt-job/1', network: 'local', name: `E4 long ${name}`, ...msg, chains: def0 })
    return { id, def, keys, text, name, chains }
  }
  type J = Awaited<ReturnType<typeof job>>
  async function run(j: J, o: { during?: (j: J) => Promise<void> } = {}): Promise<{ outcomes: Record<string, string>; ms: number }> {
    const t1 = Date.now()
    const exs = j.chains.map((c) => executor(s, { jobId: j.id, chain: c, key: j.keys[c] }))
    const runs = Promise.all(exs.map((e) => e.start()))
    await waitReady(s, j.id, j.chains)
    await armOk(s, j.id, Object.fromEntries(j.chains.map((c) => [c, capOf(c, c === 'eth' ? 10n ** 17n : 10n ** 9n)])))
    const during = o.during?.(j)
    const out = await runs
    await during
    return { outcomes: Object.fromEntries(j.chains.map((c, i) => [c, out[i]])), ms: ms(t1) }
  }
  async function verify(j: J, r: { outcomes: Record<string, string>; ms: number }, expect: Record<string, string>) {
    assert.deepEqual(r.outcomes, expect, j.name)
    const st = (await jobOf(s, j.id)).state
    const facts: Record<string, unknown> = { bytes: Buffer.byteLength(j.text), ms: r.ms }
    for (const c of j.chains) {
      const p = await assertPublished('long-message', ports, j.def as JobDef, j.text, st, c, expect[c] === 'copies-done' ? { copies: 1 } : {})
      if (expect[c] === 'copies-done') {
        const ra = reassembleFromChain(c, p.parts).get(1)!
        assert.equal(ra.text, j.text, `${j.name} ${c}: the chain's bytes reassemble to the text`)
        assert.equal(ra.sha256, sha256(Buffer.from(j.text, 'utf8')))
        assert.deepEqual(st.chains[c]!.reassembled, [{ copy: 1, ok: true }], `${j.name} ${c}: reassembled ✓`)
      }
      facts[c] = { parts: p.parts.length, phase: st.chains[c]!.phase, first: p.parts[0]?.txId, last: p.parts.at(-1)?.txId }
    }
    evidence('long-message', j.name, facts)
    return st
  }

  const [j10, j100, jmb, jsealed, jstop] = await Promise.all([
    job('L-10k', syntheticText(10_240, 'E4 long message: 10 KB'), ['eth', 'sol']),
    job('L-100k', syntheticText(102_400, 'E4 long message: 100 KB'), ['eth', 'sol']),
    job('L-mb5k', readFileSync(join(REPO, 'packages/core/contract/fixtures/messages/multibyte-5k.txt'), 'utf8'), ['eth', 'sol']),
    job('L-sealed', sealedStyle(19_968), ['eth', 'sol']),
    job('L-stop', syntheticText(40_960, 'E4 long message: Stop between parts'), ['sol']),
  ])
  const h100 = holdOn(j100.id), hstop = holdOn(jstop.id)

  await Promise.all([
    run(j10).then((r) => verify(j10, r, { eth: 'copies-done', sol: 'copies-done' })),
    run(jmb).then((r) => verify(jmb, r, { eth: 'copies-done', sol: 'copies-done' })),
    run(jsealed).then((r) => verify(jsealed, r, { eth: 'copies-done', sol: 'copies-done' })),
    // L-100k: Stop, then Resume, while part 37 is in flight — the Stop never takes effect
    run(j100, { during: async (j) => {
      await h100.reached
      assert.equal((await apiCall(s, 'POST', `/jobs/${j.id}/stop`, { chain: 'sol' })).status, 200)
      await sleep(6_500)                                                // ≥ one lease tick: the executor has read the Stop
      assert.equal((await apiCall(s, 'POST', `/jobs/${j.id}/resume`, { chain: 'sol' })).status, 200)
      await sleep(6_500)                                                // and the Resume
      h100.release()
    } }).then(async (r) => {
      const st = await verify(j100, r, { eth: 'copies-done', sol: 'copies-done' })
      const lines = journalOf(s, j100.id)
      const parts = st.chains.sol!.txs.length
      assert.ok(parts >= 95 && parts <= 110, `SOL ~100 parts (${parts})`)
      assert.equal(st.chains.eth!.txs.length, 2, 'ETH 2 parts')
      assert.equal(lines.filter((e) => e.chain === 'sol' && e.type === 'intent' && e.data.part === 37).length, 1, 'part 37: one intent, sent once')
      assert.ok(lines.some((e) => e.type === 'stop-requested') && lines.some((e) => e.type === 'resume-requested'), 'the operator stopped and resumed')
      assert.ok(!lines.some((e) => e.type === 'stopped'), 'the Stop never took effect: resumed before the in-flight part resolved')
      evidence('long-message', 'L-100k stop+resume at SOL part 37', { part37: h100.txId, intentsForPart37: 1, solParts: parts })
    }),
    // L-stop: Stop between parts — part 37 in flight resolves, then `stopped` (latched); a resume reopens it at part 38 (R79)
    run(jstop, { during: async (j) => {
      await hstop.reached
      assert.equal((await apiCall(s, 'POST', `/jobs/${j.id}/stop`, { chain: 'sol' })).status, 200)
      await sleep(1_000)
      hstop.release()
    } }).then(async (r) => {
      const st = await verify(jstop, r, { sol: 'stopped' })
      let lines = journalOf(s, jstop.id)
      const cs = st.chains.sol!
      assert.equal(cs.phase, 'STOPPED')
      assert.equal(cs.txs.length, 37, 'parts 1–37 landed, nothing after')
      assert.ok(!lines.some((e) => e.type === 'intent' && Number(e.data.part) > 37), 'part 38 never signed')
      const rb37 = lines.findIndex((e) => e.type === 'readback' && e.data.txId === hstop.txId)
      const stopped = lines.findIndex((e) => e.chain === 'sol' && e.type === 'stopped')
      assert.ok(rb37 > 0 && stopped > rb37, '`stopped` right after the in-flight part resolved')
      assert.equal(cs.stopLatched, true, 'a journaled stop latches the chain')
      // R79 (c), replacing the W3 ruling: the operator's resume lifts the latch; a fresh executor reopens the chain and continues at
      // part 38 (same copy, same header and digest). A second Stop as soon as part 38 is signed keeps the case short.
      assert.equal((await apiCall(s, 'POST', `/jobs/${jstop.id}/resume`, { chain: 'sol' })).status, 200)
      const again = executor(s, { jobId: jstop.id, chain: 'sol', key: jstop.keys.sol }).start()
      const t38 = Date.now()
      while (!journalOf(s, jstop.id).some((e) => e.type === 'intent' && e.data.part === 38)) {
        assert.ok(Date.now() - t38 < 180_000, 'part 38 signed after the resume'); await sleep(200)
      }
      assert.equal((await apiCall(s, 'POST', `/jobs/${jstop.id}/stop`, { chain: 'sol' })).status, 200)
      assert.equal(await again, 'stopped')
      lines = journalOf(s, jstop.id)
      assert.ok(lines.some((e) => e.chain === 'sol' && e.type === 'resumed'), 'the executor reopened it after the operator\'s resume')
      assert.equal(lines.filter((e) => e.type === 'intent' && e.data.part === 38).length, 1, 'continued at part 38, once')
      assert.equal(lines.filter((e) => e.type === 'intent' && e.data.part === 37).length, 1, 'part 37 never twice')
      assert.ok(!lines.some((e) => e.type === 'intent' && Number(e.data.part) > 38), 'the second Stop held before part 39')
      evidence('long-message', 'L-stop stop between parts at SOL part 37, resume, part 38, stop', { part37: hstop.txId, stoppedAfterPart: 37, phase: cs.phase, laterRun: 'reopened by resume: part 38, then stopped' })
    }),
  ])
  await waitChains(s, jstop.id, (st) => st.chains.sol!.phase === 'STOPPED', 10_000, 'stays STOPPED')
  evidence('long-message', 'timing', { totalMs: ms(t0) })
})
