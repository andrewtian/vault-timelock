// The cross-lane guard-id union and the HTTP status map.
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import assert from 'node:assert/strict'
import { GUARD_ID, GUARD_IDS, httpStatusFor, isGuardId } from '../../src/contracts/index.ts'

test('ids are well formed and unique', () => {
  for (const id of GUARD_IDS) assert.match(id, GUARD_ID)
  assert.equal(new Set(GUARD_IDS).size, GUARD_IDS.length)
})

test('the ids every lane relies on are present', () => {
  for (const id of ['job.publish-mode', 'job.publish-mode-unavailable', 'job.fee-strategy', 'job.key-busy', 'message.utf8', 'lease.reconcile-first',
    'relay.ticket-raw', 'release.mainnet-locked', 'executor.network-mismatch', 'vt.dev-dirs-required', 'contract.network', 'contract.fork-override',
    'fork.drift', 'trigger.uncleared', 'api.internal']) assert.ok(isGuardId(id), id)
  assert.equal(isGuardId('job.recipient'), false)
})

test('CC-1 (I1) additions to the union', () => {
  for (const id of ['job.arweave-copy', 'engine.cap-copy', 'engine.cap-clawback', 'engine.cap-armed', 'engine.cap-busy', 'engine.cap-ledger',
    'vt.relay-ports', 'config.identity-mismatch', 'config.identity-unknown', 'config.mainnet-host', 'net.send-permit']) assert.ok(isGuardId(id), id)
})

test('CC-7 additions to the union: job.chain-unsupported, job.text-kind (400 by the job family)', () => {
  for (const id of ['job.chain-unsupported', 'job.text-kind']) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 400, id) }
  assert.ok(isGuardId('executor.chain-unsupported'))
})

test('CC-2b (I2) additions to the union: every lane-internal id the ledger lists', () => {
  for (const id of ['event.duplicate', 'event.attempt', 'event.family', 'relay.method', 'relay.host', 'relay.origin', 'relay.fetch-site', 'relay.header-repeated',
    'serve.host', 'serve.origin', 'serve.fetch-site', 'serve.header-repeated', 'executor.key-mismatch', 'executor.skip', 'vt.op-session', 'vt.tor-socks',
    'vt.tor-required', 'vt.log-control', 'vt.log-ip', 'release.mismatch', 'release.test-only-present', 'release.index-flags', 'release.lock-drift']) assert.ok(isGuardId(id), id)
})

test('CC-4 (M1) additions to the union: the lane-internal ids C5/C6 added since CC-2b, and the M1 glue\'s', () => {
  for (const id of ['vt.message-path', 'vt.publish-confirm', 'vt.message-changed', 'vt.message-hardlink', 'backup.network', 'job.clawback-typed',
    'vt.test-only']) assert.ok(isGuardId(id), id)
})

test('LN1 additions to the union: the localnet family (cli `vt localnet`; CLI refusals, no API status of their own)', () => {
  for (const id of ['localnet.network', 'localnet.port-taken', 'localnet.port-forbidden', 'localnet.tool-missing', 'localnet.ord-version', 'localnet.reset-path',
    'localnet.fund-network', 'localnet.fund-address']) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 500, id) }
})

test('PF-C (M-5) additions to the union: arm.again, arm.ticks, arm.tor (CLI-side arm refusals)', () => {
  for (const id of ['arm.again', 'arm.ticks', 'arm.tor']) assert.ok(isGuardId(id), id)
  assert.ok(isGuardId('vt.read-allow'))
  assert.ok(isGuardId('job.resume-typed'))
})

test('CC-5 (M1.1a) additions to the union: C6 fix round 1, W6, E5 and the M1.1a glue', () => {
  for (const id of ['vt.inspector', 'vt.test-fault', 'job.clawback-precompile', 'vt.message-workdir', 'web.backup-network',
    'engine.fee-window-first', 'engine.fee-tip-input']) assert.ok(isGuardId(id), id)
  assert.equal(httpStatusFor('job.clawback-precompile'), 400)
})

test('CC-6 (M3prep) additions to the union: S5, Sfix1 and E5', () => {
  const ids = ['source.label', 'source.unknown', 'source.reused', 'source.exhausted', 'engine.nonce-disagree', 'engine.code-disagree', 'engine.eip7702',
    'relay.ticket-endpoint-reused', 'relay.endpoint-unverified', 'relay.endpoint-read-only']
  for (const id of ids) assert.ok(isGuardId(id), id)
  const want: Record<string, number> = { 'source.label': 400, 'source.unknown': 400, 'source.reused': 409, 'source.exhausted': 409,
    'engine.nonce-disagree': 500, 'engine.code-disagree': 500, 'engine.eip7702': 500 /* lane refusals, never an API reply: the family default */,
    'relay.ticket-endpoint-reused': 403, 'relay.endpoint-unverified': 403, 'relay.endpoint-read-only': 403 }
  for (const [g, s] of Object.entries(want)) assert.equal(httpStatusFor(g), s, g)
})

test('CC-9 (M4a) additions to the union: plan E6 (text modules) and plan S6 (relay breadth)', () => {
  const e6: Record<string, string[]> = {
    note: ['empty', 'utf8', 'replacement', 'control', 'bidi', 'whitespace', 'nfc', 'too-long'],
    envelope: ['ar-id', 'unlock', 'too-long'],
    armor: ['malformed'],
    published: ['unlock-mismatch', 'sealed-form', 'too-long', 'sol-too-long'],
    sealed: ['already-open', 'armor-noncanonical', 'chain-info', 'file', 'format', 'key-only-needs-ar', 'non-ascii', 'not-age', 'round', 'selfcheck', 'stanza'],
    drand: ['chain-info'],
    payload: ['empty', 'control', 'bidi', 'nfc', 'header', 'sealed-missing', 'sealed-end', 'sealed-non-ascii', 'unlock-mismatch', 'contents', 'armor',
      'not-age', 'block-mismatch', 'no-blocks', 'too-long', 'invisible', 'sealed-duplicate', 'note-structure', 'trailing-blank', 'unlock-line',
      'round-mismatch', 'sealed-line', 'sealed-structure', 'layout', 'stanza', 'sealed-text', 'invalid'],
  }
  let n = 0
  for (const [f, ids] of Object.entries(e6)) for (const i of ids) { n++; assert.ok(isGuardId(`${f}.${i}`), `${f}.${i}`); assert.equal(httpStatusFor(`${f}.${i}`), 500, 'not an API reply yet: the family default') }
  assert.equal(n, 55)
  assert.equal(isGuardId('guard-id-format'), false)
  const want: Record<string, number> = { 'relay.path': 403, 'relay.btc-params': 403, 'relay.upstream-shape': 502, 'relay.upstream-secret': 502, 'relay.service-identity': 503 }
  for (const [g, s] of Object.entries(want)) { assert.ok(isGuardId(g), g); assert.equal(httpStatusFor(g), s, g) }
})

test('contracts/guard.ts and text/guard.ts share ONE Refusal class', async () => {
  const a = await import('../../src/contracts/guard.ts')
  const b = await import('../../src/text/guard.ts')
  assert.equal(a.Refusal, b.Refusal)
  assert.equal(a.refuse, b.refuse)
  assert.equal(a.exitCodeFor(new b.Refusal('job.format', 'x')), 2)
  assert.equal(a.exitCodeFor(new Error('x')), 1)
})

test('CC-8 (S6b) addition to the union: relay.btc-prevout (403 like every relay gate refusal)', () => {
  assert.ok(isGuardId('relay.btc-prevout'))
  assert.equal(httpStatusFor('relay.btc-prevout'), 403)
})

test('E7 additions to the union: engine.btc-order, engine.btc-rebuild (lane refusals: the family default)', () => {
  for (const g of ['engine.btc-order', 'engine.btc-rebuild', 'engine.btc-open', 'engine.btc-fee-rate']) { assert.ok(isGuardId(g), g); assert.equal(httpStatusFor(g), 500, g) }
})

test('CC-12 (E7b): job.fee-rate is in the union and answers 400 like the job family', () => {
  assert.ok(isGuardId('job.fee-rate'))
  assert.equal(httpStatusFor('job.fee-rate'), 400)
})

test('HTTP status per spec §5.1', () => {
  const want: Record<string, number> = {
    'job.format': 400, 'event.shape': 400, 'api.token': 401, 'api.host': 403, 'api.origin': 403, 'api.fetch-site': 403,
    'job.missing': 404, 'lease.held': 409, 'lease.reconcile-first': 409, 'job.armed': 409, 'job.key-busy': 409, 'job.state': 409,
    'api.body-cap': 413, 'api.content-type': 415, 'release.mainnet-locked': 423, 'trigger.uncleared': 423, 'journal.corrupt': 503,
    'api.internal': 500, 'message.too-long': 413, 'message.digest': 400, 'arm.typed': 400, 'unknown.thing': 500,
    'job.arweave-copy': 400, 'config.identity-mismatch': 502, 'config.identity-unknown': 502 /* CC-1 */, 'config.mainnet-host': 500,
    'event.duplicate': 400, 'event.attempt': 400, 'event.family': 400 /* CC-2b: by family, as S2 answers them */,
  }
  for (const [g, s] of Object.entries(want)) assert.equal(httpStatusFor(g), s, g)
})

test('Efix3 additions to the union: engine.sol-expiry-unreadable|stale (lane refusals, the family default status)', () => {
  for (const id of ['engine.sol-expiry-unreadable', 'engine.sol-expiry-stale', 'engine.sol-expiry-status', 'engine.sol-expiry-finalized', 'engine.code-disagree']) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 500, id) }
})

test('CC-10/11 (M4b): every id in the core mutation map is in the union; engine.sol-expiry-* and relay.btc-prevout statuses', () => {
  // (the api, cli and web maps were enumerated against the union at M4b by script; only core's own map is reachable from a mutation copy)
  const j = JSON.parse(readFileSync(new URL('../mutation/guards.json', import.meta.url), 'utf8'))
  let n = 0
  for (const id of Object.keys(j)) { if (!id.includes('.')) continue; n++; assert.ok(isGuardId(id), id) }
  assert.ok(n > 100, String(n))
  assert.equal(httpStatusFor('relay.btc-prevout'), 403)
  for (const id of ['unreadable', 'stale', 'status', 'finalized']) assert.equal(httpStatusFor(`engine.sol-expiry-${id}`), 500)
})

test('CC-W6 (plan W6) additions to the union: the provenance family (core gates/provenance.ts; page-side refusals, the family default 500)', () => {
  for (const i of ['incomplete', 'paged', 'no-inbound', 'not-railgun', 'nonce', 'unaccounted']) {
    assert.ok(isGuardId(`provenance.${i}`), i)
    assert.equal(httpStatusFor(`provenance.${i}`), 500, i)
  }
})

test('CC-12 (M4c): the Privacy Cash relay and mint ids are in the union with their statuses; the provenance verdicts are informational (500) and attest / required are gone', () => {
  const relay403 = ['query', 'body', 'check', 'lane', 'network', 'accounts', 'amount', 'fee', 'proof', 'ext-hash', 'replay', 'allowance', 'ledger', 'ledger-lock', 'send-lock']
  for (const i of relay403) { assert.ok(isGuardId(`relay.pc-${i}`), i); assert.equal(httpStatusFor(`relay.pc-${i}`), 403, i) }
  const other: Record<string, number> = { 'body-cap': 413, tor: 503, artifact: 503, 'rpc-identity': 503, 'upstream-shape': 502 }
  for (const [i, s] of Object.entries(other)) { assert.ok(isGuardId(`relay.pc-${i}`), i); assert.equal(httpStatusFor(`relay.pc-${i}`), s, i) }
  assert.equal(GUARD_IDS.filter((g) => g.startsWith('relay.pc-')).length, relay403.length + Object.keys(other).length)
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('api.pc-')).map((g) => [g, httpStatusFor(g)]), [['api.pc-lock', 423], ['api.pc-ledger', 503], ['api.pc-allowance', 409]])
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('provenance.')), ['incomplete', 'paged', 'no-inbound', 'not-railgun', 'nonce', 'unaccounted'].map((i) => `provenance.${i}`))
  assert.equal(isGuardId('provenance.attest'), false)
  assert.equal(isGuardId('provenance.required'), false)
  for (const g of ['engine.btc-order', 'engine.btc-rebuild', 'engine.btc-open', 'engine.btc-fee-rate']) assert.equal(httpStatusFor(g), 500, g)
  assert.equal(httpStatusFor('job.fee-rate'), 400)
})

test('PF-S additions to the union (pre-flip review): their statuses are the family defaults', () => {
  const want: Record<string, number> = { 'ticket.payload-plan': 409, 'ticket.recipient': 409, 'executor.endpoints-quorum': 500, 'arm.cap-ceiling': 400, 'job.copy-order': 400, 'job.clawback-required': 400, 'ticket.fee-plan': 409, 'intent.after-stop': 409 }
  for (const [id, status] of Object.entries(want)) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), status, id) }
  assert.equal(isGuardId('ticket.payload'), false)
})

test('CC-14 (M4f) additions to the union: Eminors and Wredl', () => {
  for (const id of ['job.btc-fee-ceiling', 'engine.btc-clawback', 'note.invisible', 'published.dest', 'web.backup-redo', 'web.decrypt-chain', 'web.decrypt-identity-cap', 'web.decrypt-round-echo', 'web.decrypt-secrets-dropped', 'web.decrypt-wipe', 'web.decrypt-file-cap', 'web.decrypt-live', 'web.decrypt-input-id', 'web.decrypt-drop-default']) assert.ok(isGuardId(id), id)
  assert.equal(httpStatusFor('job.btc-fee-ceiling'), 400)
  assert.equal(httpStatusFor('engine.btc-clawback'), 500)
  assert.equal(isGuardId('web.backup-nope'), false)
})

test('CC-15 (M5): the pre-flip ids of PF-S, LN1 and PF-C are in the union with their statuses; the union grew by exactly these since CC-14', () => {
  const want: Record<string, number> = {
    'ticket.payload-plan': 409, 'ticket.recipient': 409, 'ticket.fee-plan': 409, 'executor.endpoints-quorum': 500, 'arm.cap-ceiling': 400,
    'job.copy-order': 400, 'job.clawback-required': 400, 'intent.after-stop': 409,
    'localnet.network': 500, 'localnet.port-taken': 500, 'localnet.port-forbidden': 500, 'localnet.tool-missing': 500, 'localnet.ord-version': 500,
    'localnet.reset-path': 500, 'localnet.fund-network': 500, 'localnet.fund-address': 500,
    'arm.again': 400, 'arm.ticks': 400, 'arm.tor': 400, 'vt.read-allow': 500,
  }
  assert.equal(Object.keys(want).length, 20)
  for (const [id, status] of Object.entries(want)) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), status, id) }
  assert.equal(GUARD_IDS.length, 262 + 20 + 2 + 1 + 6 + 9 + 5 + 4, 'CC-14 had 262 ids; CC-15 adds exactly the 20 above; CC-16 the 2 of R79b (below); CC-17 vt.broker; vt decrypt the 6 decrypt.* and 9 page-only web.decrypt-* + lane C\'s 5 vt.* + lane B\'s 4 sealed.*')
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('intent.')), ['intent.after-stop'])
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('localnet.')).length, 8)
  // decode reasons are tokens under relay.decode-mismatch, never guard ids of their own
  for (const r of ['sol.extra-account', 'eth.fee-members', 'sol.layout', 'relay.sol-layout']) assert.equal(isGuardId(r), false, r)
  assert.ok(isGuardId('relay.decode-mismatch'))
})

test('R79b: the union adds exactly resume.final-stop (409, an exact entry: the resume family has no default)', () => {
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('resume.')), ['resume.final-stop'])
  assert.equal(httpStatusFor('resume.final-stop'), 409)
  assert.equal(httpStatusFor('resume.other'), 500, 'no family default')
})

test('CC-17 (TTY-less round 2): vt.broker (the sandboxed command\'s refusal on the unsandboxed broker\'s behalf: no prompt channel, the broker went away) is in the union, 500 (a CLI refusal, no API status)', () => {
  assert.ok(isGuardId('vt.broker'))
  assert.equal(httpStatusFor('vt.broker'), 500)
  assert.equal(GUARD_IDS.length, 282 + 2 + 1 + 6 + 9 + 5 + 4, 'CC-16 had 284 ids; CC-17 adds vt.broker (285); vt decrypt the 6 decrypt.* (291) and the 9 page-only web.decrypt-* (300) + lane C\'s 5 vt.* + lane B\'s 4 sealed.*')
})

test('CC-16 (M5c): the R79b ids of lanes E, S and C are in the union with their statuses; the union grew by exactly these since CC-15', () => {
  const want: Record<string, number> = { 'resume.final-stop': 409, 'job.resume-typed': 400 }
  for (const [id, status] of Object.entries(want)) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), status, id) }
  assert.equal(GUARD_IDS.length, 282 + Object.keys(want).length + 1 + 6 + 9 + 5 + 4, 'CC-15 had 282 ids; CC-16 adds exactly these 2 (+ CC-17 vt.broker, + the 6 decrypt.*) + lane C\'s 5 vt.* + lane B\'s 4 sealed.*')
  for (const r of ['resume.typed', 'job.resume-final', 'stop.final']) assert.equal(isGuardId(r), false, r)
})

test('vt decrypt (lane E): the decrypt family, exactly six ids, 500 (CLI and page refusals, no API status)', () => {
  const ids = ['kind', 'passphrase', 'identity', 'too-early', 'format', 'size'].map((i) => `decrypt.${i}`)
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('decrypt.')), ids)
  for (const id of ids) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 500, id) }
  assert.equal(GUARD_IDS.length, 285 + 6 + 9 + 5 + 4, 'CC-17 had 285 ids; vt decrypt adds exactly these 6 + lane C\'s 5 vt.* + lane B\'s 4 sealed.*')
  for (const r of ['decrypt.archive', 'decrypt.signature', 'decrypt.wrong']) assert.equal(isGuardId(r), false, r)
})

test('vt decrypt (lane C): the CLI adds exactly five vt.* ids (decrypt-input in its fix round 1), 500 (CLI refusals, no API status)', () => {
  const ids = ['decrypt-output', 'out-exists', 'relay-down', 'manifest', 'decrypt-input'].map((i) => `vt.${i}`)
  for (const id of ids) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 500, id) }
  assert.deepEqual(GUARD_IDS.filter((g) => g.startsWith('vt.')).slice(-5), ids)
  assert.equal(GUARD_IDS.length, 291 + 9 + 5 + 4, 'lane E\'s union had 291 ids; the page adds 9 web.decrypt-*; lane C adds exactly these 5 (+ lane B\'s 4 sealed.*)')
  for (const r of ['vt.decrypt', 'vt.paste', 'vt.plaintext-tty']) assert.equal(isGuardId(r), false, r)
})

test('lane B (seal --list, SEALED.txt format /2): sealed.layout, sealed.blocks, sealed.per-file-full-only, sealed.index-gzip are in the union, 500 (text-module refusals, the family default); the union grew by exactly these 4 since CC-17', () => {
  const ids = ['sealed.layout', 'sealed.blocks', 'sealed.per-file-full-only', 'sealed.index-gzip']
  for (const id of ids) { assert.ok(isGuardId(id), id); assert.equal(httpStatusFor(id), 500, id) }
  assert.equal(GUARD_IDS.filter((g) => g.startsWith('sealed.')).length, 11 + ids.length)
  assert.equal(GUARD_IDS.length, 285 + 6 + 9 + 5 + ids.length, 'CC-17 had 285; the 6 decrypt.*, 9 web.decrypt-* and lane C\'s 5 vt.* (above); lane B adds exactly these 4')
})
