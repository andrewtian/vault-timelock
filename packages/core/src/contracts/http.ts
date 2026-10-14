// packages/core/src/contracts/http.ts — paths (API side; the page uses '/api' + path) and headers (Task 0, verbatim),
// plus additive constants below the verbatim block.
export const TICKET_HEADER = 'x-vt-send-ticket'
export const P = {
  status: '/status', jobs: '/jobs', job: (id: string) => `/jobs/${id}`, message: (sha: string) => `/messages/${sha}`,
  arm: (id: string) => `/jobs/${id}/arm`, skip: (id: string) => `/jobs/${id}/skip`, stop: (id: string) => `/jobs/${id}/stop`,
  resume: (id: string) => `/jobs/${id}/resume`, close: (id: string) => `/jobs/${id}/close`,
  lease: (id: string, c: string) => `/jobs/${id}/chains/${c}/lease`, events: (id: string, c: string) => `/jobs/${id}/chains/${c}/events`,
  tickets: (id: string, c: string) => `/jobs/${id}/chains/${c}/tickets`, resolve: (id: string, c: string) => `/jobs/${id}/chains/${c}/resolve`,
  stream: (id: string, from = 0) => `/jobs/${id}/events?from=${from}`, receipt: (id: string) => `/jobs/${id}/receipt`,
} as const
// Ticket (CC-3, v2; CC-3a adds q; PF-S fix round 2 adds x): 'vt-ticket/2.' + b64url(JSON {j,w,c,g,t,r,a,k,p,to,value,f,q,x,e,n}) + '.'
//                     + b64url(HMAC-SHA256(key, 'vt-ticket/2.' + b64url(payload)))
export type TicketKind = 'job' | 'clawback' | 'commit' | 'reveal'   // CC-8: commit | reveal are the btc kinds
export interface TicketPayload {
  j: string; w: 'local' | 'testnet' | 'mainnet'; c: 'eth' | 'sol' | 'btc'; g: number; t: string; r: string
  a: string; k: TicketKind; p: string | null; to: string | null; value: string | null; f: string; q: string; x: string | null
  e: number; n: string
}

// ---- additive (Task 0) ----
// b64url = RFC 4648 §5 without padding. The payload JSON is written with keys in exactly the order above and no
// whitespace; n = 16 lowercase hex. Vectors: contract/fixtures/tickets.json.
// CC-3 (ticket v2, controller-approved; relay decode verification S4, required before the M2 mainnet flip). The MAC
// covers every field. v1 ('vt-ticket/1.', payload j,w,c,g,t,r,e,n) is REFUSED everywhere (relay.send-ticket): no
// downgrade, and a v1 payload MAC'd under the v2 prefix is refused too (its keys are not the v2 keys).
//   j job id (16 hex) · w network · c chain · g lease gen (≥ 1)
//   t txId: ETH 0x + 64 lowercase hex = keccak256(raw); SOL base58 of the first signature
//   r sha256(raw bytes) (64 lowercase hex)
//   a the sender (the job key): ETH 0x + 40 LOWERCASE hex; SOL canonical base58 of 32 bytes
//   k 'job' (an `intent`) | 'clawback' (a `clawback-intent`)
//   p job: the intent's payloadSha256 (64 lowercase hex); clawback: null. PF-S I-1: the API's OWN sha256 of the planned part
//     (planLaneCopy over the STORED message, copy marker included); an intent whose payloadSha256 / parts / part differ is refused
//     (ticket.payload-plan) and gets no ticket
//   to clawback: the destination (same format as a); job: ETH the job tx's recipient, which the publish mode fixes (PF-S I-1:
//     eth.calldata.null 0x000…000, eth.calldata.self = a; lower case; ticket.recipient refuses an intent to any other); SOL null
//   value clawback: the amount in base units (wei / lamports), decimal, no leading zero, ≥ 1; job: null
//   f the declared worst-case fee in base units (decimal, no leading zero, ≥ 1), the number the API's cap check
//     reserved for this attempt: ETH gas × maxFee; SOL max(intent fee, 5,000 × 1 + ⌈cuLimit × cuPrice / 10⁶⌉)
//   q (CC-3a) the attempt's declared identity, which the API's nonce families and the takeover reconcile rely on:
//     ETH the intent's eth.nonce (decimal, no leading zero, ≤ 20 digits); SOL the intent's sol.blockhash (canonical
//     base58 of 32 bytes). The relay refuses bytes signed at another nonce / over another recentBlockhash.
//   x (PF-S fix round 2, R1-1) the attempt's declared fee members, which the signed bytes must carry EXACTLY:
//     ETH "<gas>:<tip>:<maxFee>" (the intent's eth.gas, eth.tip, eth.maxFee; decimals, no leading zero; gas and maxFee ≥ 1);
//     SOL "<cuLimit>:<cuPrice>" (the intent's sol.cuLimit 1..1,400,000 and sol.cuPrice, µlamports per CU); btc null
//   e expiry (ms, valid while now < e) · n 16 lowercase hex from the CSPRNG (the ticket's own nonce, not the tx's)
// The relay forwards a send only if the signed bytes are exactly what was ticketed (relay.decode-mismatch otherwise):
//   ETH: an EIP-1559 (type 2) tx only (legacy, 2930, blob and EIP-7702 refused); canonical RLP (re-encodes to the same
//     bytes); chainId = the network's; nonce = q; low-s signature; recovered from = a; keccak256(raw) = t; gas > 0
//     and maxFeePerGas > 0 present; maxPriorityFeePerGas ≤ maxFeePerGas; gas × maxFeePerGas ≤ f; empty access list;
//     gas, maxPriorityFeePerGas and maxFeePerGas = x exactly (PF-S fix round 2; reason eth.fee-members, CC-15).
//     job: value 0, to = ticket to (exactly the publish mode's recipient, PF-S I-1), sha256(data) = p. clawback: to = ticket to,
//     value = ticket value, data empty.
//   SOL: a legacy message (v0 without address lookup tables passes these checks, then fails the builder check below);
//     canonical (re-serializes to the same bytes); exactly one signature, valid for the message, by the fee payer = a;
//     base58(signature) = t; recentBlockhash = q; no duplicate account keys;
//     programs ⊆ {ComputeBudget SetComputeUnitLimit / SetComputeUnitPrice (at most one each, no accounts), Memo v2
//     (MemoSq4…, no accounts), System transfer}; fee = 5,000 × 1 + ⌈limit × price / 10⁶⌉ ≤ f, where a missing limit
//     counts as 1,400,000 and a missing price as 0.
//     the message is EXACTLY the one vt's builder makes (PF-S fix round 2, R1-1: core chains/sol.js buildTx / buildTransfer,
//     rebuilt from a, q, x and the memo or to / value, compared byte for byte): a legacy message; a job carries
//     SetComputeUnitLimit(cuLimit), SetComputeUnitPrice(cuPrice) only when cuPrice > 0, then the memo; a claw-back carries
//     both ComputeBudget instructions (limit, then price) only when cuPrice > 0, then the transfer; so no other order, layout,
//     version or value passes (reason sol.layout, CC-15; checked last);
//     the account keys are exactly the ones used: a, the programs of the instructions present (Memo v2 / System;
//     ComputeBudget only with a CU instruction) and, for a claw-back, `to` (PF-S fix round 1, N-1: no extra key, read-only
//     or not; reason sol.extra-account, CC-15);
//     job: exactly one memo, sha256(memo data) = p, no System instruction, the only writable account is a.
//     clawback: exactly one System transfer (instruction 2) from a to ticket `to` of exactly `value`, no memo, the
//     only writable accounts are a and `to`.
// CC-8 (BTC tickets, controller-authorised; plan S6b + fix round 1; the same v2 format, the same 15 fields in the same order,
// the same MAC): c may be 'btc'. One ticket = one raw transaction: an ordinals text inscription is a COMMIT tx and a REVEAL tx,
// each with its own ticket (k 'commit' | 'reveal'; a btc ticket is never 'job' or 'clawback', an eth/sol one never 'commit' or
// 'reveal'). Field meanings for c = 'btc' (addresses are lower-case bech32 / bech32m of the ticket's network: hrp bcrt (local),
// tb (testnet4), bc (mainnet)). ★ SERVER-COMPUTED: the API mints a btc ticket ONLY from values it computes itself (api
// tickets.ts ticketBinding; the one derivation is packages/core/src/chains/btc-ord.ts, shared with the builder and the relay).
// The executor's intent contributes only its lane pubkey, a fee and commit value under the caps, the lane outpoints and the
// commit's vout; an intent whose fields differ from the server's computation is refused before it is journaled.
//   t  the tx's txid: 64 lowercase hex, the id Core, Esplora and ord show (the double SHA-256 of the serialization
//      WITHOUT witness data, byte-reversed)
//   r  sha256 of the raw tx bytes, the segwit serialization the node accepts; the relay forwards its lowercase hex, so
//      the bytes hashed are the bytes sent
//   a  the lane address: the job definition's btc key address, which must be the p2wpkh address of the intent's lane pubkey
//      (hash160 check; never its p2tr, which receives the reveal's postage); the address the commit's funding inputs pay and
//      its change returns to
//   k  'commit' | 'reveal'
//   p  sha256 of the exact inscription body (64 lowercase hex), the same on both tickets of a copy: the API's own hash of the
//      body it slices from the STORED message (the intent's payloadSha256 must equal it)
//   to commit: p2tr(NUMS internal key, the inscription leaf of the lane's x-only key and that body) = the commit address,
//      never `a` (btc-ord.ts commitAddress); reveal: p2tr(the lane's x-only key) (revealDestination)
//   value  commit: the sats on the commit output, postage (546) <= value <= postage + the reveal's fee cap; reveal: exactly
//      the postage, 546
// Rules the API applies around those tickets (S6b fix round 2 + Minors; api jobs.ts, ledger.ts):
//   · cap: a commit reserves its fee + the value it locks (f + value), a reveal 0; a LANDED commit charges at least that, whatever
//     fee its `included` / `reconcile` reports (an executor reports the tx's own fee, or fee + value: the ledger takes the larger);
//   · one open attempt per (copy, part): a second commit (or reveal) for a copy while one is pending is event.family;
//   · after an operator Stop (stop-requested chain 'btc') the API admits exactly ONE reveal intent for a copy whose commit is
//     journaled (landed, or pending when none landed): the commit locked value only its reveal can move. Its ticket is the same
//     server-computed one (q = that commit's txid : vout). A second reveal, a replacement and any new commit stay refused.
//   f  the worst-case fee in sats (decimal, no leading zero, >= 1): the tx's fee, its inputs' value minus its outputs',
//      must be <= f; the API binds only f <= 500 sat/vB x a vsize bound of the tx (btc-ord.ts maxCommitFee / maxRevealFee)
//   q  the input outpoints the tx spends: "<txid>:<vout>" (64 lowercase hex, decimal vout without leading zero),
//      1 to 8 of them joined by "," in strictly ascending plain string order; reveal: exactly one, the JOURNALED commit's
//      txid : the vout of its output to the commit address (the API takes the txid from its own journal)
// The relay forwards a btc send (POST /relay/btc/send) only if the raw tx is exactly what the ticket binds
// (relay.decode-mismatch otherwise), parsed with @scure/btc-signer (no hand-rolled parser):
//   both kinds: canonical (re-serializes to the same bytes); exactly the inputs q (no more, none twice), each signed;
//     a COMMIT input is signed SIGHASH_ALL and nothing else (btc.sighash otherwise): p2wpkh witness exactly [DER signature ending
//     0x01, the lane pubkey with hash160 = the prevout], p2tr key path exactly one 64-byte signature; any other sighash type
//     (NONE, SINGLE, ANYONECANPAY) makes the public signature re-spendable by anyone; the reveal's script-path signature is
//     exactly 64 bytes;
//     locktime 0; txid t; every output script one of the allowed ones below; fee = sum(inputs) - sum(outputs) with
//     0 <= fee <= f. The input values come from the relay's own read of the chain (bitcoind gettxout on local, Esplora
//     GET /tx/<txid> on testnet4 / mainnet), never from the caller; a read that does not answer, or an outpoint that is
//     not found, refuses relay.btc-prevout (fail closed).
//   commit: 1 or 2 outputs: exactly one to `to` (a taproot output) of exactly `value`, and at most one more, to `a`
//     (the change); every input's prevout pays `a`. The inscription itself is hidden in the taproot commitment, so p
//     cannot be checked on the commit; the reveal ticket checks it.
//   reveal: one input (q) and exactly one output, to `to`, of exactly `value`. The witness is EXACTLY the builder's: three
//     items (a 64-byte signature, the leaf, a 33-byte single-leaf control block over the NUMS key), and the leaf is, byte
//     for byte, the canonical one-inscription script p2tr_ord_reveal(key, [{ contentType 'text/plain;charset=utf-8', body }])
//     for the body whose sha256 is p, with `to` = p2tr(key). The leaf is REBUILT and compared, not parsed and trusted: ord's
//     envelope parser and micro-ordinals' differ on odd scripts (an OP_0 inside the body, an envelope opened by
//     OP_PUSHDATA1 0x00, a content type pushed twice), so any other script, however it parses, is refused.
// Ordering (the intent journaled before each send, the reveal only after the commit was accepted) is the engine's rule,
// not the relay's. Vectors: contract/fixtures/tickets-btc.json.
export const TICKET_PREFIX = 'vt-ticket/2.'
// Typed id fields: JSON string values under these keys skip assertNoSecretOrIp in API bodies (they are hashes or
// signatures by design). `sha256` (reassembled.sha256) is added to the spec §5.1 list: a 64-hex digest would
// otherwise be refused as key-like. validateEvent still checks each one's exact format.
// CC-1a: `replaces` (intent.replaces, a txId; E1 concern 1) and `messageSha256` (POST /jobs by digest, the canonical
// form; E1 review X-2). normalizeJob checks messageSha256's format; validateEvent checks replaces'.
// CC-8 (S6b fix round 2): `pubkey` (a btc intent's 33-byte compressed lane key, 66 hex) and `inputs` (its commit's lane outpoints,
// each `<txid>:<vout>`; the elements of an `inputs` array are classified by that name) are typed ids too; validateEvent checks them.
export const TYPED_ID_FIELDS = ['txId', 'prevId', 'rawSha256', 'payloadSha256', 'blockhash', 'sha256', 'replaces', 'messageSha256', 'pubkey', 'inputs'] as const
// Message text fields (CC-1a, E1 review X-2): the top-level `message` of POST /jobs (an inline message) is publication
// text. validateMessage governs it (message.* guards: unambiguous secrets, non-loopback IP literals, NFC, controls), NOT
// the body check: every SEALED.txt holds URLs, 64-hex values and 127.0.0.1:9050, which the strict structural scan
// (assertNoSecretOrIp) would refuse. Every other body string is structural. Only top-level members are message text.
export const MESSAGE_TEXT_FIELDS = ['message'] as const
// SSE framing (spec §5.2): one event per journal line; a heartbeat comment every SSE_HEARTBEAT_MS.
export const sseFrame = (seq: number, line: string): string => `id: ${seq}\ndata: ${line}\n\n`
export const sseHeartbeat = (serverNowMs: number): string => `: hb ${serverNowMs}\n\n`
export const JSON_CONTENT_TYPE = 'application/json; charset=utf-8'
export const TEXT_CONTENT_TYPE = 'text/plain; charset=utf-8'
export const SSE_CONTENT_TYPE = 'text/event-stream; charset=utf-8'
