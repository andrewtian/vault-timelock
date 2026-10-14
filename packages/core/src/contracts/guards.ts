// packages/core/src/contracts/guards.ts — the cross-lane guard-id union (strings only) for every id named in the plan,
// plus the rulings folded into Task 0 (R73 publish modes, ruling 6 fork checks) and spec §5.1's `api.internal`.
// Efix3 (CC-11, awaiting the controller's ruling): engine.sol-expiry-unreadable|stale (gates/sol-expiry.ts: an isBlockhashValid
// answer that is no proof of expiry; lane-internal, caught by solWait, never an API reply); engine.code-disagree is in the union
// since E5 (planE5 m-6).
// Ids introduced later by controller contract changes: M3 engine.nonce-disagree, engine.eip7702,
// source.label|unknown|reused|exhausted; M4 relay.path, provenance.*. CC-3 (ticket v2, S4, moved before the M2 flip)
// added relay.decode-mismatch: the signed bytes do not decode to what the ticket binds (http.ts).
// Lane-internal ids (wrapper.*, passphrase.*, net.*, config.*, …) live with their code, not here, except those CC-1
// (I1) added because they cross a lane boundary or were ruled into the union: job.arweave-copy (CC-1 arweaveCopy);
// engine.cap-* (E2's spend-cap ledger, lane-internal but named for E3/S2/W); vt.relay-ports (C1 ruling 6);
// config.identity-mismatch|identity-unknown|mainnet-host and net.send-permit (C2: vt-broadcast/src/config.ts and
// net/fetch.ts, reached by S2/S3/E3/C7 through assertJobSendAllowed, identityMatches and createNet).
// CC-2b (I2) added every lane-internal id the ledger lists, so one union names every refusal a client can see:
//   event.duplicate|attempt|family (S2: the job service's send-path and evidence checks, 400 by family);
//   relay.method (S3: the default-deny method table) and relay.host|origin|fetch-site|header-repeated (S3: the relay's
//   request guards); serve.host|origin|fetch-site|header-repeated (S3: the page server's request guards);
//   executor.key-mismatch|skip (E3); vt.op-session|tor-socks (C1 fix round), vt.tor-required (C3),
//   vt.log-control|log-ip (C4: vt logs redaction); release.index-flags|lock-drift (C4: the release build; CC-2b
//   addendum). (E2's engine.cap-* ids came with CC-1; release.mismatch and release.test-only-present, which C4 uses,
//   were in the union from Task 0.)
// CC-4 (M1) adds every lane-internal id added since CC-2b (C5/C6), plus the M1 glue's:
//   vt.message-path|publish-confirm (C5: the message file comes from argv only, its path checks, the typed `publish`);
//   vt.message-changed|message-hardlink (C6: the file read once from a verified descriptor; hard links refused);
//   backup.network (C6: a backup from another network is refused); job.clawback-typed (C6: mainnet `claw back`);
//   vt.test-only (M1 glue: cli main()'s job ports seam outside NODE_ENV=test, a release or local).
// CC-5 (M1.1a) adds the ids of C6 fix round 1, W6, E5 and the M1.1a glue (enumerated from the @guard markers / refuse() calls and
//   every test/mutation/guards.json: these seven are the only ids added since CC-4):
//   vt.inspector (an executor not started as bin/vt starts node: --disable-sigusr1, no other node option, no NODE_OPTIONS, no inspector);
//   vt.test-fault (a fault hook outside NODE_ENV=test); vt.message-workdir (the sealer work directory checks);
//   job.clawback-precompile (an ETH claw-back to 0x…0001 to 0x…ffff: the CLI, the API and the page all refuse it);
//   web.backup-network (the page refuses a backup recorded for another network; a new `web` family: page-only refusals);
//   engine.fee-window-first|fee-tip-input (E5: the newest eth_feeHistory chunk failed so there is no passive window; a
//   maxTipGwei outside 0.1..100 or not a decimal).
// CC-6 (M3prep) adds every id the M3 lanes added (enumerated from every test/mutation/guards.json and the @guard markers; these ten
//   are the only cross-lane ids added since CC-5; vt-broadcast's own ids stay in its tree):
//   source.label|unknown|reused|exhausted (S5: a funding-source label that is malformed / not one of the job's / already spent on this
//   text / out of budget; 400, 400, 409, 409); engine.nonce-disagree|code-disagree|eip7702 (E5: the endpoints disagree about the
//   key's nonce or code, so the lane pauses; the agreed code is an EIP-7702 delegation, so the chain ends. Lane refusals, never an
//   API reply: no entry in the status table, so the engine family default (500) stands); relay.ticket-endpoint-reused|endpoint-unverified|
//   endpoint-read-only (Sfix1: /relay/sol/ep/<i> sends: one ticket per endpoint, an index that names no verified endpoint, an ETH ep
//   send; 403 like every relay gate refusal).
// CC-7 (M4 unblock) adds job.chain-unsupported (a job naming chains.btc: the btc lane is not enabled; 400 like the job family),
//   executor.chain-unsupported (an executor made for btc: a lane refusal, never an API reply, so the executor family default stands)
//   and job.text-kind (textKind is neither "plain" nor "timelocked"; 400). A textKind "timelocked" job is
//   refused job.publish-mode-unavailable (reserved) until E6/W7.
// CC-10/11 (M4b) ratify the union of the merged lanes (enumerated by script over every test/mutation/guards.json of core, api, cli and
//   web and the guard literals in src, against this list): relay.btc-prevout (S6b, CC-8: a btc send whose input values the relay could
//   not read from the chain; 403 like every relay gate refusal), engine.sol-expiry-unreadable|stale|status|finalized (Efix3: lane-internal
//   refusals meaning "no proof of expiry this round", never an API reply: the engine family default, 500) and engine.code-disagree (already
//   listed). Cfix4 and S6b fix round 1 add no other id. Efix3's `ChainRunView.delegated?: boolean` (contracts/executor.ts) is ratified as is:
//   optional, absent = false. The legacy broadcast guards.json ids (config.*, net.*, store.* ...) are not GuardIds and stay out.
// Eminors (CC-14) adds: job.btc-fee-ceiling (a NEW btc job without maxFeeRateSatVb: 400 like the job family; old journals keep the 500 sat/vB fallback),
//   engine.btc-clawback (a btc claw-back is asked: there is none yet; a lane/executor refusal before any lease, family default 500),
//   note.invisible (buildEnvelope: a zero-width / default-ignorable character in a NEW note, FE0E/FE0F excepted) and published.dest (an unknown
//   publish destination). The first two are API-visible families; the last two are text guards (no HTTP status of their own).
// PF-S (pre-flip review, lane S; ratified by CC-15 below) adds: ticket.payload-plan (I-1: an eth / sol job intent that is not the part the
//   API plans from the STORED message with the lane's planner — payloadSha256, parts, part, the copy marker; 409, the ticket family default)
//   and ticket.recipient (I-1: an eth job intent's eth.to is not the publish mode's recipient; 409). The `to` of an ETH job ticket is now the
//   job tx's recipient (http.ts CC-3 field list; it was null). executor.endpoints-quorum (M-2: a mainnet eth / sol chain is not started with
//   fewer than 2 relay-verified endpoints, gates/agree.ts MAINNET_MIN_ENDPOINTS; an executor refusal before any lease, family default 500).
//   arm.cap-ceiling (M-4: off local the API re-applies engine/arm-caps.js armCapExcess to every armed chain: an untyped cap above the
//   price-free R60 native ceiling, a typed cap without a price, a cap worth more than the job's budgetUsd, a budget outside (0, 1000];
//   400, the arm family default). Fix round 1 adds job.copy-order (N-2: an intent's copy is the highest journaled copy of its chain, at
//   a part up to one past that copy's highest, or the next copy at part 1, in both modes; 400, the job family default) and
//   job.clawback-required (N-6: a NEW mainnet job names clawbackTo on each eth / sol chain; stored jobs keep theirs; 400). Fix round 2 adds
//   ticket.fee-plan (R1-1: an intent's declared fee members outside the plan — ETH gas beyond its payload's formula window or, for a
//   claw-back, not the transfer gas of a destination class; a SOL CU limit above the model's or a CU price above the lane's cap, a SOL
//   claw-back's above the claw-back ladder's cap; 409) and the ticket field x (http.ts: the fee members the relay binds). Fix round 3 adds
//   the `intent` family with intent.after-stop (a job intent on a chain with a stop request or a journaled stop: nothing new is signed
//   after a Stop — no replacement, bump, next part or copy — except the reveal of a btc copy whose commit is out; claw-backs are not
//   refused by it; 409, an exact entry: the family has no default).
// CC-14 (M4f) is the post-M4e union: the four Eminors ids above plus web.backup-redo (Wredl: the page's "make a new backup" redo on the key
//   lane; page-only, a new id in the web family). Shapes: `stopped` event data is `{reason, delegated?: true}` (exactly true, optional, on
//   `stopped` only) and ChainState.delegated?: true (present only while the chain's journaled stop says the lane key is EIP-7702-delegated;
//   GET /jobs projects it). vt-job-1.schema.json keeps maxFeeRateSatVb OPTIONAL, but it is REQUIRED at creation for btc chains
//   (normalizeJob: job.btc-fee-ceiling, 400); stored jobs without it keep the 500 sat/vB fallback. New 400/500 statuses: job.btc-fee-ceiling 400,
//   engine.btc-clawback 500 (family default). The API ships with/before the executor: an older API refuses `stopped.delegated` with event.shape.
// CC-15 (M5, pre-flip merge of PF-E + PF-S + LN1/PF-C) ratifies the union of those lanes (enumerated by script at M5 over the @guard markers
//   and refuse('…') literals of packages/core, api, cli and web src and every test/mutation/guards.json — each marker has its guards.json
//   entry and vice versa in every workspace, and every id is in this list; these 20 are the only ids added since CC-14; PF-E adds none,
//   its new paths journal `stuck` / `stopped` with a reason): ticket.payload-plan, ticket.recipient, ticket.fee-plan (409, the ticket
//   family default), executor.endpoints-quorum (500, executor family default: a refusal before any lease, never an API reply),
//   arm.cap-ceiling (400), job.copy-order (400), job.clawback-required (400), intent.after-stop (409, an exact entry: the `intent` family
//   has no default), localnet.network|port-taken|port-forbidden|tool-missing|ord-version|reset-path|fund-network|fund-address (CLI
//   refusals: the family default 500 is never an HTTP reply), arm.again|ticks|tor (CLI-side `vt job arm` refusals; the arm family
//   default 400 is never an HTTP reply for them) and vt.read-allow (the executor/client read allow-list refuses a subpath holding
//   $HOME, ~/.local, ~/p, the state, OUT or "/": 500). Ticket fields (http.ts): `to` on an ETH job ticket is the publish mode's
//   recipient (it was null), `x` is the intent's declared fee members (ETH "<gas>:<tip>:<maxFee>", SOL "<cuLimit>:<cuPrice>", btc null).
//   relay.decode-mismatch gains three reasons (tokens under the one guard, no new id): sol.extra-account (a SOL account key the tx does
//   not use), eth.fee-members (ETH gas / tip / maxFee are not x exactly), sol.layout (the SOL message is not byte for byte vt's builder's
//   from a, q, x and the memo or to / value). The API and the relay of this build ship together: a relay of this build refuses an ETH
//   job ticket with `to` null or without `x` (an older API's), and an older relay does not check them.
// CC-15 addendum (M5b, the merge of lane-s PF-S fix rounds 5–6) adds NO id: the refusals reuse job.state (core: executor phase events and
//   job intents on a stop-latched chain or a settled base) and intent.after-stop (the API: a job intent on a stop-latched chain). It
//   ratifies three shapes, whose rules are in types.ts (stopLatched, base phase):
//   · ChainState.stopLatched?: true — the stop latch: set by a journaled `stopped`, cleared ONLY by the operator's resume-requested (the
//     API's resume route, chain or all); present only while set and the chain is not SKIPPED, CLAWED_BACK or DONE. The reducer view is
//     JobReducer.stopLatched(c).
//   · ChainState.stuckBase?: ChainPhase — present only while the phase is STUCK: the base phase under the overlay, which the event gate
//     judges executor phase events on (a JobState without it under STUCK reads as STUCK: refused, fail closed).
//   · JobReducer.basePhase(c): ChainPhase | null — the phase under the STUCK overlay (SKIPPED for a skipped chain; null for a chain the
//     job lacks); the reducer view of stuckBase, which every production gate reads.
//   GET /jobs projects both fields as reduced (contract fixtures 14-stopped: stopLatched; 09a-stuck: stuckBase RUNNING). The API and core
//   of this build ship together: an older core lacks the latch, so its gate lets executor events revive a STOPPED or settled chain.
// CC-12 (M4c) ratifies the union of the M4 lanes: the btc lane (engine.btc-order|btc-rebuild|btc-open|btc-fee-rate, job.fee-rate, all already
//   listed above), the Privacy Cash relay and mint ids of S7 / Sfix-PC (relay.pc-* x20, api.pc-lock|pc-ledger|pc-allowance with their statuses
//   in the table below: api.pc-lock 423, api.pc-allowance 409, api.pc-ledger 503) and the six informational provenance.* verdicts of W6. Also
//   BtcIntent (types.ts), AttemptView.btc + rawSha256, OpenIntent.btc, vt-publish/3 with btc.inscription, DEFAULT_PUBLISH_MODE.btc and the btc cost
//   semantics (types.ts header: a commit's reserved/fee = its fee + the value it locks, a reveal's = 0).
// CC-9 (M4a) adds the ids of plan E6 and plan S6 (enumerated from every test/mutation/guards.json and the @guard markers):
//   note|envelope|armor|published|sealed|drand|payload.* (E6: the timelocked text modules moved from broadcast into packages/core/src/text,
//   55 ids: the 27 that moved with them and the 28 new ones, 16 from the plan and 12 from fix round 1; `guard-id-format` is a bare id
//   with no family, so it stays in core's guards.json only). They are text-module refusals, not yet API replies: no entry in the
//   status table, so the family default (500) stands and a test pins that; the API wiring (W7) decides their statuses.
//   relay.path (a /relay path off the network's list), relay.btc-params (a bitcoind scantxoutset other than 'start' + addr()): 403, the
//   relay's gate status; relay.upstream-shape, relay.upstream-secret (an upstream answer not in the route's shape / carrying the
//   bitcoind credential: withheld): 502; relay.service-identity (a service endpoint answered another identity, so the service is
//   disabled: the route answers 503). contracts/guard.ts now re-exports packages/core/src/text/guard.ts, so there is ONE Refusal class.
// CC-8 (S6b) adds relay.btc-prevout (a btc send whose input values the relay could not read from the chain: the ticketed
//   tx is refused, fail closed; 403 like every relay gate refusal; http.ts has the btc ticket binding).
// E7 fix round 1 adds engine.btc-open (an attempt that may still land is left open: the run ends failed, never `stopped`) and
//   engine.btc-fee-rate (the fee rate is above the tickets' 500 sat/vB: nothing is signed). Lane refusals, family default 500.
// E7 (BTC lane; controller to number the contract change) adds engine.btc-order (a reveal asked before its commit landed in a block,
//   seen by txid: the lane refuses and builds nothing) and engine.btc-rebuild (a journaled BTC attempt that is not on the chain and
//   cannot be rebuilt byte for byte, or whose inputs are spent: the run stops with the attempt left open, nothing built beside it).
//   Lane refusals, never an API reply: the engine family default (500) stands.
// LN1 (lane-c, R77) adds the `localnet` family (cli `vt localnet`, local setup): network (a non-local --network), port-taken (a port answers
//   with another identity), port-forbidden (a port override naming :8899/:8900), tool-missing, ord-version (not 0.29.0), reset-path (--reset
//   outside $VT_HOME/localnet), fund-network (the node is not a local chain), fund-address (malformed or wrong-network address). CLI refusals,
//   no HTTP status (the family default, 500, is never reached: no API reply carries them).
// PF-C (lane-c, M-5) adds arm.again|ticks|tor: CLI-side refusals of `vt job arm` (a key with history needs the typed `again`; mainnet needs the
//   five ticks acknowledged; testnet/mainnet need the relay's IsTor). Never an API reply; the arm family default (400) is unused by them.
// CC-12 (E7b) adds job.fee-rate (maxFeeRateSatVb outside 1..500 or not an integer, 400 like the job family) and the btc lane on local
//   (job.chain-unsupported now means btc off the local network).
// CC-W6 (plan W6, a controller-ratified contract change) adds the `provenance` family (core gates/provenance.ts, D-R21): incomplete|paged
//   (the reading is malformed / has another page), no-inbound, not-railgun, nonce, unaccounted (the §6.2 `eth` row): INFORMATIONAL verdict
//   entries (R76: nothing gates Arm on them; attest and required were removed). No status-table entry: the family default (500) stands.
// R79b (fix round 4, lane E owns the union edit) adds the `resume` family: resume.final-stop — `vt job resume` / the page's Resume on a chain
//   whose stop is FINAL (contracts/stop.ts: the stop-reason classes; a missing or unknown code is FINAL) is refused, 409 (an exact entry:
//   the family has no default), with a message that names the reason and the way out (stop.ts finalStopText: claw back or close, then a
//   new job). The API refuses it (lane S); the executor never reopens a FINAL stop either (executor.ts, its own marker). Shapes: `stopped`
//   event data is `{reason, code?, delegated?}` (code one of STOP_CODE_LIST; optional for journals from before R79b, every writer of this
//   build sets it) and ChainState.stopCode?: StopCode (present only while the base is STOPPED with a known code; GET /jobs projects it).
// CC-16 (M5c, the R79b merge of lanes E, S, C and W + Wresume) ratifies the union of those lanes (enumerated by script at M5c over the
//   @guard markers of packages/core, api, cli, web and broadcast src/bin and every test/mutation/guards.json: each marker has its
//   guards.json entry and vice versa, and every core/api/cli/web id is in this list; these 2 are the only ids added since CC-15):
//   resume.final-stop (409, an exact entry: the `resume` family has no default; the API's resume route — lane S — and the executor's own
//   reopen check — lane E) and job.resume-typed (400, the job family default; CLI-side: `vt job resume` on mainnet without the typed word
//   `resume` — lane C; never an API reply: the API does not require the word, the CLI and the page ask it, like `again`). Shapes:
//   · `stopped` event data `{reason, code?, delegated?}`: code one of STOP_CODE_LIST (contracts/stop.ts); optional only so journals from
//     before R79b replay — every writer of this build sets it (the lane, the executor, the API's stop route: operator-stop);
//   · the stop-code table (contracts/stop.ts STOP_CODES): RESUMABLE operator-stop, start-check, rpc-unavailable; FINAL readback-mismatch,
//     reverted, reassembly-mismatch, eip7702, spend-cap, stuck, tx-failed, exhausted, integrity; stopClassOf reads a FINAL code, then the
//     journal's FINAL facts (readback not ok, a failed reassembly, a delegated key, a stuck or mark-failed attempt), then a RESUMABLE code;
//     anything else (no code, an unknown code) is FINAL (fail closed);
//   · ChainState.stopCode?: StopCode and ChainState.stopClass?: 'resumable' | 'final' — present only while the chain's base is STOPPED
//     (phase STOPPED, or STUCK over a STOPPED base); stopCode only for a code this build knows. GET /jobs projects both (fixture
//     14-stopped). The field is stopCode (never "stopReason"); `reason` stays the text. The executor, `vt job run` and the page reopen a
//     resumed STOPPED chain only when stopClass is 'resumable' (absent = final);
//   · the resume route's answer `{ seq, resumed: Chain[], refused: [{ chain, guard: 'resume.final-stop', message }] }` (message =
//     stop.ts finalStopText: the reason, its code and the way out — claw back or close, then a new job). A resume of ONE chain whose stop is
//     FINAL, and a resume of every chain when every one is FINAL, is the 409 error body instead (nothing journaled, the latch stays);
//   · the API's phase rule (M-4): an executor's `resumed` (or any phase event but `stopped`, and copy-built) on a STOPPED base while a new
//     stop request is pending is refused job.state, until the operator resumes again.
//   The API, core, CLI and page of this build ship together: an older API lifts a FINAL stop; an older core journals stops without a
//   code, which this build reads as FINAL.
export const GUARDS = {
  job: ['format', 'unknown-key', 'network-field', 'network', 'name', 'address', 'budget', 'tip-cap', 'cu-cap', 'mode',
    'publish-mode', 'publish-mode-unavailable', 'fee-strategy', 'clawback', 'field-chain', 'message-source',
    'message-file', 'key-like', 'ip-like', 'missing', 'armed', 'state', 'key-busy', 'resolve-typed', 'arweave-copy',
    'clawback-typed', 'resume-typed', 'clawback-precompile', 'chain-unsupported', 'text-kind', 'fee-rate', 'btc-fee-ceiling', 'copy-order', 'clawback-required'],
  source: ['label', 'unknown', 'reused', 'exhausted'],
  message: ['empty', 'nfc', 'control', 'utf8', 'too-long', 'secret', 'ip-like', 'digest', 'missing'],
  event: ['type', 'shape', 'by', 'duplicate', 'attempt', 'family'],
  arm: ['typed', 'amount', 'chains', 'countdown', 'stagger', 'cap-ceiling', 'again', 'ticks', 'tor'],
  api: ['host', 'origin', 'fetch-site', 'token', 'token-missing', 'content-type', 'body-cap', 'json', 'key-like', 'ip-like',
    'not-confined', 'already-running', 'test-only', 'args', 'internal', 'pc-lock', 'pc-ledger', 'pc-allowance'],
  journal: ['write', 'corrupt'],
  lease: ['held', 'lost', 'stale', 'reconcile-first', 'holder'],
  ticket: ['not-intent', 'terminal', 'payload-plan', 'recipient', 'fee-plan'],
  intent: ['after-stop'],
  resume: ['final-stop'],
  relay: ['send-ticket', 'ticket-network', 'ticket-chain', 'ticket-expired', 'ticket-raw', 'airdrop-network', 'decode-mismatch',
    'method', 'host', 'origin', 'fetch-site', 'header-repeated', 'ticket-endpoint-reused', 'endpoint-unverified', 'endpoint-read-only',
    'path', 'btc-params', 'upstream-shape', 'upstream-secret', 'service-identity', 'btc-prevout',
    'pc-query', 'pc-body', 'pc-body-cap', 'pc-check', 'pc-lane', 'pc-network', 'pc-accounts', 'pc-amount', 'pc-fee', 'pc-proof', 'pc-ext-hash',
    'pc-replay', 'pc-allowance', 'pc-ledger', 'pc-ledger-lock', 'pc-send-lock', 'pc-tor', 'pc-artifact', 'pc-rpc-identity', 'pc-upstream-shape'],
  serve: ['host', 'origin', 'fetch-site', 'header-repeated'],
  release: ['mainnet-locked', 'mismatch', 'test-only-present', 'index-flags', 'lock-drift'],
  executor: ['network-mismatch', 'reconcile', 'key-mismatch', 'skip', 'chain-unsupported', 'endpoints-quorum'],
  engine: ['no-ticket', 'cap', 'cap-copy', 'cap-clawback', 'cap-armed', 'cap-busy', 'cap-ledger',
    'fee-window-first', 'fee-tip-input', 'nonce-disagree', 'code-disagree', 'eip7702', 'sol-expiry-unreadable', 'sol-expiry-stale', 'sol-expiry-status', 'sol-expiry-finalized',
    'btc-order', 'btc-rebuild', 'btc-open', 'btc-fee-rate', 'btc-clawback'],
  backup: ['decrypt', 'chain', 'address-mismatch', 'inconsistent', 'network'],
  vt: ['env', 'flag', 'network-invalid', 'no-sandbox', 'port', 'path', 'dev-dirs-required', 'mainnet-dev-tree',
    'tty-required', 'sealer-stub-only', 'not-confined', 'backup-format', 'relay-ports', 'op-session', 'tor-socks', 'tor-required',
    'log-control', 'log-ip', 'message-path', 'publish-confirm', 'message-changed', 'message-hardlink', 'test-only',
    'inspector', 'test-fault', 'message-workdir', 'read-allow', 'broker'],
  localnet: ['network', 'port-taken', 'port-forbidden', 'tool-missing', 'ord-version', 'reset-path', 'fund-network', 'fund-address'],
  contract: ['network', 'fork-override'],
  fork: ['drift'],
  trigger: ['uncleared'],
  config: ['identity-mismatch', 'identity-unknown', 'mainnet-host'],
  net: ['send-permit'],
  web: ['backup-network', 'backup-redo'],
  provenance: ['incomplete', 'paged', 'no-inbound', 'not-railgun', 'nonce', 'unaccounted'],
  note: ['empty', 'utf8', 'replacement', 'control', 'bidi', 'invisible', 'whitespace', 'nfc', 'too-long'],
  envelope: ['ar-id', 'unlock', 'too-long'],
  armor: ['malformed'],
  published: ['unlock-mismatch', 'sealed-form', 'too-long', 'sol-too-long', 'dest'],
  sealed: ['already-open', 'armor-noncanonical', 'chain-info', 'file', 'format', 'key-only-needs-ar', 'non-ascii', 'not-age', 'round',
    'selfcheck', 'stanza'],
  drand: ['chain-info'],
  payload: ['empty', 'control', 'bidi', 'nfc', 'header', 'sealed-missing', 'sealed-end', 'sealed-non-ascii', 'unlock-mismatch', 'contents',
    'armor', 'not-age', 'block-mismatch', 'no-blocks', 'too-long', 'invisible', 'sealed-duplicate', 'note-structure', 'trailing-blank',
    'unlock-line', 'round-mismatch', 'sealed-line', 'sealed-structure', 'layout', 'stanza', 'sealed-text', 'invalid'],
} as const

type Families = typeof GUARDS
export type GuardId = { [F in keyof Families]: `${F & string}.${Families[F][number]}` }[keyof Families]

export const GUARD_IDS: readonly GuardId[] = Object.entries(GUARDS)
  .flatMap(([family, ids]) => (ids as readonly string[]).map((id) => `${family}.${id}` as GuardId))

export function isGuardId(s: string): s is GuardId {
  return (GUARD_IDS as readonly string[]).includes(s)
}

// HTTP status for an API refusal (spec §5.1 table, then family defaults). Rows not in the spec table are marked (T0).
const EXACT: Readonly<Record<string, number>> = {
  'api.token': 401,
  'api.host': 403, 'api.origin': 403, 'api.fetch-site': 403,
  'job.missing': 404,
  'job.armed': 409, 'job.key-busy': 409, 'job.state': 409, 'intent.after-stop': 409 /* (PF-S fix round 3) a state conflict, like job.state */,
  'resume.final-stop': 409 /* (R79b) a resume of a FINAL stop: a state conflict, like job.state */,
  'api.body-cap': 413, 'message.too-long': 413 /* (T0) the PUT /messages cap */,
  'api.content-type': 415,
  'release.mainnet-locked': 423, 'trigger.uncleared': 423,
  'config.identity-mismatch': 502, 'config.identity-unknown': 502 /* (CC-1) the upstream chain identity is wrong or unknown */,
  'journal.corrupt': 503, 'journal.write': 503 /* (T0) nothing was acked */,
  'api.internal': 500,
  'source.reused': 409, 'source.exhausted': 409 /* (CC-6) a source already spent on this text / out of budget: a state conflict, like job.armed */,
  'relay.ticket-endpoint-reused': 403, 'relay.endpoint-unverified': 403, 'relay.endpoint-read-only': 403 /* (CC-6) the relay's gate refusal status */,
  'relay.path': 403, 'relay.btc-params': 403 /* (CC-9) the relay's gate refusal status */,
  'relay.upstream-shape': 502, 'relay.upstream-secret': 502 /* (CC-9) an upstream answer withheld */,
  'relay.service-identity': 503 /* (CC-9) the route of a service disabled for answering another identity */,
  'relay.btc-prevout': 403 /* (CC-8) likewise */,
  // CC-12 (S7, Sfix-PC): the Privacy Cash relay routes answer 403 (the gate refusal status) except the ones below; relay.pc-artifact and
  // relay.pc-rpc-identity are the 503 of a route that is not available (a circuit file that is not the pinned one; an RPC endpoint of another genesis).
  'relay.pc-query': 403, 'relay.pc-body': 403, 'relay.pc-check': 403, 'relay.pc-lane': 403, 'relay.pc-network': 403, 'relay.pc-accounts': 403,
  'relay.pc-amount': 403, 'relay.pc-fee': 403, 'relay.pc-proof': 403, 'relay.pc-ext-hash': 403, 'relay.pc-replay': 403, 'relay.pc-allowance': 403,
  'relay.pc-ledger': 403, 'relay.pc-ledger-lock': 403, 'relay.pc-send-lock': 403,
  'relay.pc-body-cap': 413, 'relay.pc-tor': 503, 'relay.pc-artifact': 503, 'relay.pc-rpc-identity': 503, 'relay.pc-upstream-shape': 502,
  'api.pc-lock': 423 /* a mainnet mint: the funding lock */, 'api.pc-allowance': 409 /* a reservation conflict, like job.armed */, 'api.pc-ledger': 503 /* the mint ledger is unusable, like journal.write */,
}
const FAMILY: Readonly<Record<string, number>> = {
  job: 400, event: 400, lease: 409, source: 400 /* (CC-6) label, unknown */,
  arm: 400 /* (T0) */, message: 400 /* (T0) */, api: 400 /* (T0) json, key-like, ip-like, args */, ticket: 409 /* (T0) */,
}
export function httpStatusFor(guard: string): number {
  if (Object.hasOwn(EXACT, guard)) return EXACT[guard]
  const family = guard.split('.')[0]
  return Object.hasOwn(FAMILY, family) ? FAMILY[family] : 500
}
