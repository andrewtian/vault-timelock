// @vault-timelock/core/job — the job domain (Task E1): the vt-job/1 validator, the message rules, key-like and IP-like
// refusals, journal event shapes, the reducer, the arm schedule and the arm confirmations. Pure and browser-safe (no
// node: imports): the API (S2), the CLI (C) and the page (W) all import these, so each rule has one source.
export { canonicalJson, jobId, sha256Hex } from './canonical.ts'
export { assertNoSecretOrIp, looksLikeIp } from './keylike.ts'
export { validateMessage } from './message.ts'
export type { MessageInfo } from './message.ts'
export { normalizeJob, suggestedBtcFeeCeiling } from './validate.ts'
export { validateEvent } from './events.ts'
export { STRANDING_ATTEMPT, btcCommitStranded, btcStrandedIn, createReducer, isChainTerminal, reduce, worstFeeOf } from './reduce.ts'
export type { JobReducer, TxFact } from './reduce.ts'
export { drawSchedule, startAt } from './schedule.ts'
export { checkArmConfirm, checkClawbackConfirm } from './confirm.ts'
export { assertEventAllowed, assertIntentAllowed, eventRefusal, intentRefusal } from './intent.ts'
export type { IntentKind, JobView } from './intent.ts'
