// @vault-timelock/core/executor — the executor runtime (E3): createExecutor (and the claw-back runner), the HTTP
// clients of the jobs API and the relay, the lease, the takeover reconcile and preflight. Browser-safe except
// adapters/node.ts (import it from '@vault-timelock/core/executor/node').
export { createExecutor, laneConfigOf, resumeOf } from './executor.ts'
export type { ExecutorKey, ExecutorOptions } from './executor.ts'
export { httpJournalClient, JournalUnreachable } from './journal-client.ts'
export type { Fetch } from './journal-client.ts'
export { httpRelayClient } from './relay-client.ts'
export { createLease } from './lease.ts'
export type { Clock, Lease } from './lease.ts'
export { reconcileChain } from './reconcile.ts'
export type { AdoptedEth, ReconcileResult } from './reconcile.ts'
export { preflight } from './preflight.ts'
export type { PreflightReport, PreflightRow } from './preflight.ts'
export { DELEGATED_DETAIL, DELEGATED_LABEL, DEV_TREE_BUILD_DETAIL, EXPECTED_SERVICES, REQUIRED_BREADTH, delegatedFromJobs, delegatedRows, localTorView, pageRows, readinessVerdict } from './readiness.ts'
export type { LocalTorView, ReadinessInput, ReadinessRow, ReadinessServices } from './readiness.ts'
export { browserAdapter, browserClients, uniform } from './adapters/browser.ts'
