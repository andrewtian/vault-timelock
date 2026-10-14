// cli/src/report.ts — how a failed vt command is reported (plan Tasks C1, C5): one line on stderr and the exit code.
//   refusal  `refused <guard-id>: <message>`, exit 2 (a guard said no: nothing was done past it);
//   usage    `vt: <message>`, exit 1 (wrong or missing words);
//   other    `vt: error: <message>`, exit 1.
// src/main.ts and the job command test stub (test/fixtures/job-stub.ts) both use it, so the stub's output is main's.
import { isRefusal } from '@vault-timelock/core/contracts'
import { UsageError } from './args.ts'

export function failure(e: unknown): { code: number; line: string } {
  if (isRefusal(e)) return { code: 2, line: `refused ${e.guardId}: ${e.message}\n` }
  if (e instanceof UsageError) return { code: 1, line: `vt: ${e.message}\n` }
  return { code: 1, line: `vt: error: ${e instanceof Error ? e.message : String(e)}\n` }
}
