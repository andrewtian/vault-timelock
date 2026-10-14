// Guard primitive: Refusal and refuse() live in @vault-timelock/core (browser-safe, shared with the API and the page;
// moved there by E6). Every refusal in broadcast/ is still one line:
//   if (!ok) refuse('<guard-id>', '<message>')   followed by the guard marker comment
// The mutation runner (test/mutation/run.ts) blanks that line and requires the mapped tests
// (test/mutation/guards.json) to fail.
// exitCodeFor stays here: it is the CLI's exit-code policy.
import { Refusal } from '@vault-timelock/core/text/guard.ts'
export { Refusal, refuse } from '@vault-timelock/core/text/guard.ts'

// Fail closed: only a Refusal maps to 2; everything else is 1; nothing unknown is 0.
export function exitCodeFor(e: unknown): number {
  if (e instanceof Refusal) return 2 // @guard:exit-code-refusal
  return 1
}
