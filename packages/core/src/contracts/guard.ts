// contracts/guard.ts re-exports packages/core/src/text/guard.ts (E6 moved the guard primitive there; CC-9 made this file a re-export), so
// there is ONE Refusal class for broadcast, the API, the CLI and the page. The guard markers live in text/guard.ts.
// exitCodeFor (the CLI's exit-code policy, fail closed: only a refusal maps to 2) stays here.
import { isRefusal } from '../text/guard.ts'

export { Refusal, GUARD_ID, refuse, isRefusal } from '../text/guard.ts'

export function exitCodeFor(e: unknown): number {
  return isRefusal(e) ? 2 : 1
}
