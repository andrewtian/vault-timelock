// Guard primitive, shared by vt-broadcast (CLI), the API and the page. Moved from broadcast/src/guard.ts (E6).
// Every refusal is one line:  if (!ok) refuse('<guard-id>', '<message>')  followed by the guard marker comment;
// the mutation runner blanks that line and requires the mapped tests (test/mutation/guards.json) to fail.
// exitCodeFor (the CLI's exit-code policy) stays in broadcast/src/guard.ts.
// contracts/guard.ts re-exports this file (CC-9), so there is ONE Refusal class.

export class Refusal extends Error {
  readonly guardId: string

  constructor(guardId: string, message: string) {
    super(message)
    this.name = 'Refusal'
    this.guardId = guardId
  }
}

export const GUARD_ID = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/

export function refuse(guardId: string, message: string): never {
  if (!GUARD_ID.test(guardId)) throw new Error('bad guard id') // @guard:guard-id-format
  throw new Refusal(guardId, message)
}

export function isRefusal(e: unknown): e is Refusal {
  if (!(e instanceof Error) || e.name !== 'Refusal') return false
  const id: unknown = (e as unknown as { guardId?: unknown }).guardId
  return typeof id === 'string' && GUARD_ID.test(id)
}
