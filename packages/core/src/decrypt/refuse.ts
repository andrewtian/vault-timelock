// The six decrypt.* refusals, each in ONE place (the mutation runner allows one marker per guard id): every check in src/decrypt
// that refuses calls one of these, so blanking a marker line removes that refusal from every check at once, and the mapped
// tests must notice. Messages never carry plaintext, a passphrase or an identity.
import { refuse } from '../text/guard.ts'
import { unlockIso } from '../text/drand.ts'

export function refuseKind(message: string): never {
  refuse('decrypt.kind', message) // @guard:decrypt.kind
}

export function refusePassphrase(): never {
  refuse('decrypt.passphrase', 'the passphrase does not open this file') // @guard:decrypt.passphrase
}

export function refuseIdentity(message: string): never {
  refuse('decrypt.identity', message) // @guard:decrypt.identity
}

/** The round is not reached yet: "opens at <UTC>". */
export function refuseTooEarly(round: number, unpublished = false): never {
  refuse('decrypt.too-early', unpublished ? `too early: drand has not published round ${round} yet (relay)` : `too early: this time lock opens at ${unlockIso(round)} (drand quicknet round ${round})`) // @guard:decrypt.too-early
}

export function refuseFormat(message: string): never {
  refuse('decrypt.format', message) // @guard:decrypt.format
}

/** `what` is over its bound (sizes only; never the secret itself). */
export function refuseSize(what: string): never {
  refuse('decrypt.size', `${what}: over this tool's bound`) // @guard:decrypt.size
}

/** n > max → decrypt.size. */
export function bounded(n: number, max: number, what: string): void {
  if (!(n <= max)) refuseSize(`${what} is larger than ${max}`)
}
