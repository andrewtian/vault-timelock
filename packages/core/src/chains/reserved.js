// @ts-check
// packages/core/src/chains/reserved.js — the ONE source of "an address nobody controls" per chain (E6; M1.1a issues 1-2).
// Pure, no dependencies. Callers: the job validator (job.clawback / job.clawback-precompile at validation), the engine's
// claw-back (clawbackEth / clawbackSol), and — at the next merge — the CLI, the API and the page, which keep their own
// guard ids and swap their private 0xffff / burn-list constants for these.
//
//   ETH  0x…0000                 the null address (burn)                         kind 'null'
//        0x…dEaD                 the conventional burn address                   kind 'burn'
//        0x…0001 … 0x…ffff       the precompiles (0x01–0x11 today) and the range reserved for more; they hold no code,
//                                so a contract check passes them, yet nobody controls them        kind 'precompile'
//   SOL  11111111111111111111111111111111          the System Program               kind 'system'
//        1nc1nerator11111111111111111111111111111111   the incinerator (burns)     kind 'incinerator'
// A claw-back, or a job's clawbackTo, to any of these is refused: the value would be lost.

export const ETH_RESERVED_MAX = 0xffffn
export const ETH_BURN_ADDRESS = '0x000000000000000000000000000000000000dead'
export const SOL_SYSTEM_PROGRAM = '11111111111111111111111111111111'
export const SOL_INCINERATOR = '1nc1nerator11111111111111111111111111111111'

/** The class of a reserved ETH address, or null. @param {string} address a valid 0x + 40 hex ETH address (any case)
 *  @returns {'null' | 'burn' | 'precompile' | null} */
export function ethReservedKind(address) {
  const n = BigInt(address)
  if (n === 0n) return 'null'
  if (n === BigInt(ETH_BURN_ADDRESS)) return 'burn'                  // 0xdEaD is inside the 0x…ffff range: judged first, as a burn
  return n <= ETH_RESERVED_MAX ? 'precompile' : null
}
/** @param {string} address a valid 0x + 40 hex ETH address @returns {boolean} true for 0x0, 0x…0001–0x…ffff and 0x…dEaD */
export const isEthReserved = (address) => ethReservedKind(address) !== null

/** The class of a reserved SOL address, or null. @param {string} address canonical base58 @returns {'system' | 'incinerator' | null} */
export function solReservedKind(address) {
  if (address === SOL_SYSTEM_PROGRAM) return 'system'
  return address === SOL_INCINERATOR ? 'incinerator' : null
}
/** @param {string} address canonical base58 @returns {boolean} true for the System Program and the incinerator */
export const isSolReserved = (address) => solReservedKind(address) !== null
