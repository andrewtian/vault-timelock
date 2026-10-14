// packages/core/src/gates/send.ts — the send gate (spec §7.2). Every send-type RPC the engine makes (chains/eth.js send,
// chains/sol.js send and rebroadcast) carries the relay send ticket the API issued with the acked intent; no ticket, no
// send. The relay checks the ticket itself (MAC, expiry, chain, network, sha256 of the raw bytes); this gate makes a
// missing or malformed one a refusal before any byte leaves the process, so a code path that skips the intent cannot
// reach the relay.
//   engine.no-ticket  the ticket is not a string of the contract's form (contracts/http.ts TICKET_PREFIX, v2 since
//                     CC-3): TICKET_PREFIX + b64url(payload) + '.' + b64url(32-byte MAC) — header-safe characters only
//                     (it travels in x-vt-send-ticket)
import { TICKET_PREFIX, refuse } from '../contracts/index.ts'

const TICKET = new RegExp(`^${TICKET_PREFIX.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}[A-Za-z0-9_-]{1,2048}\\.[A-Za-z0-9_-]{43}$`)

export function assertTicketedSend(ticket: string | undefined): void {
  const ok = typeof ticket === 'string' && TICKET.test(ticket)
  if (!ok) refuse('engine.no-ticket', 'refusing a send without a relay send ticket from an acked intent') // @guard:engine.no-ticket
}
