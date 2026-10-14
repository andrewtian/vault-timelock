// The Transport test seam. When createNet({ transport }) is given one, fetchFor sends requests
// through it instead of the SOCKS agent / the direct loopback socket. Every guard still applies
// (role, side, scheme, gate, request shape, timeout, redirect, body cap) and events are recorded.
//
// A transport that throws a Refusal has it passed through unchanged (e.g. the replay transport's
// unmatched-request refusal). Any other throw is tor.unreachable for a SOCKS-side request and
// net.failed for a loopback one; the thrown error's text never reaches the caller.
//
// The second argument, `real`, performs this same request over the real path (the role's SOCKS
// agent, or the direct loopback socket), with every guard of that path. A test transport may answer
// some requests itself (e.g. the gate's check) and hand the rest to `real()`.
//
// Production code never sets a transport: createNet refuses one outside a test runner
// (net.transport-test-only), and without one it poisons the fetch/WebSocket/http(s) globals.

export interface TransportRequest {
  readonly method: string
  readonly url: string
  readonly headers: Readonly<Record<string, string>>
  readonly body: Uint8Array | null
  // `<role>.<tick>` for a request that would go over SOCKS; null for a loopback request.
  readonly socksUser: string | null
}

export interface TransportResponse {
  readonly status: number
  readonly headers: Readonly<Record<string, string>>
  readonly body: Uint8Array
}

export type Transport = (req: TransportRequest, real: () => Promise<TransportResponse>) => Promise<TransportResponse>
