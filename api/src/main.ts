// api/src/main.ts — the jobs API process (spec §3.1, §5).
//
//   node api/src/main.ts --network <local|testnet|mainnet> --home <VT_HOME> [--build <id>]
//
// Startup, in order, every step fail closed (a refusal prints `refused <guard>: <message>` and exits 2):
//   1. arguments (api.args, contract.network); no key-like environment variable (config.env-key);
//   2. <home>/<network>/ must be a private (0700) directory (store.perms);
//   3. api.token and relay-ticket.key, 0600, 64 hex each (api.token-missing);
//   4. the single-instance lock api.lock (api.already-running);
//   5. the confinement proof (api.not-confined): EPERM on a write outside the state dir, loopback 9 / the relay port /
//      9050, the DNS socket and TEST-NET-1 (confine.ts);
//   6. listen on 127.0.0.1:PORTS[network].api and print `vt-api ready network=<n> port=<p> build=<b>`.
// Nothing under jobs/ is opened, repaired or written before listen (S1 review m7): the job service opens a job's journal
// on the first request that names it, so an instance that lost a stale-lock race fails on EADDRINUSE first.
// $OUT (the legacy trigger latch, read-only) follows VAULT_TIMELOCK_DIR's rule (broadcast resolveOut); it must be
// absolute (api.args). `vt up` passes VAULT_TIMELOCK_DIR in the API's env (always, from a dev tree).
// Tests only (NODE_ENV=test): `--port 0` listens on an ephemeral port instead (api.test-only otherwise).
// Output never carries an address, a path, a header or a body: only the ready line, one line per request (method,
// route name, status, ms, guard) and refusals.
import { createServer } from 'node:http'
import { isAbsolute, join } from 'node:path'
import { PORTS, exitCodeFor, isRefusal } from '@vault-timelock/core/contracts'
import { assertNoKeyEnv } from 'vt-broadcast/src/config.ts'
import { checkPrivateDir, resolveOut } from 'vt-broadcast/src/lifecycle/paths.ts'
import { assertArgs, parseArgs } from './args.ts'
import { readSecretHex } from './auth.ts'
import { systemClock } from './clock.ts'
import { proveConfined } from './confine.ts'
import { takeLock } from './lock.ts'
import type { ApiLock } from './lock.ts'
import { createApi, createRegistry } from './routes.ts'

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))
  assertNoKeyEnv(process.env)
  const out = resolveOut(process.env)
  assertArgs(isAbsolute(out) && !out.includes('\0'))
  const stateDir = join(args.home, args.network)
  checkPrivateDir(stateDir) // missing: the secrets below are missing too (api.token-missing)
  const token = readSecretHex(join(stateDir, 'api.token'))
  const ticketKey = Buffer.from(readSecretHex(join(stateDir, 'relay-ticket.key')), 'hex')
  const lock: ApiLock = takeLock(join(stateDir, 'api.lock'))
  let server: ReturnType<typeof createServer> | null = null
  let registry: ReturnType<typeof createRegistry> | null = null
  const stop = (code: number): void => {
    if (registry !== null) registry.close() // the final trace.txt flush (the twins are written at most once per few seconds)
    lock.release()
    if (server !== null) server.close()
    process.exit(code)
  }
  try {
    await proveConfined(PORTS[args.network].relay, stateDir)
    // Sfix-PC: the Privacy Cash lane cap (lamports per lane address), from VT_PC_LANE_CAP_LAMPORTS; absent or malformed: no cap, so
    // the mint refuses (api.pc-ledger). Not a secret.
    const capText = process.env.VT_PC_LANE_CAP_LAMPORTS
    const capLamports = typeof capText === 'string' && /^[1-9][0-9]{0,17}$/.test(capText) ? BigInt(capText) : 0n
    const privacyCash = { capLamports }
    registry = createRegistry({ stateDir, network: args.network, clock: systemClock, out, ticketKey, privacyCash })
    const api = createApi({
      network: args.network, token, build: args.build, clock: systemClock, registry,
      log: (line) => { process.stdout.write(`${line}\n`) },
    })
    server = createServer(api.handle)
    const s = server
    await new Promise<void>((resolve, reject) => {
      s.once('error', reject)
      s.listen(args.port ?? PORTS[args.network].api, '127.0.0.1', () => { s.off('error', reject); resolve() })
    })
  } catch (e) {
    lock.release()
    throw e
  }
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) process.once(sig, () => stop(0))
  const addr = server.address()
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0
  process.stdout.write(`vt-api ready network=${args.network} port=${port} build=${args.build}\n`)
}

try {
  await main()
} catch (e) {
  if (isRefusal(e)) process.stderr.write(`refused ${e.guardId}: ${e.message}\n`)
  else {
    const code = (e as NodeJS.ErrnoException | null)?.code
    process.stderr.write(`vt-api: startup failed${typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? ` (${code})` : ''}\n`)
  }
  process.exit(exitCodeFor(e))
}
