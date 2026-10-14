// cli/src/ops/localnet-miner.ts — the `miner` window of `vt localnet`: one regtest block every N seconds, so a BTC commit and its
// reveal confirm without a manual step (the BTC lane waits for one confirmation; nothing else in vt mines).
//   node localnet-miner.ts <auth-file> <state-file> <bitcoind-port> <seconds>
// ★ The credential is read from the 0600 auth file (`vt:<pass>`) named on the command line: its PATH is in argv, its contents
//   never are, and nothing here prints it. Blocks are mined to a fresh address of the wallet `vt` (the funding wallet of
//   `vt localnet fund btc`). Loopback only.
import { readSmallFile } from './stack.ts'
import { jsonRpc, listenerPidOf, sleepMs } from './localnet-rpc.ts'

export const MINER_READY = /^vt-miner ready every (\d+) s$/
export const WALLET = 'vt'

// M-4: the credential goes only to the bitcoind vt recorded: before every request the pid listening on the port must equal the pid in state.json
// (`vt localnet up` writes it when it starts bitcoind). Otherwise the miner exits (status 3) and sends nothing.
export function ownerOk(stateFile: string, port: number, listenerPid: (port: number) => number | null): boolean {
  const t = readSmallFile(stateFile, { cap: 4096, privateOnly: true })
  let rec: unknown
  try { rec = t === null ? undefined : (JSON.parse(t) as { pids?: { bitcoind?: unknown } }).pids?.bitcoind } catch { rec = undefined }
  const now = listenerPid(port)
  return typeof rec === 'number' && now !== null && now === rec
}

export async function mineLoop(o: { authFile: string; stateFile: string; port: number; seconds: number; log: (l: string) => void; stop?: () => boolean; listenerPid?: (port: number) => number | null }): Promise<boolean> {
  const lp = o.listenerPid ?? ((p: number) => listenerPidOf(p, process.env))
  const read = (): string | null => {
    const t = readSmallFile(o.authFile, { cap: 4096, privateOnly: true })
    const line = t === null ? '' : t.replace(/\n$/, '')
    return /^[^:\s]+:[^\s]+$/.test(line) ? line : null
  }
  let line = read()
  let addr: string | null = null
  let announced = false
  while (o.stop?.() !== true) {
    if (!ownerOk(o.stateFile, o.port, lp)) { o.log('vt-miner: the process on the bitcoind port is not the bitcoind vt started; exiting without sending anything'); return false }
    try {
      if (line === null) line = read()
      if (line === null) throw new Error('the credential file is unusable')
      if (addr === null) {
        const a = await jsonRpc(o.port, 'getnewaddress', [], { line, path: `/wallet/${WALLET}` })
        if (!a.ok) { if (a.status === 401) line = null; throw new Error(`getnewaddress: ${a.error}`) }
        addr = String(a.result)
      }
      const g = await jsonRpc(o.port, 'generatetoaddress', [1, addr], { line })
      if (!g.ok) { if (g.status === 401) line = null; throw new Error(`generatetoaddress: ${g.error}`) }
      if (!announced) { o.log(`vt-miner ready every ${o.seconds} s`); announced = true }
    } catch (e) {
      o.log(`vt-miner: ${e instanceof Error ? e.message : 'error'} (retrying)`)
    }
    await sleepMs(o.seconds * 1000)
  }
  return true
}

if (import.meta.main) {
  const [authFile, stateFile, port, seconds] = process.argv.slice(2)
  const p = Number(port), s = Number(seconds)
  if (authFile === undefined || stateFile === undefined || !Number.isInteger(p) || !Number.isInteger(s) || s < 1) {
    process.stderr.write('usage: localnet-miner.ts <auth-file> <state-file> <port> <seconds>\n')
    process.exit(2)
  }
  process.on('SIGTERM', () => process.exit(0))
  const ok = await mineLoop({ authFile, stateFile, port: p, seconds: s, log: (l) => { process.stdout.write(`${l}\n`) } })
  if (!ok) process.exit(3)
}
