// cli/test/fixtures/job-stub.ts — TEST ONLY (never in a release: cli/test is excluded). A process that runs a `vt job …`
// command exactly as src/main.ts does (src/job/index.ts jobCommand with processIo, failures reported by
// src/report.ts), but against the ports it is given (a test's fake API and relay on ephemeral 127.0.0.1 ports) and
// without bin/vt's sandbox (the test suite's sandbox is around it). Start it as bin/vt starts node,
// `node --disable-sigusr1 job-stub.ts …`: the executor commands refuse anything else (vt.inspector). Before anything
// else it reports its own command line, as the process sees it, and its pid on stderr:
//   vt-job-stub argv {"argv":[…],"execArgv":[…],"pid":N}
// so a test can check that no message byte ever reaches the argv of the process that uploads the text, and signal it.
//   node --disable-sigusr1 cli/test/fixtures/job-stub.ts <api port> <relay port> <network> <job subcommand> [args…]
// VT_JOB_STUB_POLL (tests only): the executor's poll interval in ms for `job run` / `job clawback` (a test seam main.ts
// never sets).
// VT_JOB_STUB_FAULT (tests only): <point>:<kind>, the test-only fault hook (fault-hook.ts) as RunDeps.fault, which src
// refuses unless NODE_ENV=test (vt.test-fault). With it, the stub keeps every key handle loaded and prints on exit
//   vt-job-stub keys-zeroed true|false        (every loaded key's SOL secret bytes are all zero)
import { isNetwork } from '@vault-timelock/core/contracts'
import { writeSync } from 'node:fs'
import { jobCommand, processIo } from '../../src/job/index.ts'
import type { RunDeps } from '../../src/job/run.ts'
import { failure } from '../../src/report.ts'
import { faultHook, parseFault } from './fault-hook.ts'

process.stderr.write(`vt-job-stub argv ${JSON.stringify({ argv: process.argv, execArgv: process.execArgv, pid: process.pid })}\n`)
const [api, relay, network, ...argv] = process.argv.slice(2)
try {
  if (!isNetwork(network)) throw new Error('job-stub: usage: <api port> <relay port> <network> <job args…>')
  const run: RunDeps = {}
  const poll = Number(process.env.VT_JOB_STUB_POLL ?? '')
  if (Number.isSafeInteger(poll) && poll > 0) run.poll = poll
  const fault = parseFault(process.env.VT_JOB_STUB_FAULT)
  if (fault !== null) {
    const loaded: Array<{ kp?: { _keypair?: { secretKey?: Uint8Array } } } | null> = []
    run.fault = faultHook(fault)
    run.onKey = (k) => { loaded.push(k.handle as never) }
    process.on('exit', () => {
      const zeroed = loaded.length > 0 && loaded.every((h) => h?.kp?._keypair?.secretKey !== undefined && h.kp._keypair.secretKey.every((b) => b === 0))
      writeSync(2, `vt-job-stub keys-zeroed ${zeroed}\n`)
    })
  }
  process.exitCode = await jobCommand(argv, processIo({ network, env: process.env, ports: { page: 1, relay: Number(relay), api: Number(api) } }),
    Object.keys(run).length > 0 ? { run } : {})
} catch (e) {
  const f = failure(e)
  process.stderr.write(f.line)
  process.exitCode = f.code
}
