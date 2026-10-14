// cli/test/fixtures/vt-entry.ts — TEST ONLY (M1 glue; never in a release: a release copies cli/src and cli/bin only, and
// one holding a test/ or fixtures/ path is refused release.test-only-present). It runs the REAL vt dispatcher
// (src/main.ts runMain: the env checks, the confinement proof, the dev-dirs rule, the network, `vt job …`) with main()'s
// ports seam, so `vt job run` / `vt job clawback` reach a LOCAL stack on ephemeral ports (the E4 integration harness,
// test/integration/harness/stack.ts runCli) instead of the network's fixed ports. The caller applies what bin/vt would:
// env -i (an explicit environment) and the executor's sandbox profile for the stack's two ports, VT_CONFINED=1.
//   VT_TEST_PORTS=api=<port>,relay=<port>[,page=<port>] NODE_ENV=test node cli/test/fixtures/vt-entry.ts <vt args…>
// Refused (vt.test-only) unless NODE_ENV=test: here first, then by main() itself (a dev tree, local only). bin/vt's
// env -i passes neither NODE_ENV nor VT_TEST_PORTS (test/args.test.ts).
import { PORTS, refuse } from '@vault-timelock/core/contracts'
import type { Ports } from '../../src/job/client.ts'
import { runMain } from '../../src/main.ts'
import { failure } from '../../src/report.ts'

function testPorts(v: string | undefined): Ports {
  if (process.env.NODE_ENV !== 'test') refuse('vt.test-only', 'cli/test/fixtures/vt-entry.ts is a test fixture: it runs only with NODE_ENV=test')
  const m = /^api=([1-9][0-9]{0,4}),relay=([1-9][0-9]{0,4})(?:,page=([1-9][0-9]{0,4}))?$/.exec(v ?? '')
  const ok = m !== null && [m[1], m[2], m[3] ?? '1'].every((p) => Number(p) <= 65535)
  if (!ok) throw new Error('vt-entry: VT_TEST_PORTS must be api=<port>,relay=<port>[,page=<port>]')
  return { api: Number(m![1]), relay: Number(m![2]), page: m![3] === undefined ? PORTS.local.page : Number(m![3]) }
}

let ports: Ports
try {
  ports = testPorts(process.env.VT_TEST_PORTS)
} catch (e) {
  const f = failure(e)
  process.stderr.write(f.line)
  process.exit(f.code)
}
const env = { ...process.env }
delete env.VT_TEST_PORTS
await runMain(process.argv.slice(2), env, { ports })
