// cli/test/fixtures/browser-executor.ts — TEST ONLY (never in a release: cli/test is excluded). The page's executor,
// simulated in Node in its own process so a test can SIGKILL it mid-job (a tab closed or crashed): E3's createExecutor
// with the BROWSER adapter (browserAdapter: the wall clock, crypto.getRandomValues) and holder 'browser', its clients
// reaching a test stack's real API and relay through test/integration/stack.ts's stackFetch (the page server would add
// the token; here the shim carries it). Input: one JSON line in VT_C6_BROWSER (a synthetic key secret, the job id and
// chain, the stack's ephemeral ports, the API token). Output: `browser started`, then `outcome <RunOutcome>`.
import { PORTS } from '@vault-timelock/core/contracts'
import { browserAdapter, createExecutor, httpJournalClient, httpRelayClient } from '@vault-timelock/core/executor'
import { fromSecret } from '@vault-timelock/core/engine/keys.js'
import { stackFetch } from '../../../test/integration/stack.ts'

const o = JSON.parse(process.env.VT_C6_BROWSER ?? '{}') as { jobId: string; chain: 'eth' | 'sol'; secret: string; api: number; relay: number; token: string }
const handle = fromSecret(o.chain, o.secret) as { address: string }
const f = stackFetch({ api: o.api, relay: o.relay })
const journal = httpJournalClient({ base: `http://127.0.0.1:${PORTS.local.api}`, fetch: f, token: o.token })
const relay = httpRelayClient({ base: `http://127.0.0.1:${PORTS.local.relay}`, fetch: f })
const { clock, random } = browserAdapter()
const ex = createExecutor({ jobId: o.jobId, chain: o.chain, key: { chain: o.chain, address: handle.address, network: 'local', handle }, holder: 'browser',
  deps: { journal, relay, clock, random, poll: 300 } })
process.stdout.write('browser started\n')
const outcome = await ex.start()
process.stdout.write(`outcome ${outcome}\n`)
process.exit(0)
