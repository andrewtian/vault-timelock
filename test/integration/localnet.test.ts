// LN1: `vt localnet` for real — the localnet HALF only (up -> status -> fund eth/sol/btc -> reuse -> port conflict -> down -> restart
// keeps data -> down). It does not start the relay/API: the relay reads the bitcoind credential from $VAULT_TIMELOCK_DIR/local/
// btc-rpc.auth, which this test checks exists (0600) and authenticates, but the relay's own ports for the local profile are fixed
// (8545/8999/18443/8090 via endpoints.json; VT_TEST_* overrides exist only for eth/sol/btc/ord, not exercised here).
// OWN SANDBOX (listed in own-sandbox.list: real tmux, real chains, unsandboxed). Never the shared chains: every port is an
// overridden free high port (LocalnetDeps.ports, the test-only seam), the tmux server is private (-L vt-ln-<pid>-<rand> in a private
// TMUX_TMPDIR), VT_HOME and VAULT_TIMELOCK_DIR are fresh temp dirs. Synthetic data only: coins on these throwaway chains. Docker/Otterscan is
// not started here (--no-otterscan equivalent).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { btcFromSecret } from '../../packages/core/src/chains/btc.js'
import { localnetDown, localnetFund, localnetStatus, localnetUp, defaultLocalnetDeps, readCredentialLine, SESSION } from '../../cli/src/ops/localnet.ts'
import type { LocalnetPorts } from '../../cli/src/ops/localnet.ts'
import { jsonRpc, tcpOpen } from '../../cli/src/ops/localnet-rpc.ts'
import { hasSession, listWindows, systemTmux } from '../../cli/src/ops/tmux.ts'
import { freeRun, sleep } from './stack.ts'
import { tempDir } from '../../api/test/helpers.ts'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function b58(b: Buffer): string {
  let n = BigInt(`0x${b.toString('hex')}`)
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  return s
}

test('vt localnet: up, status, fund, reuse, port conflict, down, restart keeps data (LN1)', { timeout: 600_000 }, async (t) => {
  const { dir, cleanup } = tempDir('vt-ln1-')
  const tm = tempDir('vt-ln1t-') // short TMUX_TMPDIR
  const home = join(dir, 'home'), out = join(dir, 'out')
  mkdirSync(home, { mode: 0o700 }); mkdirSync(out, { mode: 0o700 })
  const base = await freeRun(70)
  const ports: LocalnetPorts = { anvil: base, solana: base + 1, solanaFaucet: base + 3, solanaGossip: base + 4, solanaDynFrom: base + 5, solanaDynTo: base + 40, bitcoind: base + 41, ord: base + 42, otterscan: base + 43 }
  const sock = `vt-ln-${process.pid}-${randomBytes(3).toString('hex')}`
  const env = { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: dir, LANG: 'en_US.UTF-8', TERM: 'xterm', VT_HOME: home, VAULT_TIMELOCK_DIR: out, TMUX_TMPDIR: tm.dir }
  const tmux = systemTmux({ socket: sock, env })
  const all: string[] = []   // EVERYTHING vt printed (stdout and stderr lines of up, status, fund, down), scanned at the end
  const deps = { ...defaultLocalnetDeps(env, ports), tmux, out: (l: string) => { all.push(l) }, err: (l: string) => { all.push(l); process.stderr.write(`${l}\n`) } }
  const lines: string[] = []
  const rec = { ...deps, out: (l: string) => { lines.push(l); all.push(l) } }
  t.after(async () => {
    try { tmux.run(['kill-server']) } catch { /* gone */ }
    await sleep(500)
    cleanup(); tm.cleanup()
  })
  const up = (o: Partial<{ reset: boolean }> = {}) => localnetUp({ btc: true, otterscan: false, reset: o.reset ?? false, mineEvery: 2, env }, rec)
  // M8: Otterscan is optional. A docker that fails at once (an offline image pull, a container-name conflict ...) is a warning; the rest stays up.
  const failDocker = join(dir, 'fake-docker')
  writeFileSync(failDocker, '#!/bin/sh\necho "docker: simulated failure" >&2\nexit 1\n')
  chmodSync(failDocker, 0o755)
  const upWithBadDocker = () => localnetUp({ btc: true, otterscan: true, reset: false, mineEvery: 2, env }, { ...rec, tools: { ...rec.tools, docker: failDocker }, dockerReady: () => true, dockerRun: () => ({ code: 0 }) })

  // ---- up: everything starts
  assert.equal(await upWithBadDocker(), 0, lines.join('\n'))
  assert.ok(lines.some((l) => /^otterscan: NOT started \(warning, the rest is up\)/.test(l)), `otterscan failure is a warning: ${lines.join('\n')}`)
  assert.ok(hasSession(tmux, SESSION))
  assert.ok(!(listWindows(tmux, SESSION) ?? []).includes('otterscan'), 'the failed window was removed')
  for (const s of ['anvil', 'solana', 'bitcoind', 'miner', 'ord']) assert.ok(lines.some((l) => l.startsWith(s) && l.includes('started')), `${s} started: ${lines.join('\n')}`)
  const authFile = join(out, 'local', 'btc-rpc.auth')
  assert.equal(statSync(authFile).mode & 0o777, 0o600)
  const cred1 = readCredentialLine(out)
  assert.ok(cred1 !== null && cred1.startsWith('vt:'))
  const credHash = createHash('sha256').update(readFileSync(authFile)).digest('hex') // compared later, never printed
  assert.equal(statSync(join(home, 'localnet', 'bitcoind', 'bitcoin.conf')).mode & 0o777, 0o600)
  // the miner is mining
  const height = async (): Promise<number> => Number((await jsonRpc(ports.bitcoind, 'getblockcount', [], { line: cred1 as string }) as { result: number }).result)
  const h0 = await height()
  assert.ok(h0 >= 101, `101 blocks mined to the wallet (height ${h0})`)
  await sleep(5000)
  const h1 = await height()
  assert.ok(h1 > h0, 'the miner mines blocks')

  // ---- status is green and says vt started everything
  const sl: string[] = []
  assert.equal(await localnetStatus({ json: true, env }, { ...deps, out: (l) => { sl.push(l); all.push(l) } }), 0)
  const st = JSON.parse(sl[0]) as { ok: boolean; services: Array<{ name: string; identity: string; who: string }> }
  assert.equal(st.ok, true)
  for (const s of ['anvil', 'solana', 'bitcoind', 'miner', 'ord']) assert.deepEqual(st.services.find((x) => x.name === s) && { i: st.services.find((x) => x.name === s)?.identity, w: st.services.find((x) => x.name === s)?.who }, { i: 'ok', w: 'vt' }, s)

  // ---- fund eth / sol / btc
  const ethAddr = `0x${randomBytes(20).toString('hex')}`
  const solAddr = b58(Buffer.concat([Buffer.from([1]), randomBytes(31)]))
  const btcAddr = btcFromSecret(randomBytes(32).toString('hex'), 'local').address
  const fl: string[] = []
  const fdeps = { ports, out: (l: string) => { fl.push(l); all.push(l) } }
  assert.equal(await localnetFund({ chain: 'eth', address: ethAddr, amount: '0.5', env }, fdeps), 0)
  assert.equal(BigInt((await jsonRpc(ports.anvil, 'eth_getBalance', [ethAddr, 'latest']) as { result: string }).result), 5n * 10n ** 17n)
  assert.equal(await localnetFund({ chain: 'sol', address: solAddr, amount: '1.5', env }, fdeps), 0, fl.join('\n'))
  assert.equal((await jsonRpc(ports.solana, 'getBalance', [solAddr, { commitment: 'confirmed' }]) as { result: { value: number } }).result.value, 1_500_000_000)
  assert.equal(await localnetFund({ chain: 'btc', address: btcAddr, amount: '0.01', env }, fdeps), 0, fl.join('\n'))
  const btcTxid = (fl.find((l) => l.startsWith('txid ')) as string).split(' ')[1]
  const raw = (await jsonRpc(ports.bitcoind, 'getrawtransaction', [btcTxid, true], { line: cred1 as string }) as { result: { confirmations?: number; vout: Array<{ value: number; scriptPubKey: { address?: string } }> } }).result
  assert.ok(raw.vout.some((v) => v.scriptPubKey.address === btcAddr && v.value === 0.01), 'the 0.01 BTC output pays the address')
  assert.ok((raw.confirmations ?? 0) >= 1, 'fund btc mined a block')
  assert.ok(fl.every((l) => !l.includes(cred1 as string)), 'no credential in the output')

  // ---- up again: every service is reused, nothing restarted
  lines.length = 0
  assert.equal(await up(), 0, lines.join('\n'))
  for (const s of ['anvil', 'solana', 'bitcoind', 'miner', 'ord']) assert.ok(lines.some((l) => l.startsWith(s) && l.includes('reused')), `${s} reused: ${lines.join('\n')}`)

  // ---- a foreign listener on a port refuses before anything is touched
  const squat = createServer()
  const sp = await freeRun(1)
  await new Promise<void>((r) => squat.listen(sp, '127.0.0.1', r))
  t.after(() => { squat.close() })
  await assert.rejects(() => localnetUp({ btc: true, otterscan: false, reset: false, mineEvery: 2, env }, { ...rec, ports: { ...ports, anvil: sp } }), (e: unknown) => (e as { guardId?: string }).guardId === 'localnet.port-taken')
  squat.close()

  // ---- I1: a leftover ord of vt's own, whose bitcoind went away and came back as ANOTHER regtest chain, is restarted, not "reused"
  const ordHashBefore = await (async () => (await fetch(`http://127.0.0.1:${ports.ord}/r/blockhash/5`)).text())()
  tmux.run(['kill-window', '-t', `=${SESSION}:=miner`]); tmux.run(['kill-window', '-t', `=${SESSION}:=bitcoind`])
  for (let i = 0; i < 100 && (await tcpOpen(ports.bitcoind)); i++) await sleep(200)
  assert.equal(await tcpOpen(ports.bitcoind), false, 'bitcoind stopped')
  for (let i = 0; ; i++) {   // bitcoind closes its port before it has finished flushing: retry until its datadir is quiet
    try { rmSync(join(home, 'localnet', 'bitcoind', 'regtest'), { recursive: true, force: true }); break } catch (e) { if (i > 40) throw e; await sleep(500) }
  }   // a different regtest chain from block 1 on
  lines.length = 0
  assert.equal(await up(), 0, lines.join('\n'))
  assert.ok(lines.some((l) => l.startsWith('bitcoind') && l.includes('started')) && lines.some((l) => l.startsWith('ord') && l.includes('started')), `bitcoind and ord restarted: ${lines.join('\n')}`)
  assert.ok(lines.some((l) => l.startsWith('miner') && l.includes('started')))
  const sl2: string[] = []
  assert.equal(await localnetStatus({ json: true, env }, { ...deps, out: (l) => { sl2.push(l); all.push(l) } }), 0, 'status green on the new chain')
  void ordHashBefore

  // ---- M9: the password is in the credential file (and bitcoind's salted hash in bitcoin.conf) and NOWHERE else vt writes or shows
  const pass = (readCredentialLine(out) as string).slice(3)
  const files = [join(home, 'localnet', 'state.json'), join(home, 'localnet', 'solana', 'genesis-hash'), join(home, 'localnet', 'bitcoind', 'bitcoin.conf'), ...readdirSync(join(home, 'localnet', 'logs')).map((f) => join(home, 'localnet', 'logs', f))]
  for (const f of files) if (existsSync(f)) assert.ok(!readFileSync(f, 'latin1').includes(pass), `the password is not in ${f.slice(home.length)}`)
  const cookie = (readFileSync(join(home, 'localnet', 'bitcoind', 'regtest', '.cookie'), 'utf8')).trim()
  const cookieVal = cookie.slice(cookie.indexOf(':') + 1)
  const line = `vt:${pass}`
  // every form of every secret: the password, the credential line, their base64 (and the Basic header), the cookie value and line and their base64
  const needles = [pass, line, Buffer.from(line).toString('base64'), Buffer.from(pass).toString('base64'), `Basic ${Buffer.from(line).toString('base64')}`,
    cookieVal, cookie, Buffer.from(cookie).toString('base64'), Buffer.from(cookieVal).toString('base64'), `Basic ${Buffer.from(cookie).toString('base64')}`]
  const hits = (text: string): string[] => needles.filter((n) => text.includes(n)).map((n) => `${n.slice(0, 4)}…(${n.length})`)
  assert.deepEqual(hits(all.join('\n')), [], 'nothing vt printed (up, status, fund, down, errors) holds a secret')
  for (const f of readdirSync(join(home, 'localnet', 'logs'))) assert.deepEqual(hits(readFileSync(join(home, 'localnet', 'logs', f), 'latin1')), [], `log ${f}`)
  for (const w of listWindows(tmux, SESSION) ?? []) {
    const cap = tmux.run(['capture-pane', '-p', '-S', '-', '-t', `=${SESSION}:=${w}`])
    assert.deepEqual(hits(cap.out ?? ''), [], `no secret in the ${w} pane (scrollback)`)
    assert.ok((cap.out ?? '').includes('logs to'), `the ${w} pane says where its log is`)
  }

  // the validator restarts from its last ROOTED slot: wait until the airdrop is finalized before stopping it
  for (let i = 0; i < 180; i++) {
    const f = (await jsonRpc(ports.solana, 'getBalance', [solAddr, { commitment: 'finalized' }]) as { result?: { value: number } }).result?.value
    if (f === 1_500_000_000) break
    await sleep(500)
  }

  const h1b = await height()   // the chain as it is now (the stale-ord scenario replaced it)

  // ---- down: the session is gone, the ports are free, the data is kept
  const dl: string[] = []
  assert.equal(await localnetDown({ env }, { ...deps, out: (l) => { dl.push(l); all.push(l) } }), 0, dl.join('\n'))
  assert.ok(!hasSession(tmux, SESSION))
  for (const p of [ports.anvil, ports.solana, ports.bitcoind, ports.ord]) assert.equal(await tcpOpen(p), false, `port ${p} is free after down`)
  assert.ok(existsSync(join(home, 'localnet', 'solana', 'genesis-hash')))

  // ---- up again from the kept data: same password (a running relay needs no restart), funded balances persist
  lines.length = 0
  assert.equal(await up(), 0, lines.join('\n'))
  assert.equal(createHash('sha256').update(readFileSync(authFile)).digest('hex'), credHash, 'the credential file is unchanged across a restart')
  assert.equal(BigInt((await jsonRpc(ports.anvil, 'eth_getBalance', [ethAddr, 'latest']) as { result: string }).result), 5n * 10n ** 17n, 'anvil state persisted')
  assert.equal((await jsonRpc(ports.solana, 'getBalance', [solAddr, { commitment: 'confirmed' }]) as { result: { value: number } }).result.value, 1_500_000_000, 'the validator ledger persisted')
  const h2 = await height()
  assert.ok(h2 >= h1b, 'the regtest chain persisted')
  assert.equal(await localnetDown({ env }, { ...deps, out: () => {} }), 0)
})
