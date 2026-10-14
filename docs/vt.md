# `vt` operator guide

The operator runbook for `vt` (`vt help` is the command reference; `docs/E2E.md` is the local flow).
Sections: [start commands](#start-commands-per-network) · [the local environment: `vt localnet`](#the-local-environment-vt-localnet) · [pre-flight](#pre-flight-vt-preflight) ·
[first mainnet run](#first-mainnet-run) · [funding](#funding-testnet-and-local) · [backups](#backups) ·
[reassembling by hand](#reassembling-parts-by-hand) · [recovery](#recovery) · building a release · vt's tmux server ·
jobs (message file, run, clawback) · [the BTC lane](#the-btc-lane-local-only-for-now) ·
[Open (timelocked texts)](#open-timelocked-texts-open) · [`vt decrypt`](#decrypting-at-the-terminal-vt-decrypt) · [the funding tabs](#the-funding-tabs-railgun-and-privacy-cash) ·
[the mainnet Arm gate (R76)](#the-mainnet-arm-gate-r76) · [the M2 flip (applied)](#the-m2-flip-applied-r78).

**Agents and sessions: never run `op`, never read 1Password item data, never send on testnet or mainnet.** Every
step below that spends or needs an account is the operator's.

## Start commands, per network

One stack per network; each has its own page, relay and API ports and its own state under `$VT_HOME/<network>/`.

| Network | Start | Page | Needs |
|---|---|---|---|
| local | `bin/vt localnet up`, then `bin/vt up --network local [--open] [--dev]` | `http://127.0.0.1:5180/` | the local chains, started by `vt localnet up` ([below](#the-local-environment-vt-localnet); `docs/E2E.md` §0): anvil, a `solana-test-validator`, a regtest bitcoind (+ miner, wallet) and ord, Otterscan |
| testnet | `bin/vt up --network testnet` | `http://127.0.0.1:5190/` | **held (R77): not maintained.** The system Tor on `127.0.0.1:9050` (`vt.tor-required`); Sepolia + Solana devnet |
| mainnet | `bin/vt up --network mainnet` | `http://127.0.0.1:5200/` | Tor, and a **verified release** (`vt.mainnet-dev-tree`); job sends (ETH / SOL jobs and their claw-backs) are **enabled** in this build ([the M2 flip](#the-m2-flip-applied-r78), R78); funding and every other mainnet send stay locked (`MAINNET_SEND_ENABLED`) |

From a development tree `VT_HOME` and `VAULT_TIMELOCK_DIR` must both be set (agents: fresh temp dirs). **No sandboxed vt process has a terminal.** `vt status`, `preflight`, `job …` run under a sandbox that denies `/dev/tty` and every pty device (no TIOCSTI, no
termios, no escape sequences written to your terminal), runs node with `--no-addons`, maps no native code at all (`file-map-executable` is denied except the system
libraries and node), and can neither fork nor signal other processes. A small unsandboxed broker (`cli/src/ops/broker.ts`) owns the terminal and asks **only what the command's own
arguments allow**, mirroring what that command really needs: `vt job run` / `clawback` get one echo-off passphrase per `--backup-<chain>` file for a chain that will
run (`--chain` narrows it; a claw-back uses only its own chain), written by the broker itself as "passphrase of the key backup <file> (<chain>)" behind the tag
`[vt broker]` (in what the command prints, any bracketed look-alike of that tag, in any kind of bracket, has its brackets turned into parentheses). For these two
commands echo is off from the moment they start until the last passphrase is read; what was typed before the prompt appeared is thrown away, and the broker then
says "type it now". If the command ends while a prompt is open, what you type is discarded and sent nowhere until you press Enter (at most 2 minutes); only then
does the shell get the terminal back. Ctrl-Z is ignored while a command runs (vt says so; Ctrl-C still works). Typed words come from a fixed list per command (`publish`, `again`, `ticks`,
`broadcast`, `resume`, `resolve`, an amount, `claw back`; the mainnet-only ones only on mainnet) and the broker checks what you type against the expected word, asking again
up to three times: it never forwards free text. Every other command has no prompt channel at all. A request outside that set, a second one while a prompt is open or an
oversized one stops the command and restores the terminal. The broker reads `s` and Ctrl-C and forwards them to the command's process group (once the command has ended, Ctrl-C
ends vt), holds the command's output while a prompt is open, and filters it (no ESC / OSC / CSI / DCS / C1 controls, no bidi or invisible format characters; ASCII only in a
non-UTF-8 locale, decided like the C library: `LC_ALL`, then `LC_CTYPE`, then `LANG`); a redirect (`> receipt.json`) keeps working, and `vt status | head -1` ends quietly.
If vt itself is killed (`kill -9`), a running command notices that its broker is gone and **detaches** (signs nothing new, exits after its in-flight transaction); the terminal
can then stay in raw mode: run `stty sane`. The passphrase travels only over a pipe to the executor and is never printed.

`VT_HOME` and `VAULT_TIMELOCK_DIR` may be reached through the macOS links `/tmp`, `/var` and `/etc` but through no other symlink (the client and executor sandboxes name real paths; a path through another link fails closed). A release
tree may use the defaults (`~/.local/state/vt`, `~/.local/share/vault-timelock`). Then:

```
bin/vt status [--network N] [--json]       # is it up, and healthy (booleans, ids, locks only)
bin/vt preflight --network N [--json]      # the readiness table (below)
bin/vt logs relay|api|page [--network N] [-n 50] [-f]
bin/vt down --network N
```

## The local environment: `vt localnet`

R77: only the local network and mainnet are maintained, and the local network must work from a purely local environment
setup. One command brings up every endpoint the local profile uses, so a fresh operator runs, in order:

```
bin/vt localnet up                 # anvil, solana-test-validator, bitcoind regtest + miner, ord 0.29.0, Otterscan
bin/vt up --network local --open   # relay, API, page
bin/vt preflight --network local   # exit 0
bin/vt localnet fund eth <address> [amount]   # 1 ETH by default, from anvil dev account 0
bin/vt localnet fund sol <address> [amount]   # 2 SOL by default (airdrop)
bin/vt localnet fund btc <address> [amount]   # 0.01 BTC by default (regtest address only), then mines 1 block
bin/vt localnet status [--json]    # per service: endpoint, identity, version, who started it
bin/vt localnet down               # stops exactly the tmux session vt-localnet; data is kept
```

`vt localnet up [--no-btc] [--no-otterscan] [--reset] [--mine-every <seconds>]` (orchestration, unsandboxed like `vt up`;
local only: any other `--network` is refused, `localnet.network`). It needs `anvil` (Foundry), `solana-test-validator`
(Agave), and for BTC `bitcoind` (Bitcoin Core) and **`ord` 0.29.0** exactly (`localnet.ord-version`); a missing tool is
refused with its install hint (`localnet.tool-missing`). Docker is optional: without a running daemon Otterscan is skipped
with a note.

| Window | Endpoint | Notes |
|---|---|---|
| `anvil` | `127.0.0.1:8545` | `--chain-id 31337 --block-time 1`, state kept in `$VT_HOME/localnet/anvil/state.json` |
| `solana` | `127.0.0.1:8999` | `--limit-ledger-size 50000000`, ledger kept; its faucet, gossip and dynamic ports are chosen so that `:8899`/`:8900` (the validator's defaults, left to any other local validator) are never touched |
| `bitcoind` | `127.0.0.1:18443` | regtest, wallet `vt` (user `vt`), 101 blocks mined to it on a fresh chain |
| `miner` | none | one regtest block every 5 s (`--mine-every`): nothing else in vt mines, and a commit/reveal needs a confirmation |
| `ord` | `127.0.0.1:8090` | ord 0.29.0 on that regtest |
| `otterscan` | `127.0.0.1:5100` | `otterscan/otterscan:v2.11.0`, bound to 127.0.0.1 only, pointed at anvil |

- **Where.** One tmux session `vt-localnet` on vt's own server (`tmux -L vt attach -t vt-localnet`), one window per service. A pane
  shows only one line naming its log (the output goes to `$VT_HOME/localnet/logs/<service>.log`: `tail -f` it). Data lives in `$VT_HOME/localnet/<service>/` and survives `down` and a restart;
  `vt localnet up --reset` wipes exactly those four data directories first (never anything else; a link there refuses,
  `localnet.reset-path`) and needs the localnet stopped. The Solana validator restarts from its last *rooted* slot, so a
  transaction from the last few seconds before `down` may not survive a restart.
- **Reuse and refusal (fail closed).** Before anything starts, every port is probed. A port that answers with the right
  identity (anvil chain id 31337; the validator's genesis hash that `vt localnet up` recorded; a regtest bitcoind that accepts
  the cookie of vt's own datadir *and* the credential file (vt's own calls use the cookie; the file's password goes only to a
  listener the cookie identified); an ord whose indexed chain is the chain of *this* bitcoind (regtest's genesis is shared by
  every regtest, so it proves nothing; ord 0.29.0 reports no version, so none is shown); Otterscan bound to 127.0.0.1 only)
  is **reused** and the line says so. A port taken by anything
  else refuses naming the port (`localnet.port-taken`) and nothing is started or killed: vt never stops a process it did not
  start. A leftover ord of vt's own whose bitcoind came back as another chain is restarted with a fresh index. A reused
  bitcoind gets its wallet `vt` checked, and a dead miner is restarted. Otterscan is optional: if it fails to start it is a
  warning and the rest stays up. `:8899` and `:8900` are never used (`localnet.port-forbidden`).
- **The bitcoind credential.** `vt localnet up` writes `$VAULT_TIMELOCK_DIR/local/btc-rpc.auth` (`vt:<password>`, mode 0600,
  written atomically): the relay reads the credential only there. The 32-character password is on no command line and in no
  log; bitcoind gets only its salted `rpcauth` hash, in `$VT_HOME/localnet/bitcoind/bitcoin.conf` (0600), and ord and the
  miner use the datadir cookie / that 0600 file. The password is kept across restarts, so a running relay needs no restart;
  start the relay (`vt up --network local`) after the first `vt localnet up` so it sees the file.
- **Funding.** `vt localnet fund` refuses unless the node on that port is a local chain (anvil 31337, a Solana ledger that is
  none of the public networks and is the recorded one, a regtest bitcoind): `localnet.fund-network`; and a malformed or
  wrong-network address (a BTC address must be regtest `bcrt1…`): `localnet.fund-address`. It prints the transaction id.
- **Keep the macOS firewall on.** `solana-test-validator` binds its RPC, websocket and faucet to *all* interfaces whatever
  `--bind-address` says (measured with Agave 4.2.2); vt runs it under an outbound-loopback-only profile, but nothing stops a
  LAN peer from reaching its faucet. The exposure is a worthless local ledger, never a key or a real coin.
- **Stopping.** `vt localnet down` kills exactly the session `vt-localnet` (each service gets its stop signal, ord before its
  bitcoind) and removes the Otterscan container vt started, by its recorded name; data stays. If a port still answers
  afterwards it says so and exits 1; it never kills by port.

`vt localnet status` identifies solana, bitcoind and ord with files that live under the `VT_HOME` that started the localnet (the genesis record, the
credential file). Run from another `VT_HOME` it says `started under another VT_HOME — run status with that VT_HOME` for a vt-started service it has no proof for
(not `IDENTITY WRONG`, which stays for a listener that really is something else, or one nobody started through vt).

## Pre-flight: `vt preflight`

`vt preflight --network <n> [--json]` is the terminal twin of the page's **Status** screen: **the same rows, the same
verdicts, the same exit rule** (both come from core: `executor/readiness.ts` for the page/API/relay rows,
`executor/preflight.ts` for the chain rows). It only reads: the relay's status, Tor flag, fee history and a fork probe;
the page server's `/__serve`; the relay's `/relay/release`; the API's `/status`. It sends nothing and reads no key.

```
vt preflight — network testnet
  ✓  API answers — build 3f9a1c0d22b4
  ✓  Page, API and relay serve the same network — all testnet
  ✓  Build id equal across page, API and relay — api 3f9a1c0d22b4 · relay 3f9a1c0d22b4 · server 3f9a1c0d22b4
  ✓  Ethereum fork matches this network — no fork drift reported by the relay
  —  Release verified — digest 6c1e…  (or: dev tree (needed only on mainnet))
  ✓  Relay answers · ✓ Relay serves testnet · ✓ Relay confinement · ✓ Tor — IsTor ✓
  ✓  ETH chain identity · ✓ ETH verified endpoints · ✓ ETH fees now · ✓ ETH fork gas probe (a send to another address)
  ✓  SOL chain identity · ✓ SOL verified endpoints · ✓ Memo v2 program deployed and executable · ✓ SOL fees now
regime: TESTNET: …
mainnet sends: locked  ·  mainnet job sends: enabled
page and relay digests: equal (6c1e…)
every check passed · exit 0
```

- **Marks.** `✓` passed, `✗` failed, `—` informational (not applicable here).
- **Exit 0 only when** core's `preflight()` passed (identity and deployments: the relay answers and is confined, serves
  this network, reaches both chains, Tor is on off local, Memo v2 is executable, every read worked) **and** no row
  anywhere is `✗`. Anything else is exit 1, and a stack that is not up is exit 1 with the start command.
- **Dev tree.** The page bundle, the API and the relay carry different build ids by design in a development tree, so
  the *Build id equal across page, API and relay* row shows `—  dev tree (needed only on mainnet/verified release)`,
  like *Release verified*. On a release it is a hard check: any difference is `✗`, exit 1.
- **Verified endpoints (pre-flip review M-2).** On **mainnet** each job chain (ETH, SOL) needs **at least 2** endpoints
  that passed the relay's identity check: one is a `✗` row (exit 1), because the ETH nonce agreement and the SOL expiry
  proof would rest on one provider's word. `vt job run` and the page's Run here refuse to start such a chain
  (`executor.endpoints-quorum`; a claw-back is not refused). An endpoint that timed out at `vt up` (a slow Tor circuit) is
  checked again by the relay every 30 s and joins when it answers, so wait a minute and run `vt preflight` again before
  restarting. Local and testnet need one.
- **Fork probe.** The ETH fork row estimates a 100-byte send **from a synthetic address to the null address** (never a
  self-send, which Amsterdam prices differently and would under-estimate). testnet must read Amsterdam gas
  (15,000 + 64·n), mainnet pre-Amsterdam (21,000 + 40·n) until a reviewed contract change flips it; local accepts
  either fork. A drift names the cause ("Amsterdam appears active on mainnet — update required").
- **Below the table:** the regime line, the mainnet send and job-send locks, and whether the page server's and the
  relay's release digests are equal (`n/a` on a dev tree).
- **`--json`** prints the report (`format: vt-preflight/1`, `rows`, `exit`, `failing`, `regime`, `mainnetSends`,
  `jobSends`, `digests`). No IP, endpoint, token or control sequence is ever printed (a line that fails the checks is
  withheld).

## First mainnet run

**Agents send nothing on mainnet.** This is the operator's checklist. It is the page's five ticks (Status screen; Arm
on mainnet stays disabled until all are set) plus the steps around them.

Before starting:

1. **A verified release, not the dev tree.** On a clean tree: reinstall from the lockfiles, `bin/vt release build`,
   `bin/vt release verify <buildId>` (0 mismatches; "Building a release" below). Note the build id and the `SHA256SUMS`
   digest. Run `vt` from the release path.
2. Tor is running (`curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip` says `IsTor`).
3. `bin/vt up --network mainnet`. The page opens with the red MAINNET banner. A custom `VT_HOME` must exist with mode 0700
   before the first command (`mkdir -m 700 "$VT_HOME"`): vt refuses a group- or world-accessible one.
4. `bin/vt preflight --network mainnet` exits **0**, with *Release verified* `✓` and the page and relay digests equal.
   Read every row yourself.
5. `bin/vt status --network mainnet`: healthy, `isTor yes`, `mainnet sends: locked` and `mainnet job sends: enabled` (this
   build lifted the job-send lock: [the M2 flip](#the-m2-flip-applied-r78), R78). A release that shows
   `mainnet job sends: locked` is older than the flip: stop and rebuild from the flip commit or later.

**Run vt on a single-user Mac** (pre-flip review N-4). The page server listens on loopback only and adds this stack's
API token to the page's requests. It refuses a request other than GET without the page's own Origin, which stops
browsers and careless scripts, but any local process can send that header. On a machine with another user account (or
software you do not trust running as another user), that process could arm, skip, stop or resume your jobs through the
page server. A per-launch page capability that other users cannot read is planned after the handover; until then, run
mainnet jobs on a Mac that only you use.

The five ticks (each on the Status screen; kept in that tab only):

- [ ] **Backups.** Every lane key's backup is saved, re-selected and verified, and kept **off this machine**.
- [ ] **Funds.** I fund only what I am willing to spend; the per-job cap is shown again at Arm.
- [ ] **Permanence.** The text is public at once, permanently, and cannot be taken back.
- [ ] **Release.** I ran `vt release verify` on this release and the digests match.
- [ ] **Pre-flight.** I read the pre-flight table; every row is `✓`, or I understand why not.

Then:

6. Create the job (`vt job create`, or the page). With `--message-file`, you confirm the file's sha256 and type
   `publish`. On mainnet every ETH and SOL lane **must name its claw-back address** (`chains.<chain>.clawbackTo`; the
   page's field says "required on mainnet"): an address of your own wallet, checked now. The API refuses a mainnet
   claw-back to any other address, whoever asks (`job.clawback`), and a mainnet job without one is refused at creation
   (`job.clawback-required`).
7. Fund each lane key with a small amount first (a real payment of your own, from your own wallet; agents never fund).
   **Tip:** fund close to the job's cap. A claw-back that empties a lane holding more than what is left of the cap asks for
   the exact amount typed (see `vt job clawback`); a lane funded near the cap stays under it and skips that prompt.
8. Arm: the page asks for typed `broadcast` (and the amount again if it is over the cap, and `again` if the key has
   history). **`bin/vt job arm` asks the same, at the terminal**: it refuses unless the relay reports `IsTor`
   (`arm.tor`); shows the five ticks above and asks you to type `ticks` (`arm.ticks`); then `broadcast`, each over-cap
   amount, and `again` for every chain whose key already sent transactions (ETH nonce above 0, SOL signed memos; it
   prints `KEY HISTORY` first; `arm.again`). A history it cannot read refuses. Countdown, then Run here, or `vt job run <id> --backup-eth … --backup-sol …` in a terminal.
   **For a first CLI run pass `--stagger 0,10`**: the default stagger spreads the chains' starts over up to about 5 minutes
   (one chain can start minutes after the other), which looks like a hang.
9. Watch `vt job status <id> --watch`. Check each part's readback and "reassembled ✓" per copy.
10. Afterwards: claw back what is left (`vt job clawback`; it links the lane key to the destination publicly and for
    good) **or** close the job (`vt job close`), not both: a claw-back ends in CLAWED_BACK, which is terminal (a later
    `vt job close` is refused, `job.state`), and it frees the key; closing a DRAINED, COPIES_DONE or STOPPED job frees it
    too, keep the receipt (`vt job receipt <id> --json > receipt.json`), `bin/vt down --network mainnet`.

## Funding (testnet and local)

Local: `vt localnet fund` (below). **Testnet is held (R77): not maintained**; its notes are kept as they were.

Faucets that need a login, a captcha or an account are **the operator's step**; agents never automate or bypass them.

- **Sepolia ETH (testnet; held (R77): not maintained).** On the job form, the ETH lane shows its address with a copy button and the note
  "operator faucet step". Paste that address into a Sepolia faucet of your choice and request a small amount (0.05
  Sepolia ETH is plenty for a short text). Wait for the balance on the lane (the page polls), or check it:
  `cast balance <address> --rpc-url $SEPOLIA_RPC_URL` over Tor.
- **Solana devnet airdrop (testnet; held (R77): not maintained).** The SOL lane has **Request devnet airdrop**: it calls `requestAirdrop` through the
  testnet relay (the only network besides local where the relay forwards it; mainnet refuses it,
  `relay.airdrop-network`). If the public faucet throttles or refuses, the page shows the faucet link and "operator
  step"; request SOL there instead.
- **Local.** `bin/vt localnet fund eth <lane address>` (1 ETH from anvil's dev account 0, a well-known development key worthless
  outside your own anvil), `bin/vt localnet fund sol <lane address>` (an airdrop of 2 SOL on the local validator,
  `127.0.0.1:8999`) and `bin/vt localnet fund btc <lane address>` (0.01 BTC from the regtest wallet, then 1 block). Amounts
  are optional last arguments; each prints the transaction id.

### Funding sources (`vt source`)

A funding source is only a **label** you pick for each try (for example `pool-a`); it holds no secret. `vt source list
[--json]` shows them, `vt source add <label>` declares one (1 to 24 lowercase letters, digits and hyphens, starting with a
letter or digit; a refused label comes back with the API's `source.label` guard). No typed confirmation is needed. They
are the CLI twin of the job page's picker. **Sources are never deleted.** Once one exists, every `vt job arm` needs
`--source <chain>=<label>` for each armed chain (for example `--source eth=pool-a,sol=pool-b`), and a source that already
paid an earlier try of the same message is refused (`source.reused`).

## Backups

A lane key lives in the page's tab until you save its backup: **download** `vt-<chain>-key-<UTC>.age` (age-encrypted
under your passphrase), **re-select** the saved file and type the passphrase (`verifySavedFile` ✓), then tick. A backup
records its network, and the page warns when you load one made for another.

```
bin/vt backup import ~/Downloads/vt-eth-key-20261010T101500Z.age [--chain eth|sol|btc]
```

`vt backup import` moves the file into `$VT_HOME/backups/<chain>/` (0600, a durable copy first, then the original is
removed) and never decrypts it. `vt job run` and `vt job clawback` then read it with `--backup-eth` / `--backup-sol`.
**Keep another copy off this machine** (the mainnet tick), and remember the passphrase: without both, the lane's funds
cannot be moved.

## Reassembling parts by hand

A message longer than one transaction goes out as `vt-parts/1` parts: each part's text starts with a header line
`[k/N <h8>]`, where `<h8>` is the first 8 lowercase hex characters of the sha256 of the full text (part 1 is
`[1/N <h8> sha256=<64 hex>]`; the header holds no `#`); the reader accepts parts only from the publishing address,
strips exactly the header line, joins the chunks by index and checks the sha256. You do not need vt for this: any node
and `python3` do it.

The job page (**after a run**, "Reassemble by hand") prints, for each chain, the landed ids of the best copy, a file
to save them in, and one **self-contained command** with your job's digest and publishing address filled in. Its shape:

```
# Ethereum (needs cast from Foundry and python3; $ETH_RPC_URL is a Sepolia/mainnet node, mainnet over Tor)
while read -r t; do cast tx "$t" --json; done < eth-txids.txt \
  | python3 -I -c '<the page's reader script>' <message-sha256> <publishing-address>

# Solana (needs curl and python3; $SOL_RPC_URL is a devnet/mainnet node, mainnet over Tor)
while read -r s; do curl -s -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getTransaction\",\"params\":[\"$s\",{\"encoding\":\"json\",\"maxSupportedTransactionVersion\":0}]}" \
  "$SOL_RPC_URL"; echo; done < sol-signatures.txt \
  | python3 -I -c '<the page's reader script>' <message-sha256> <publishing-address>
```

It prints the text on stdout and `reassembled OK sha256 …` on stderr, or exits with what is wrong (a part not sent by
the publishing address, a missing part, a sha256 mismatch). A one-part message is plain text: its sha256 must equal the
job's `messageSha256`. The reader holds no URL, endpoint or key; it reads the raw calldata (ETH) or Memo data (SOL),
never an indexer's decoded text.

## Recovery

**An executor died, or the terminal closed.** One chain has one executor at a time (its lease, 15 s). After the lease
lapses, run the job again from anywhere (the page's *Run here*, or `vt job run <id> --backup-… `): it takes over and
**reconciles every open transaction from the chain before signing anything new**, so nothing is sent twice. The job
page and `vt job status <id>` show who holds each chain's lease. `lease.held` means the holder is still alive.

**A transaction is stuck or its outcome is unknown (STUCK).** Look at it on the chain (the job page links it; copy the id,
never click through on mainnet). Then record the truth with `vt job resolve`:

```
bin/vt job resolve <id> --chain eth --tx 0x… mark-done      # you saw it land on the chain
bin/vt job resolve <id> --chain eth --tx 0x… mark-failed    # it never will (frees no cap)
```

On mainnet it asks for the typed word `resolve` (`job.resolve-typed`). Marking a transaction done that did not land
loses a part; marking one failed that later lands sends it twice. On ETH, a transaction marked failed keeps its nonce:
no job transaction uses that nonce again, and `vt job clawback` signs the claw-back at it. Only one transaction can land
at one nonce. The cap still counts both, as the engine does, until the chain shows the nonce used. Once every open
transaction of a stopped chain is resolved (marked failed, or landed), `vt job close` is accepted too: the close takes your
word, the cap keeps counting what you marked failed. When unsure, wait for the chain (the chain's own rules settle it: a SOL blockhash expires, an ETH nonce is consumed), then resolve.

**Before `mark-failed` and then close on ETH or SOL, check the transaction on every explorer and endpoint you can reach.**
Close takes the operator's word: once the chain is closed, its key is free for another job. If the transaction marked
failed still lands later, it uses a nonce on that freed key, and that job's transaction at the same nonce can never land.
Look the transaction up by its id at every endpoint: it must be neither pending nor mined anywhere. For ETH, a
transaction that is unknown everywhere can still be rebroadcast by someone holding its bytes until its nonce is used. For
SOL, it is final only once its blockhash has expired at every endpoint.

**An ETH transaction taken over at an unused nonce, then dropped (passive lanes).** When a run takes over (a page
reload, a tab hidden long enough for its lease to lapse, a laptop that slept, a killed `vt job run`), an open ETH
transaction whose nonce is still unused is *adopted* (`reconcile adopted`). The new executor rebuilds its signed bytes from
the journaled intent and the planned part (signatures are deterministic) and uses them only when they are byte for byte the
journaled transaction (its tx id and raw-tx digest). A passive lane (the drain default) then sends those same bytes again
whenever the nodes do not have them; it never signs a different transaction at that nonce. (Economy and prompt lanes replace
it with a same-nonce fee bump, as before.) The chain becomes STUCK, with nothing else signed at that nonce, when:

- the bytes cannot be rebuilt: the reason says *cannot be rebroadcast:* or *cannot be sent again*, and why (another payload
  or recipient, a digest that does not match). This happens at once;
- the verified endpoints do not all know the transaction for 3 windows of 25 blocks in a row (about 15 minutes on mainnet)
  while its nonce stays unused: *not known to every verified endpoint (…) after 3 windows*. One endpoint's word is not
  enough: on mainnet at least two must agree that they hold it. This applies to every passive ETH transaction, adopted or
  not, and to an economy one that waits because a fee bump would not fit the balance;
- you stop the chain (`vt job stop`, the page's Stop) while the endpoints do not all know it (below). A Ctrl-C only
  detaches and escalates nothing, not even for bytes whose send ticket does not bind them: the next run decides.

Look the transaction up, then resolve it as above: `mark-failed` if it never landed, `mark-done` if it did. The chain is then
STOPPED with nothing in flight. `vt job clawback` can move the remainder: it signs at the same nonce, once no node holds the
dropped transaction. `vt job close` can end the chain instead.

Running the job again instead of resolving re-reads the chain. On a chain that is already stopped, the run only watches that
transaction. It sends the same signed bytes again for at most 3 windows, and nothing new is signed. It ends in one of three
ways:
- the transaction lands, and the chain is settled;
- STUCK again, with the reason; this happens at once if the bytes cannot be rebuilt;
- it is still pending at every verified endpoint: run it again later.

On mainnet this watch-only rerun also needs 2 verified endpoints for the chain, like every run. The quorum check
(`executor.endpoints-quorum`, see `vt preflight`) runs first, before the watch. With only one verified endpoint the rerun is
refused before it takes the chain: nothing is watched and nothing is journaled. Wait for the relay's re-check, or fix the
endpoints, then run it again. The check does not apply to `vt job resolve` on a chain that is already STUCK, or to a
claw-back: a claw-back is allowed on one endpoint once nothing is in flight.

Ctrl-C ends that watch at the end of its window and journals nothing (no `stuck`): the transaction stays open for the next
run. A SOL transaction adopted at a takeover is never sent again. It is watched
until it lands or until its blockhash expiry is proven on every endpoint (a minute or two), then its part is signed afresh.

**Stop, detach and resume.** Three different things:

- **Stop:** `vt job stop <id> [--chain c]`, or the page's job **Stop**, stops the job. Whichever executor holds the chain
  stops after its in-flight transaction (below) and journals `stopped`. The chain is then STOPPED and *latched* (below).
  The run's own stops are journaled the same way, for example a spend cap reached, a readback that does not match, or an
  EIP-7702 delegation. Every journaled stop carries a reason code, and the code says whether the stop is *resumable* or
  *final* (below).
- **Detach:** Ctrl-C in `vt job run`, the page's **Stop running here**, or closing the tab ends only that executor. It
  also lets its in-flight transaction resolve first and signs nothing new. Then it exits and journals nothing final: no
  `stopped`, no `stuck`, and the chain stays as it was. That holds in that process for good: if someone resumes the job
  at the API meanwhile, the process that was detached still signs nothing more. On the page it also holds against that
  tab's own **Resume** or **Cancel the stop**: they are journaled at the API, but the detached executor stays detached.
  The next `vt job run` (or Run here) takes the chain over, reconciles every open transaction from the chain and continues
  the job.
- **Resume:** `vt job resume <id> [--chain c]` (the page's **Resume**) lifts a *resumable* stop. On mainnet it asks for
  the typed word `resume`, in the CLI and on the page (the API does not check the word, like `again`; see the single-user
  Mac note above). The page asks it for every mainnet resume: the Resume of a stopped chain, the Resume of a paused one,
  and **Cancel the stop**. Without `--chain` it resumes only the chains whose stop is
  resumable, and lists the others; it never lifts a final stop. `vt job resume` prints `resumed: …` and, for each chain
  it left alone, `NOT resumed: <chain> — resume.final-stop: <the reason and the way out>`. On a chain whose stop is final
  it is refused (`resume.final-stop`, 409), and the message names the reason and the way out; so is a resume of every
  chain when every one is final. The page shows a final stop's reason and code instead of its Resume button. A page
  Stop the API refuses is shown (`stop: <guard> — <message>`), and that tab's executor is not stopped locally.

  After a resume, the next `vt job run` (or the page's *Run here*) reopens the chain and continues at the next part of the
  current copy, with the same header, the same digest and every cap rule. It journals `resumed`, but only once every
  pre-start check has passed: the reconcile, the re-read of any landed part, and the check at the start (Tor, the relay
  identity, a fresh simulation). If a check fails, it journals nothing and the chain stays STOPPED; so does a Ctrl-C (or
  *Stop running here*) during the checks. Fix the cause, then run it again; the resume still stands. One check is a
  verdict, not a failure to retry: when the re-read of a landed part gets a definitive answer from the chain (other bytes,
  or status 0), the run journals that evidence (`readback` not ok) and a final stop (`readback-mismatch` or `reverted`).
  The run says so ("resumed, but … the chain stays stopped … and the resume still stands"), and so do `vt job status`
  ("resumed, but still STOPPED: the next vt job run (or Run here) reopens it …") and the page ("Resumed, but still
  STOPPED"). If you stop the chain again before a run reopens it, nothing reopens it until you resume it again
  (`vt job resume`, or the page's **Cancel the stop**): a run that is still in its checks journals your Stop
  (`operator-stop`, latched again), a run started later ends at once, and the API refuses a reopen (`job.state`).

**Resumable and final stops.** The reason code of a journaled stop (`stopCode` in `GET /jobs`, with `stopClass`: `resumable`
or `final`) decides what a resume may do. Resumable means you can fix the cause and continue. Final means nothing more can be
sent for this job on this key.

| Code | Class | The stop |
|------|-------|----------|
| `operator-stop` | resumable | `vt job stop` / the page's job Stop: in the countdown, between parts or copies, while paused (Tor, an RPC error, the fee cap), during the reconcile |
| `start-check` | resumable | the check at the chain's start failed (Tor, the relay identity, the simulation) |
| `rpc-unavailable` | resumable | the endpoints could not be read while the next copy was planned; nothing of it was signed |
| `readback-mismatch` | final | a landed part does not read back from the chain as planned |
| `reverted` | final | a landed part failed on the chain (ETH status 0, a SOL transaction that landed with an error) |
| `reassembly-mismatch` | final | a copy did not reassemble from the chain |
| `eip7702` | final | the lane key's account has an EIP-7702 delegation |
| `spend-cap` | final | the armed spend cap cannot cover the next copy (a resume cannot add cap) |
| `stuck` | final | a transaction was journaled stuck (`vt job resolve` records what the chain shows) |
| `tx-failed` | final | a part's transaction failed otherwise (its nonce used by a transaction vt did not sign, a SOL program error, a BTC commit that cannot pay its reveal) |
| `exhausted` | final | a part ran out of fee bumps, balance or per-transaction cap while its transactions may still land |
| `integrity` | final | any other integrity failure |

A stop is also final, whatever its code, when the chain's journal shows any of these:
- a landed part whose readback is not ok: other bytes, or a part that failed on the chain (vt journals ETH status 0 and a
  SOL transaction that landed with an error as readback not ok);
- a copy that did not reassemble;
- a delegated key;
- a stuck transaction (resolving it later does not make the stop resumable: see below);
- a transaction you resolved `mark-failed`, because its nonce cannot be used for the job again.

`spend-cap`, `tx-failed`, `exhausted` and `integrity` have no journal fact of their own: their class rests on the code the
engine journals (its mapping is pinned by tests).

The API's resume and its reopen check decide from the whole journal, and may only be stricter than the class above:
- a readback or a reassembly that ever failed keeps the stop final, even if a later line reports it ok;
- an `operator-stop` that an executor journaled while no stop request was held is final. Your Stop always journals its
  request first. An executor of this build re-reads the request just before it journals your Stop: if your resume (or the
  page's *Cancel the stop*) lifted it in between, it journals nothing and the chain goes on — in the countdown, between
  parts, while paused, or with a transaction still open at the end of its window (that transaction goes on with its fee
  strategy's next step, as if no Stop had been asked). Only a resume that lands after that re-read, in the instant
  before the `stopped` line, still makes that stop final (fail closed).

The API serves that verdict: `stopClass` in `GET /jobs/<id>` (and so in `vt job status`, `vt job run`, the receipt and the
trace) is the class the resume decides with, and `stopCode` stays as journaled. In these two cases `vt job status` says
*stopped for good* with the code's own reason; the resume's refusal (`resume.final-stop`, 409) names the real one. The job
list (`GET /jobs`) carries no stop class. The page folds the journal itself and can still show the class above; when the
API refuses its Resume or **Cancel the stop** (`resume.final-stop`), it shows the final-stop panel with the API's reason in
place of both buttons.

Once the API's verdict on a stopped chain is final, it stays final for as long as the chain stays stopped; only a
landed claw-back or a close ends that stretch. No later line lowers it: a later `stopped` with a resumable code is refused
(`job.state`), and resolving the stuck transaction that made it final (`mark-done`) does not make it resumable again.

A stop journaled without a code (a journal from before this build), or with a code this build does not know, is final.
Fail closed. The way out of a final stop is to claw back what is left (`vt job clawback`, the page's claw-back) or to close
the chain (`vt job close`), then make a new job. Nothing reopens a final stop, even if something cleared its latch (a
journal from before this build): `vt job run` says *nothing to run*, the page offers no Run here, an executor that is
started anyway ends at once and says *stopped for good*, and the API refuses an executor's `resumed`, `paused`, `drained`,
`copies-done` and `copy-built` on it (`job.state`), latched or not. A final fact that appears after a resume (a
takeover's `stuck`, then `mark-failed`) makes the resumed chain final the same way; a claw-back and close stay open.
`vt job status` shows each stopped chain's code and class
(`stop operator-stop (resumable): vt job resume … lifts it`, or *stopped for good* with the reason and the way out).

`vt job close <id> --chain c` ends a chain.

The job's own phase (`vt job status`, `vt job list`, the page) is DONE only when every chain is terminal: closed, clawed
back or skipped, with nothing in flight (its key is then free). A stopped chain, resumable or final, keeps the job ARMED,
as a drained or copies-done chain does, before and after a resume; a running, paused, stuck or clawing-back chain makes it
RUNNING. `vt job status --watch` ends at DONE.

A Stop that the API journaled during the countdown (a chain that never started) ends the run `stopped`, not failed.

After a Stop or a detach, that executor signs nothing new on the chain, whatever the fee strategy: no next part, no next
copy, no fee bump, no replacement, no SOL re-sign. After a Stop, the API also refuses every new send intent while the stop is
requested or latched (`intent.after-stop`). The one exception is the reveal of a BTC copy whose commit is out (see the BTC
lane). A claw-back is still allowed once the chain is settled.

An ETH transaction in flight keeps its signed bytes, and vt may send those same bytes again (the API re-tickets them),
until the end of its current window: 3 blocks for economy and prompt, 25 blocks (about 5 minutes on mainnet) for passive.
What happens then depends on which of the two it was.

After a Stop:
- If the transaction landed, the chain is STOPPED cleanly.
- If it is still pending at the nodes, or the nodes cannot be read, the chain is STOPPED with that transaction open. It may
  still land, and a claw-back waits for it. Run `vt job run` again: it only watches that transaction (see above), and it
  ends landed, STUCK, or still pending.
- If the endpoints do not all know it, the chain is STUCK: resolve it as above.
- If the API refused a fee bump because the Stop reached it first, the run ends without journaling `stopped`, since the
  transaction is still open. Run `vt job run` again: it takes the Stop path above.

After a detach, nothing is journaled whatever the transaction's state. The next run adopts it as at any takeover.

A SOL signature in flight is watched until it lands or its expiry is proven, and is never re-signed. If, after a Stop, the
expiry cannot be proven on every verified endpoint within 5 minutes (for example, one endpoint keeps failing), the chain is
STUCK with the reason. A detach ends after the same 5 minutes and journals nothing. A Stop before a BTC copy's commit is
signed, even one that arrives while the copy is being planned, signs no commit.

**The stop latch.** A journaled stop holds until you resume. This covers `vt job stop`, the page's Stop, and a stop the run
makes itself. A Ctrl-C or a closed tab journals nothing, so it never latches. Once a chain is STOPPED it stays stopped,
through STUCK and through every later executor event:
- The API refuses a new send intent (`intent.after-stop`) and an executor's `paused` or `resumed` (`job.state`). A new
  `vt job run` on it ends at once with nothing to run, unless a transaction is still open; then it only watches it.
- It still takes what recovery needs: reconcile, sent, included, readback and stuck for transactions already journaled,
  `vt job resolve`, a claw-back and close.
- Only your `vt job resume` (the API's resume route) lifts it, and only for a resumable stop (above). An executor cannot.
  After the resume, the next run journals `resumed` once its pre-start checks pass. The API now takes it, and the chain
  runs again.

Every other settled chain holds for good. A DRAINED or COPIES_DONE chain is never moved again by an executor, STUCK or not,
and a resume does not reopen it. Neither is a CLAWED_BACK, DONE or SKIPPED one moved. `paused`, `resumed`, `drained`,
`copies-done`, `stopped` and `copy-built` are refused, and so is a new send intent. A drained lane that is topped up later
is not resumed: claw back, or make a new job.

**Take the funds back.** On a settled chain (drained, copies done or stopped): `vt job clawback` (below) sends what is
left to the job's `clawbackTo` (on mainnet always, and only there), or, off mainnet on a job that names none, to an address
you name.

**A stack misbehaves.** `vt status`, `vt logs relay|api|page -n 100`, then `vt down --network N` and `vt up --network N`;
jobs and journals live in `$VT_HOME/<network>/` and survive a restart. Only vt's own tmux server is touched.

## Building a release

A release is built from the commit at HEAD (spec §9). `vt release build` checks that the installed `node_modules`
match the commit's lockfiles (`release.lock-drift`), but it cannot check the files inside an installed package
offline. A file edited or added inside an installed package would therefore be released as installed.

So reinstall from the lockfiles **immediately before** every `vt release build`, from the repository root, on a clean
tree:

```
npx npm@11.21.0 ci --ignore-scripts
(cd broadcast && npx npm@11.21.0 ci --ignore-scripts)
bin/vt release build
bin/vt release verify <buildId>
```

- Use the pinned npm (11.21.0). An older system npm can fail partway and leave `node_modules` broken.
- `SHA256SUMS` then pins exactly what was copied. Two builds from the same install give identical sums.

## Runbook: vt's tmux server

`vt up` runs each network's relay, API and page (and Vite with `--dev`) as windows of the tmux session `vt-<network>`
on vt's **own** tmux server: `tmux -L vt`. Attach with `tmux -L vt attach -t vt-<network>`. vt never talks to your
default tmux server.

vt's server **never loads a tmux configuration**: every vt tmux call is `tmux -L vt -f /dev/null …`, so the server
`vt up` starts reads neither `/etc/tmux.conf` nor `~/.tmux.conf` nor `~/.config/tmux/tmux.conf`. Your hooks, plugins
and options (tmux-resurrect, tmux-continuum, a `session-created` hook) never run there: a resurrect save from inside
vt's server would overwrite the save your post-reboot recovery relies on. A vt server holds no window but relay, api,
page (and vite) for each `vt-<network>` session, and the `vt-localnet` session's anvil, solana, bitcoind, miner, ord and otterscan windows.

**Once, after upgrading from a vt that did not pass `-f /dev/null`:** a vt server started by the old code keeps the
configuration it loaded until it ends. Stop every vt stack, then end that server, then start again:

```
bin/vt localnet down; bin/vt down --network local; bin/vt down --network testnet; bin/vt down --network mainnet
tmux -L vt kill-server        # only vt's own server (-L vt); your default server is untouched
bin/vt up --network local
```

Check a running vt server: `tmux -L vt show-hooks -g` lists hook names only (no command after any of them),
`tmux -L vt show-options -g | grep '^@'` prints nothing, and `tmux -L vt list-windows -a` shows only vt's windows (including the `vt-localnet` ones).

## Jobs: the message and the message file

`vt job create <job.json>` takes the message from one of three places:

- an inline `"message"` in the job file;
- `"messageSha256"` + `"messageBytes"` of a text already uploaded;
- **`--message-file <path>` on the command line.** This is the only way a file becomes the message. A job file never
  names a file: a job JSON with `messageFile` is refused (`vt.message-path`), because a job file can come from anyone
  and whatever file is read is **published, permanently and publicly**.

Before it reads a byte, vt checks the path (`vt.message-path`):

- the named file must not be a symbolic link; its real path (every directory link resolved) is what is checked;
- it must be a regular file (no directory, FIFO, socket or device), at most 16 MiB (`message.too-long`), with one
  link only (`vt.message-hardlink`: a second hard link could name it inside a denied directory; copy it instead);
- it is read **once**, from one descriptor: the real path is resolved once, opened (`O_NOFOLLOW`, `O_NONBLOCK`), and
  the descriptor must be the file checked; the path must still resolve to it after the open, and the file must not
  change while it is read (`vt.message-changed`). The sha256 vt shows and you confirm is computed from those bytes, and
  exactly those bytes are uploaded: vt never opens the path again;
- a second name of a denied directory (such as `/System/Volumes/Data/Users/you/.ssh`, which `realpath` does not fold)
  is recognised by the directory's identity and denied like the directory;
- never keys or credentials: `~/.ssh`, `~/.gnupg`, `~/Library/Keychains`, `~/.aws`, `~/.config/op`, `~/.op`;
- never vt's state (`VT_HOME`, default `~/.local/state/vt`), never `/tmp/vt-asdf.*`;
- never a file in a sealer's work directory, known by its name alone (`1password-timelock.*`, wherever it is:
  `$TMPDIR`, `/private/var/folders/…`, `/tmp`): the sealer exports the vault's plaintext there before any marker file
  exists (`vt.message-workdir`);
- never a file the sealer or vt writes for local use only, wherever it is: `identity.key`, `*.age`,
  `SEALED-plaintext.txt`, `STRUCTURE.txt`, `MANIFEST.csv`, `BLANK-AT-SEAL.txt`, `api.token`, `relay-ticket.key`;
- package directories allow only `SEALED.txt`, wherever they live: inside `$OUT` (`VAULT_TIMELOCK_DIR`, or its
  defaults), inside any `~/p/1password-*` directory (also when that directory is a link to another disk: the path as
  given is checked as well as the real path), or inside a package directory anywhere (`1password-*-timelock-*`,
  `*-timelock-<stamp>`, or a directory holding a sealer's file such as `vault.tar.gz.age`): **only a package's own
  `SEALED.txt`**, the one file a seal writes to be published. README.txt, an export's files, items/, files/,
  restored/ and everything else there are refused.

vt then shows the file's real path, size, sha256 and first line (escaped, at most 80 characters), and uploads it only
after you confirm **that** file:

```
bin/vt job create job.json --message-file ~/pkgs/1password-X-timelock-20261009T120000Z/SEALED.txt
#   message file  /Users/you/pkgs/1password-X-timelock-20261009T120000Z/SEALED.txt
#     4211 bytes  sha256 3f2a…
#     first line: vault-timelock-sealed/1
#   Type publish to upload this file (…) for publication: publish
```

Without a terminal (a script), pass the digest vt showed: `--yes-publish-file <sha256>`. Any other digest is refused
(`vt.publish-confirm`). With `--normalize`, the digest is the normalized text's (vt shows it).

## Jobs: running a job here (`vt job run`) and clawing back (`vt job clawback`)

`vt job run` is the CLI executor: it decrypts the key backups **in this process's memory** and signs the job's
transactions, under the executor sandbox (this network's relay and API ports, no terminal, no file writes; it reads the
backup files and `api.token`, and cannot read any network's `relay-ticket.key`: the sandbox denies it, so a compromised dependency
cannot mint relay tickets). Your terminal belongs to vt's unsandboxed broker
([start commands](#start-commands-per-network)): it asks the passphrase and every typed word for the executor, reads `s`
and Ctrl-C, and filters what the executor prints.
The page's Run button is the other executor; one chain has one executor at a time (its lease).

```
bin/vt job run <id> --backup-eth ~/.local/state/vt/backups/eth/vt-eth-key-….age --backup-sol …/vt-sol-key-….age
bin/vt job run <id> --chain sol --backup-sol …/vt-sol-key-….age      # one chain only
bin/vt job run <id> --chain btc --backup-btc …/vt-btc-key-….age      # the BTC lane (local network only)
```

Before anything is decrypted:

- no debugger can reach the process (`vt.inspector`): bin/vt starts node as `node --disable-sigusr1 --no-addons` (by
  default, Node opens an inspector on a loopback port when a process gets SIGUSR1; `--no-addons` loads no native code),
  and any other node option, `NODE_OPTIONS` or an open inspector refuses;
- stdin and `/dev/tty` must be a terminal (`vt.tty-required`; the broker checks its own, since the executor has none):
  the passphrase is typed there, never piped, never in argv or the environment, and the broker hands it to the executor
  over a pipe;
- the job-send lock (`release.mainnet-locked`): lifted in this build ([the M2 flip](#the-m2-flip-applied-r78)), so
  mainnet runs; a build with the lock on refuses here;
- the BTC lane runs on the local network only: `--chain btc` (or a job whose btc chain would run) on testnet or mainnet is
  refused (`executor.chain-unsupported`) before any file is read;
- the job and the API are on this network (`executor.network-mismatch`); each chain that runs (every chain of the job
  that has not settled, or `--chain`) needs its `--backup-<chain>`, a regular age file of at most 1 MiB
  (`vt.backup-format`).

Then the passphrase, typed with no echo. One passphrase is tried on every backup, so a passphrase shared by both
backups is asked once. The key must be the job's `keyAddress` (`backup.address-mismatch`; a wrong passphrase is
`backup.decrypt`), and the backup must have been made on the job's network (`backup.network`). A BTC backup is the same age file
(`{chain:'btc', address, secret hex, network}`): its address is the job's bech32 p2wpkh lane address, and a backup that
records no network is not a BTC key (`backup.inconsistent`). A backup from before
networks were recorded asks you to type `again`.

While it runs, vt prints each chain's progress (the countdown as `M:SS`) and the job's journal events, with IP literals
redacted and terminal control sequences escaped; the broker then drops any control sequence still left (ESC, OSC, CSI,
DCS, C1; colours too). vt itself never prints a key, a passphrase or an IP: every line it prints goes through that
printer, and an error it did not expect is never printed as such (below).

- `s` during the countdown skips it (every chain of the job), once.
- **Ctrl-C detaches this terminal's executor; it does not stop the job.**
  - Every chain this `vt job run` holds stops signing: no next part, no fee bump, no replacement.
  - vt prints "stopping after the in-flight transaction…" and waits for the transaction in flight. Its same signed bytes may
    be sent again, but only until the end of its current window: ETH 3 blocks (economy, prompt) or 25 blocks (passive, about
    5 minutes on mainnet); a SOL signature until it lands or its expiry is proven (at most 5 minutes).
  - Then vt exits and **journals nothing final**: no `stopped`, no `stuck`. The chain stays as it was (RUNNING), and a
    transaction still pending stays open.
  - The next `vt job run` (or Run here) takes the chain over, reconciles every open transaction from the chain (an open ETH
    transaction is adopted with its identical bytes) and continues the job at the next part.
  - It sends no stop request to the API, so a chain held by another executor (the page, another terminal) is not touched.
- **`vt job stop <id> [--chain c]` is what stops the job.**
  - The API's stop request is honoured by whichever executor holds the chain. After its in-flight window that executor
    journals `stopped`.
  - The chain is then latched: a STOPPED chain that no executor reopens. With a transaction still pending, the chain is
    STOPPED with it open, and a later `vt job run` only watches it (see Recovery).
  - `vt job resume <id>` lifts the latch of a *resumable* stop only (your Stop, a failed start check, an RPC outage; mainnet:
    type `resume`). The next `vt job run` then reopens the chain and continues at the next part of the current copy, once
    its pre-start checks pass. A *final* stop (a readback mismatch, a reverted part, a failed reassembly, an EIP-7702
    delegation, the spend cap, a stuck or mark-failed transaction) is never lifted (`resume.final-stop`): claw back
    (`vt job clawback`) or close (`vt job close`), then make a new job. See Recovery, "Resumable and final stops".
- **A BTC copy is a commit and its reveal, one unit.** Ctrl-C (or a Stop) never leaves a commit without its reveal.
  - If the commit is out, vt waits for it to land, sends the reveal, and only then ends: it journals nothing after a Ctrl-C,
    and `stopped` after a Stop. The core journal refuses `stopped` over a stranded commit (`engine.btc-open`).
  - A Stop seen before a copy's commit is signed, even while it is planned, signs no commit.
- A second Ctrl-C prints a warning and changes nothing. `kill -INT`, `kill -TERM` and a closed terminal are treated the same
  (they reach vt's broker, which passes each on to the executor). Sent to `bin/vt`'s own pid it is forwarded to the broker (`bin/vt` ignores Ctrl-Z), unless the shell that started `bin/vt` left SIGINT ignored
  (a background job of a non-interactive shell): a shell cannot trap what was ignored on entry, so send the signal to the broker's pid then.
- Two things end the executor with a transaction in flight: `kill -9` of the executor process itself (vt's sandboxed
  child), and an unexpected internal error (below). The next run reconciles that transaction from the chain before
  anything new, so nothing is sent twice. `kill -9` of vt itself (the broker) is not one of them: the executor notices
  that its broker is gone and detaches as on Ctrl-C (the terminal may stay raw: `stty sane`).
- A chain held by another executor (the page, or another `vt job run`) is refused `lease.held`; once that lease lapses
  (15 s after its holder died), `vt job run` takes it over and reconciles every open transaction from the chain before
  signing anything new.
- An **unexpected internal error** (an uncaught exception or an unhandled rejection; none is known) ends vt at once.
  It drops the keys, prints one fixed line (never the error's text, which could hold an address or key material), then
  for each chain either ``stopped unexpectedly after sending — run `vt job run` again to reconcile (nothing will be
  sent twice)`` (this run journaled an intent there) or `did not run — nothing was sent`, and exits 1. A chain that
  ends in an error after this run journaled an intent says the same; `did not run` means that provably none was.

When vt returns, fails or meets an unexpected internal error, the keys are dropped: the SOL secret bytes are zeroed and
every reference is released (the BTC key's secret is a hex string, so like the passphrase it cannot be wiped). `kill -9` of the executor, or `kill -INT`, `kill -TERM` or a closed terminal while a prompt is open before
the run starts (nothing is in flight then), ends the process without that; the OS frees its memory. (JavaScript
strings, the passphrase among them, cannot be wiped; they end with the process.)

`vt job clawback` sends what is left on a **settled** chain's key (drained, copies done or stopped) to the address you
name with `--to` (the job's `clawbackTo`, when it has one; on mainnet always), with the same terminal, lock and key rules:

```
bin/vt job clawback <id> --chain eth --to 0xYourChecksummedAddress… --backup-eth …/vt-eth-key-….age
```

- `--to` must be an EIP-55 checksummed address (ETH) or a canonical base58 address (SOL); never the lane's own key,
  never an address nobody controls (`0x0…0`, `0x…dEaD`, the System Program, the incinerator; an Ethereum precompile
  or reserved system address, `0x…0001` to `0x…ffff`, is `job.clawback-precompile`), and exactly the job's
  `clawbackTo` when the job names one (`job.clawback`). On mainnet only the job's stored `clawbackTo` is ever accepted,
  whoever asks and whatever amount is typed; every new mainnet job names one (`job.clawback-required`). An ETH contract
  destination is refused.
- **No BTC claw-back yet:** `vt job clawback --chain btc` is refused ("not available yet"); the BTC lane runs copies only.
  Keep the BTC backup: what is left on the lane key stays there.
- ETH gas depends on the destination: 21,000 to an existing account; after Amsterdam, 204,600 to an **empty** one.
  vt shows which before anything is signed.
- The claw-back empties the lane: value + fee = the lane's balance. When that is more than what is left of the cap
  confirmed at Arm, you type that exact amount (shown in full; compared in base units, `arm.amount`). It approves this
  one claw-back, never a higher cap.
  - The amount can move before signing (the fee estimate, or a copy landing): vt then shows the new amount and **asks again**
    (a wrong or stale amount is re-asked, 3 tries, then the claw-back is declined). Type what vt shows now.
  - Fund a lane near the job's cap and the amount stays under it: no typed amount.
  - Dust stays: an ETH balance at or below what one transfer costs (21,000 x the max fee) is "nothing to claw back" and the
    chain stays DRAINED.
  - A drain spends up to the lane's funds or the job's cap, whichever is smaller, so small remainders (dust) are normal.
  - A claw-back ends in CLAWED_BACK: terminal. It cannot be closed afterwards; it frees the key.
- The claw-back links the lane key to `--to` on-chain, publicly and for good (vt prints this warning). On mainnet you
  type `claw back` (`job.clawback-typed`).
- **A claw-back never waits for ever.**
  - A passive ETH claw-back sends its same signed bytes again whenever no node has them.
  - If the verified endpoints do not all know it for 3 windows of 25 blocks in a row (about 15 minutes on mainnet; one
    endpoint's word is not enough), it is journaled STUCK. An economy or prompt claw-back is replaced by a same-nonce fee
    bump instead, at most 6 times.
  - A claw-back taken over from an earlier run whose transaction the nodes dropped is rebuilt byte for byte from the
    journal and sent again. If the rebuilt bytes would differ, it is STUCK with the reason, and nothing else is signed at
    that nonce.
  - To get out of STUCK: look the transaction up. If it never landed, run `vt job resolve … mark-failed`, then
    `vt job clawback` again at the same nonce. If it landed, just run `vt job clawback` again: the landing is read from
    the chain. A claw-back is never marked done by hand.
- **Ctrl-C during a claw-back signs nothing new.**
  - Before the claw-back is signed, nothing is signed. That includes a Ctrl-C that arrives while the claw-back is being
    prepared.
  - With one in flight there is no fee bump. vt keeps watching it to the end of its window. If it is still pending, the
    claw-back stays open (run `vt job clawback` again to watch it). If the endpoints do not all know it, it is STUCK (above).
  - A Stop of the job itself (the one that settled the chain) does not cancel a later claw-back.

## The BTC lane (local only for now)

A job can carry a Bitcoin lane that publishes the text as an **ordinals inscription** (`btc.inscription`, `text/plain`;
the BTC lane's only publish mode). **Local only for now:** a testnet or mainnet BTC job is refused
(`job.chain-unsupported`), and the stack's relay reaches a Bitcoin node only on the local network. The Arm dialog shows
the BTC lane's fee rate, the worst case per copy (commit fee + reveal fee + 546 sat postage, priced at the job's `maxFeeRateSatVb`, or 500 sat/vB for a stored job without one) and the lane balance. A BTC
tx is stuck-safe: a run never ends `stopped` over a commit whose reveal has not landed (`engine.btc-open`).

| Piece | Status |
|---|---|
| Relay BTC routes (`/relay/btc`, `/relay/btc/ord/…`, ticketed `POST /relay/btc/send`; spec §6) | **in this tree** (S6b) |
| One derivation of the inscription (`packages/core/src/chains/btc-ord.ts`), API-minted BTC tickets | **in this tree** |
| **BTC executor** (the commit + reveal engine, `vt job run` / the page's Run for a `btc` lane) | **in this tree** (E7/E7b), on the local network only |
| The page's BTC form, fee/balance lines in the Arm dialog, ord links and key backup form | **in this tree** (W7b) |
| **`vt job run` / `vt job arm` / `status` / `watch` / `receipt` for a `btc` lane** (`--chain btc --backup-btc <file>`, `--chains …,btc`, `--source btc=<label>`; the commit and reveal txids and the readback in `status`) | **in this tree** (Cbtc). Through the real API process (M4d: `cli/test/run-btc-real.test.ts` on its own regtest, ord, relay and API) |
| BTC claw-back | **not available yet** (`vt job clawback --chain btc` is refused) |
| Stuck BTC commit | `vt job resolve <id> --chain btc --tx <txid> mark-failed` only (the API refuses `mark-done` for a commit); a failed attempt stays counted against the cap |

What the operator needs (local network only, regtest):

1. A regtest `bitcoind` on its loopback RPC port and an `ord` server on its loopback port (the ports are in
   `broadcast/endpoints.json`, section `local`, keys `btc.bitcoind` and `btc.ord`). **`bin/vt localnet up` starts both**, with a
   miner so commits and reveals confirm. The relay reads the bitcoind credential only from
   `$VAULT_TIMELOCK_DIR/local/btc-rpc.auth`, and **`vt localnet up` writes that file** (mode 0600, `vt:<password>`); without
   it the local BTC lane is off and nothing is sent to the bitcoind or ord. Start (or restart) `vt up --network local` after
   the file exists.
2. **Regtest funding is the operator's step, on your own regtest node.** The BTC lane key is a native-segwit (p2wpkh)
   address; the funding panel shows it. `bin/vt localnet fund btc <lane address>` pays it from the regtest wallet `vt` and
   mines a block. Or mine to it (`bitcoin-cli -regtest -datadir="$VT_HOME/localnet/bitcoind" generatetoaddress 101 <lane address>`, the datadir
   holding the RPC cookie, pays the
   first coinbase and makes it spendable after 100 more blocks), or send from your regtest wallet. The postage output
   goes to a taproot address and is never spent. Nothing here involves a testnet or mainnet coin.
3. The job is **copies only** (no drain) and **must name a fee-rate ceiling** `maxFeeRateSatVb` (an integer 1 to 500
   sat/vB; `job.btc-fee-ceiling` when it is missing from a new job, `job.fee-rate` when it is out of range). The lane never
   pays more than the ceiling, and nothing above 500. Arm quotes and caps every copy at the ceiling (the worst case: up to 8
   inputs, the largest commit and reveal for your text, the 546-sat postage), never at today's node estimate, and the Arm
   rows say which rate they are priced at. The page's New job form prefills the field with min(500, max(10, 4 x the relay's
   current estimate)) (25 when there is no estimate) and lets you edit it; `vt job validate` and `vt job create` print the
   same suggestion when the field is missing. A job created before this rule, without the field, still loads and runs
   with a 500 sat/vB ceiling. A large text or a high ceiling can make the planned spend (N x the worst case) exceed the
   0.01 BTC native cap: Arm then asks you to type the planned amount, as it does on the other chains.
4. After the run, the job page links the commit and reveal transactions and the inscription **on your local ord**
   (`http://127.0.0.1:8090/…`; the links are loopback only and need your ord running).
5. The BTC key backup is the same age backup as ETH and SOL (`{chain:'btc', address, secret hex, network}`); save it and
   re-select it as for the other lanes (see Backups).

A `btc` chain that is STUCK prints its real job id and commit txid in the reason, and the exact next command
`vt job resolve <id> --chain btc --mark-failed`. For btc only `--mark-failed` is accepted: `mark-done` is refused, because a
commit that never landed must not be marked done. `vt job stop` on a btc chain takes effect after the in-flight commit's reveal.

A note may not contain invisible format characters in a NEW text: every Unicode Default_Ignorable_Code_Point and U+FFF9-U+FFFB (soft hyphen,
zero-width characters, word joiners, variation selectors other than the two below, and the like) is refused (`note.invisible` when the envelope is built,
`payload.invisible` when a text is checked for publishing). **U+FE0E and U+FE0F (the text and emoji presentation selectors) are ALLOWED in notes.**
Open keeps the older, more liberal set when it reads an existing text. A note whose lines look like SEALED.txt structure is refused
`payload.note-structure`.

The relay refuses every Bitcoin send that is not the ticketed one, and the API computes every ticket field itself, so a
compromised executor cannot redirect the commit.

ETH and SOL job sends are bound the same way (pre-flip review I-1): the API plans each copy from the STORED message with the
lane's own planner and refuses an intent whose payload, part count or part is not the planned one (`ticket.payload-plan`), or
whose ETH recipient is not the one the publish mode sends to (`ticket.recipient`). The ticket carries the planned payload's
digest and, for ETH, that recipient; the relay forwards only signed bytes that carry exactly that payload to exactly that
address. Copies go in order (`job.copy-order`: the current copy, or the next one at part 1), so no copy number is made
up, and a SOL tx carries exactly the account keys it uses (no extra key: `relay.decode-mismatch`). A compromised page or
executor therefore cannot publish other text under the job's cap.

The fee fields are bound too (pre-flip fix rounds 2 and 3). Every ETH and SOL ticket names the intent's declared fee
members (`x`). The relay forwards:

- an ETH tx only when its gas limit, priority fee and max fee are exactly those;
- a SOL tx only when its message is byte for byte the one vt's own builder makes from the ticket: a legacy message in the
  builder's order, the CU limit and CU price exactly, no price without a limit, no other ComputeBudget instruction, no CU
  limit of 0.

The API refuses declared values outside its plan (`ticket.fee-plan`):

- ETH job gas: the gas formula of the planned payload plus the estimate tolerance (15/985), for the network's fork and
  the publish mode (local accepts either fork).
- ETH claw-back gas: exactly the transfer gas of a destination class: 21,000, or 204,600 for an empty account where
  Amsterdam may run.
- SOL job: a CU limit up to the CU model's limit for the planned part, and a CU price up to the lane's cap. The cap is
  maxCuPrice (2,000,000 when unset, as the engine), or a higher cuPriceCap from an operator resume.
- SOL claw-back: sized as the engine sizes a transfer. Unpriced, it carries the default limit 200,000 and no ComputeBudget
  instruction. Priced, the limit is at most 1,100 and the price at most 2,000,000.

What remains, per transaction:

- **The signature nonce (accepted).** An ECDSA (ETH) or ed25519 (SOL) signer chooses the nonce inside each signature. A
  malicious signer can leak data through it. A party that shares a secret with the signer, and so knows the nonce, can
  even compute the key from one signature. No relay check can see this.
- **The SOL blockhash.** The declared blockhash `q` is any 32 bytes; the API cannot tell that it is recent. Any value
  reaches the RPC providers (and leaders on a rebroadcast): 256 bits off chain. Only a recent one lands: about 7 bits on
  chain (one of about 150 valid blockhashes).
- **The claw-back amount's low bits.** The value is the executor's choice under the cap (honest: the balance minus the
  fee). Its low b bits cost at most 2^b base units left behind and land on chain at clawbackTo: about 30 bits for at most
  1 gwei on ETH, and about 17 bits for at most 0.00013 SOL.
- **The fee choices inside the plan** (journaled and visible):
  - ETH job gas inside the tolerance window: ⌈15g/985⌉ + 1 values, about 8.5 bits at 23,000 gas and 11 bits at 120,000.
  - ETH max fee: free above what is paid, so tens of bits at no cost.
  - ETH tip: tens of bits; about 30 bits cost at most 1 gwei per gas.
  - ETH claw-back gas: at most 1 bit (21,000 or 204,600).
  - SOL job CU limit: up to the model's limit, about 15–20 bits (49,500 for a 50-byte part).
  - SOL job CU price: up to the lane's cap, about 21 bits; it costs at most limit × price / 10⁶ lamports.
  - SOL priced claw-back: about 10 bits in the limit and 21 in the price. An unpriced one has none.

Run only a verified release.

## Open: timelocked texts (`#/open`)

`http://127.0.0.1:<page port>/#/open` opens a **timelocked** published text (a `SEALED.txt`, or the published text):

1. Paste the text or load the file. The page parses it with core and shows the unlock time, the drand round and the file
   names with their sizes. A text core does not accept is refused with the reason.
2. **Before the unlock time** it shows a countdown by the API's clock and "Not yet". The only request it ever makes is
   drand's public `latest` round number, once the countdown ends (or on your click), one check at a time, at least 3 s
   apart. Nothing else is fetched, and nobody, this page included, can open it earlier.
3. **drand goes through Tor.** The page asks the stack's relay (`/relay/drand/…`), never drand directly. On the local
   network the relay sends drand through Tor after its IsTor check, so a local stack needs Tor on `127.0.0.1:9050` for Open
   (the same as testnet and mainnet).
4. **After the round is published** you press **Fetch the round and decrypt**. The page decrypts in this tab (tlock + age)
   and lists the restored files with size and sha256.
5. **Files are downloads.** Each file has its own **Download** button; nothing downloads by itself. The plaintext lives in
   the tab's memory only (never in storage, a URL or a request), and **Clear** drops it.

Timelocked *publishing* is switched off in this build ("not enabled yet"): the page can open such texts, not make them.

## Decrypting at the terminal: `vt decrypt`

```
vt decrypt [<file> | -] [--identity F] [--out <path|dir>] [--stdout] [--list] [--only <path>]
```

One command for every age file vt deals with, on the same core as the page's Decrypt tab:

| input | what it needs |
|---|---|
| age **passphrase** file (scrypt), armored or binary | the passphrase, typed at the terminal when vt asks (not echoed) |
| age **identity** file (X25519, e.g. a `--recovery-recipient` key) | `--identity F`, an age-keygen identity file |
| **time-locked** file (tlock, e.g. `unlock-TIME.age`) | the drand round's signature, fetched through the running stack's relay: `vt up --network <n>` first |
| a whole **SEALED.txt** (bare or the published text) | its full open chain: through its time lock (the relay), or with `--identity` (the one-time key, e.g. recovered from `unlock-KEY.age`) straight to `vault.tar.gz.age`, at any time |

**Input.** A file, or none / `-` for stdin. On a terminal vt reads a **paste** itself: the text is shown as you paste
(ciphertext is not secret) and the paste ends at `-----END AGE ENCRYPTED FILE-----`, at a SEALED.txt's `== end ==`, or with
Ctrl-D. It must be age armor or a SEALED.txt (its first line says which) and at most 1 MiB, and that is checked **before
anything is asked**: anything else is refused at once (`decrypt.format`, `decrypt.size`). Whatever follows the end line
is thrown away, never left for your shell. A pipe (`pbpaste | vt decrypt - --out x`) is read to its end under the same
cap and checks (binary age too). Bigger inputs: give the file.

**Passphrase.** Asked once, by vt's broker on the terminal (echo off), and only when the input really is an age
passphrase file — also when the input comes through a pipe. Never from stdin, argv or the environment; no terminal is
refused (`vt.tty-required`).

**Output: only where you say.**
- `--out <path>` writes the plaintext to a NEW file, mode 0600; it never overwrites (`vt.out-exists`).
- For a SEALED.txt, `--out <dir>` is a NEW directory (0700) holding every file of its archive (0600). Before anything is
  written, the files are checked against the archive's `MANIFEST.csv` / `ATTACHMENTS.csv` digests when it has them. A
  mismatch writes nothing (`vt.manifest`). Two archive paths that the disk would store as one file (`A` / `a`, or
  NFC / NFD `é` on APFS) are refused, never merged. On any failure, whatever was written is removed.
- `--stdout` prints the plaintext (for a SEALED.txt: the archive, e.g. `vault.tar.gz`), and only when asked.
- With neither, nothing is decrypted (`vt.decrypt-output`): a decrypted key never lands on screen by accident.
- `--list` prints `<size>  <path>` for each file of the archive and never its contents. It is allowed on a terminal.
  Invisible characters (bidi, zero-width, controls) are shown as `[U+XXXX]`.
- `--only <path> --out <file>` (or `--stdout`) extracts one file. Give the path exactly as `--list` printed it.

**Time locks.** Before the round vt refuses with the unlock time (`decrypt.too-early`) and fetches nothing. After it,
vt asks the relay of the network (`--network`, default local) for the round. If that stack is not up, vt refuses and
tells you to run `vt up` for that network (`vt.relay-down`). The relay reaches drand through Tor, as for the page's Open.

**Confinement.** The decrypting process runs in its own sandbox. It can reach only the network's relay port. It can
read only the files it was handed (the input and `--identity`). It cannot write any file and has no terminal. vt's
unsandboxed broker reads the paste, asks the passphrase and writes `--out`. Nothing is logged: no passphrase, identity
or plaintext.

```
vt decrypt unlock-KEY.age --identity ~/recovery.key --out one-time.key      # the recovery path, step 1
vt decrypt SEALED.txt --identity one-time.key --list                         # what is inside (paths, sizes)
vt decrypt SEALED.txt --identity one-time.key --out restored                 # every file, checked against MANIFEST.csv
vt --network testnet decrypt SEALED.txt --out restored                       # after the round, through the testnet relay
pbpaste | vt decrypt - --out note.txt                                        # a pasted passphrase-encrypted note
```

## The funding tabs: Railgun and Privacy Cash

Funding stays **locked** in this build: no tab here moves money by itself, and **withdrawals stay locked** (below).

| Tab | What it does | Status |
|---|---|---|
| **Railgun** (ETH lanes) | Shows how to fund a lane from a private balance: **you** do the unshield, **by hand, in your own wallet** (Railgun's own app), to the lane's address. The tab never holds a Railgun key and never sends. It then reads the lane's funding transaction and shows a **provenance badge** (informational, see R76). | **in this tree** (W6) |
| **Privacy Cash** (SOL lanes) | Balance check for a Privacy Cash account whose key you paste (kept in the tab's memory only; every balance check and withdrawal first shows a linkage warning). Proving runs in a worker (about 5 s, single-threaded). | **in this tree**: the tab (W6) and the relay routes `/relay/privacycash/*` (S7) |
| **PC withdraw** (Privacy Cash to a lane) | Moves funds from Privacy Cash to the lane address through the relay. The relay takes it only with a single-use **lane authorization** (`x-vt-pc-lane`, `v2…`) that the API mints for this job, try and the exact request body (`POST /api/jobs/<id>/privacycash/lane`, reserving the amount against a per-lane cap `VT_PC_LANE_CAP_LAMPORTS`; unset means no mint). The page's worker asks for it when the SDK posts the body, and the page server forwards the header only on `/relay/privacycash/*`. | **built, and LOCKED on mainnet**: the API mints nothing there (`api.pc-lock`, 423) and the relay refuses withdrawals while funding sends are locked, so the tab shows the lock and its Withdraw button stays off. Withdrawals are gated on the funding lock, not on the job-send lock, so the M2 flip of the job-send lock does **not** open them. They open only with a separate, operator-approved funding unlock, which also changes the mint's `api.pc-lock` rule and the tab's `MAINNET_FUNDING_LOCKED`. Not every item of the before-unlock list is done (see the S7 reports). |

Until the funding unlock, fund lanes as in "Funding (testnet and local)" above.

## The mainnet Arm gate (R76)

On mainnet the Arm dialog asks **only that funds are present in each armed lane's wallet**: for every armed chain the
dialog shows the lane's address and **balance**, and "no funds present" at zero. "Present" is the existing READY rule: the
executor sees at least one copy affordable. There is **no** provenance requirement and **no** typed attestation.

- The **provenance badge** (Railgun L1 funding: the six `provenance.*` verdicts) is **informational**: shown when it can be
  evaluated, never blocking Arm.
- The mainnet typed confirmations are unchanged: `broadcast` (and the amount again over the cap, and `again` when the
  key has history), and `claw back` for a claw-back. `vt job arm` at the terminal asks the same, after the relay's
  `IsTor` (`arm.tor`) and the five ticks typed as `ticks` (`arm.ticks`; First mainnet run, step 8).
- **The cap the API accepts (pre-flip review M-4).** An arm without the typed amount carries at most the R60 native
  ceiling: 0.004 ETH, 0.07 SOL (price-free, so the API, which has no price, checks the very number the page and
  `vt job arm` plan with). When the $10 R60 cap is worth more than that (ETH under $2,500, SOL under about $143), the
  planned spend above the ceiling is asked as a typed amount, like any over-cap arm. A typed arm needs a price, and every
  priced cap is at most the job's `budgetUsd` (itself at most $1,000). Anything else is refused `arm.cap-ceiling`.
- Job sends on mainnet are **enabled** in this build ([the M2 flip](#the-m2-flip-applied-r78), R78): the
  lock no longer refuses Arm. R76 (funds present in each armed lane: READY, else `job.state`), the legacy latch, the typed
  confirmations, the countdown and the cap ceiling still refuse, in the API as in the page and `vt job arm`.

## The M2 flip (applied, R78)

**Applied** in the commit `release: lift the mainnet job-send lock (M2 Step 6, R78)`, approved as R78 after the
clean-state localnet loop passed. It set `export const MAINNET_JOB_SENDS_ENABLED = true`
(broadcast/src/config.ts) and changed nothing else in the source: `lock()` is byte for byte the same (the `LOCK_SHA256`
pin did not move) and `export const MAINNET_SEND_ENABLED = false` stays. So on mainnet:

- **open:** the job sends, ETH value-0 data txs and SOL Memo v2 txs, and their claw-backs: the API's arm, intent and
  ticket paths, the relay's `/relay/eth`, `/relay/sol` and `/relay/sol/ep/<i>`, `vt job arm|run|clawback` and the page's
  Arm (`/status` answers `jobSends: 'ENABLED'`; `vt status` and `vt preflight` print `mainnet job sends: enabled`);
- **still refused:** everything behind `MAINNET_SEND_ENABLED` (Flow 1 and the legacy `release`, funding and Privacy Cash
  withdrawals, Turbo / Arweave, Esplora POST, bitcoind, airdrop, query-string or non-JSON sends), mainnet BTC (the
  all-scope lock, PF-S M-1), and a job send whose endpoint does not answer mainnet's own identity
  (`config.identity-mismatch`); and every other gate stays: R76 (an armed lane must be READY: funds present), the legacy
  latch, the typed words, the countdown, the cap ceiling, the tickets and the decode verification.

The tests are split so that the flip commit edited only the job-scope ones; the all-scope ones are byte for byte the same
(`git diff`: no hunk in a test named `ALL scope`). The list below was derived by a simulated flip (pre-flip review N-3, fix
round 1; again at the pre-flip merge, M5) and once more at the flip itself:
the broadcast offline, api and cli suites with the flag lifted failed exactly 6 broadcast, 11 api and 3 cli tests, these.
Each was edited to expect what the lifted lock does, and each now also asserts that the other gates still refuse.

1. `broadcast/test/offline/send-lock.test.ts` (each marked `M2 FLIP`):
   - `JOB scope (M2 FLIP): MAINNET_JOB_SENDS_ENABLED is true in this build` (was: `false`).
   - `JOB scope (M2 FLIP): assertJobSendAllowed(mainnet) gives a mainnet job permit ...`: the mainnet profile gets a
     `job`-scope permit with no observed identity (the API's arm and ticket paths) or a mainnet eth / sol identity (the
     relay's); a non-mainnet, malformed or out-of-scope identity still refuses (`config.identity-mismatch`); a btc mainnet
     genesis STAYS refused (`release.mainnet-locked`, the all-scope message); the all-scope lock refuses them all.
   - `JOB scope (M2 FLIP): eth and sol on mainnet get a job-scope permit ...` (never an all-scope one).
2. `broadcast/test/offline/net-send-permit.test.ts`: `JOB scope (M2 FLIP): a mainnet job permit exists in this build ...`:
   it covers only the ETH / SOL job sends; every other send class stays `net.send-permit`.
3. `broadcast/test/offline/send-lock-static.test.ts`: the pinned line is `export const MAINNET_JOB_SENDS_ENABLED = true`
   ("holds both lock lines exactly", "nothing in src/ or bin/ declares or assigns the lock names"); `LOCK_SHA256` unchanged.
4. api:
   - `api/test/routes.test.ts`: `GET /status: ... mainnet job sends ENABLED (the M2 flip) ...` and `mainnet (M2 flip:
     the job-send lock lifted): ...` (an unarmed or unreleased job is `job.state`, an unfunded lane cannot be armed, the
     legacy latch blocks the intent and the ticket; once released the intent is journaled and ticketed for mainnet);
   - `api/test/contract-http.test.ts`: `status-200` (the vector's `jobSends: 'LOCKED'` stays a valid example; the build
     answers `ENABLED`);
   - `api/test/arm.test.ts`: `mainnet with MAINNET_JOB_SENDS_ENABLED = true (the M2 flip) ...` (latch, R76, typed word,
     countdown, stagger, cap ceiling in turn; then it arms);
   - `api/test/relay-gate.test.ts`: the contract vectors (the mainnet ETH vector passes; a non-mainnet identity or relay
     refuses it) and `mainnet send (M2 flip ...)` (genuine bytes pass; other bytes, an expired or testnet ticket, a lying
     binding or a non-mainnet identity refuse);
   - `api/test/relay-networks.test.ts`: `mainnet send (M2 flip ...)` (forwarded once per chain; refusals never forwarded);
   - `api/test/relay-endpoints.test.ts`: `ETH per-endpoint routes stay read-only ...` (its mainnet case) and `over HTTP:
     mainnet (M2 flip ...)` (the endpoint ledger on mainnet; ETH `ep` stays read-only);
   - `api/test/decode.test.ts`: the valid vectors and the engine-built txs pass the whole gate on mainnet too.
5. cli: `cli/test/run.test.ts` (`mainnet: the job-send lock is lifted ...`: the terminal and one-network checks still
   refuse), `cli/test/clawback.test.ts` (the real lock reaches the `claw back` question), `cli/test/job-client.test.ts`
   (the real lock reaches the `ticks` question: `arm.ticks`; then `ticks` and `broadcast` typed exactly).

Unedited, and still passing after the flip (they do not depend on the flag): `send-lock-flip.test.ts` (each flipped copy
sets both lock lines itself), the `M-1: a mainnet BTC job send is refused by the ALL-scope lock` test,
`api/test/relay-btc-send.test.ts` (mainnet BTC: the all-scope refusal), `api/test/decode-btc.test.ts`, the PF-S M-4 test in
`api/test/arm.test.ts` (`arm.cap-ceiling` on mainnet), the PF-S R1-2 and R2-2 tests in `api/test/routes.test.ts` (they
still lift the lock through the test-only `jobSendLock` seam), every `ALL scope: ...` test, the `MAINNET_SEND_ENABLED =
false` pin, and everything about Turbo, Arweave, Esplora POST, bitcoind, airdrop, query-string or non-JSON sends.
