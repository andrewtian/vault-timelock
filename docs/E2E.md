# End-to-end workflow

How to run the whole vault-timelock publish and broadcast workflow, from a local sandbox up to
mainnet. The operator guide and command reference is `docs/vt.md`.

## 0. Canonical `vt` stacks (`vt localnet`, `vt up` / `status` / `logs` / `down`, `vt backup import`)

R77: only the local network and mainnet are maintained; **testnet is held (R77): not maintained** (its section below is kept
as it was). The local network's chains are set up by one command, `vt localnet up` (operator guide: `docs/vt.md`, "The local
environment: `vt localnet`").

One stack per network, each in its own tmux session `vt-<network>` (windows `relay`, `api`, `page`) on vt's own tmux
server (`tmux -L vt attach -t vt-local` to look), every process in its own sandbox. From a development tree, `VT_HOME` and `VAULT_TIMELOCK_DIR` must both be set (agents: fresh temp dirs).
The sandboxed `vt` commands (`status`, `preflight`, `job …`) have no terminal: vt's unsandboxed broker asks every
passphrase and typed word, reads `s` and Ctrl-C, and filters their output (`docs/vt.md`, "Start commands").

```
vt localnet up                             # anvil :8545, solana-test-validator :8999, bitcoind regtest :18443 + miner + wallet vt, ord 0.29.0 :8090, Otterscan :5100
vt localnet status [--json]                # per service: identity, version, who started it
vt localnet fund eth|sol|btc <address> [amount]   # local chains only; prints the tx id
vt localnet down                           # stops exactly the session vt-localnet; data kept in $VT_HOME/localnet
vt up --network local [--open] [--dev]     # waits for every readiness line; prints the page URL and the build id
vt status [--network local] [--json]       # page /__serve, relay status + Tor, API status: booleans, ids, locks only
vt preflight [--network local] [--json]   # the readiness table (same rows as the page's Status screen); exit 0 = ready
vt logs relay|api|page [--network local] [-n 50] [-f]
vt down --network local                    # kills exactly vt-local; removes up.json
vt backup import ~/Downloads/<backup>.age [--chain eth|sol]   # into $VT_HOME/backups/ (0600), never decrypted
```

- **testnet / mainnet** need the system Tor on `127.0.0.1:9050` (`vt.tor-required`). Mainnet starts only from a
  verified release (`vt.mainnet-dev-tree`).
- **mainnet job sends are enabled** in this build (the M2 flip, R78: `MAINNET_JOB_SENDS_ENABLED = true`): ETH and
  SOL jobs and their claw-backs, through every other gate (R76 funds present, typed words, caps, tickets, identity). Every
  other mainnet send stays locked (`MAINNET_SEND_ENABLED = false`: funding, Privacy Cash withdrawals, Turbo / Arweave,
  BTC, and the legacy `release` flow below). `vt status` prints `mainnet sends: locked  mainnet job sends: enabled`
  (`docs/vt.md`, "The M2 flip").
- **local: the Solana validator keeps its history.** `vt localnet up` runs `solana-test-validator` with
  `--limit-ledger-size 50000000` (and its ledger under `$VT_HOME/localnet/solana`); with the default ledger limit, old
  slots are pruned and explorer links to earlier transactions stop resolving. The validator listens on `:8999`
  (never `:8899`, the validator's default, which is left to any other local validator).
- **local: Chrome's "Apps on device" permission.** The local Solana explorer (explorer.solana.com on a custom cluster)
  reads the validator on this machine. Chrome 145 and later blocks that unless the explorer site is allowed the
  "Apps on device" permission (site settings, or the lock icon in the address bar); without it the explorer shows no
  data. `vt up --open` starts Chrome with its own profile (`$VT_HOME/chrome`), so grant it there once.

## 0.1 The canonical local flow (vt, one stack, no real funds)

The whole workflow on the `local` network, start to finish. Every command is `bin/vt`; in a development tree set
`VT_HOME` and `VAULT_TIMELOCK_DIR` to fresh temp directories first (agents always do). The operator's runbook for
testnet and mainnet is `docs/vt.md`.

1. **Chains.** `bin/vt localnet up` starts anvil (chain id 31337, `127.0.0.1:8545`), `solana-test-validator
   --limit-ledger-size 50000000` (`127.0.0.1:8999`), a regtest bitcoind (`:18443`, wallet `vt`, a miner window) with ord 0.29.0
   (`:8090`), and Otterscan (`:5100`, needs docker; `--no-otterscan` / `--no-btc` skip parts), writes the bitcoind
   credential the relay reads, and says per service whether it started or reused one. `bin/vt localnet status` shows them.
2. **Stack.** `bin/vt up --network local --open` waits for every readiness line, prints the page URL
   (`http://127.0.0.1:5180/`) and the build id, and opens Chrome with vt's own profile.
3. **Pre-flight.** `bin/vt preflight --network local` exits 0 (`--json` for the machine form). In a development tree the
   *Build id equal* and *Release verified* rows read `—  dev tree`; they are hard checks only on a release (mainnet
   needs one). The page's Status screen shows the same table.
4. **Keys and backups.** On the job form, create an ETH and a SOL lane key, **download** each backup
   (`vt-<chain>-key-<UTC>.age`), re-select it with its passphrase (`verifySavedFile` ✓) and tick. Then
   `bin/vt backup import ~/Downloads/vt-eth-key-….age` (and the SOL one): moved into `$VT_HOME/backups/`, never decrypted.
5. **Fund (local stand-ins).** `bin/vt localnet fund eth <eth lane address>` (1 ETH from anvil dev account 0),
   `bin/vt localnet fund sol <sol lane address>` (2 SOL airdrop on `:8999`), and for a BTC lane
   `bin/vt localnet fund btc <btc lane address>` (0.01 BTC, then a block). Each prints the transaction id.
6. **Job.** Create it on the page (the message field starts empty; **Load text file** for a long one), or
   `bin/vt job create job.json --message-file msg.txt` (you confirm the file's sha256 and type `publish`).
   `bin/vt job validate` checks a job file without a stack.
7. **Arm and run.** Arm on the page (a countdown of 1:00, `s`/Skip to shorten it), then **Run here**, or in a terminal:
   `bin/vt job run <id> --backup-eth ~/.local/state/vt/backups/eth/… --backup-sol …` (one passphrase prompt, asked by
   the broker; Ctrl-C detaches after the in-flight transaction, `bin/vt job stop <id>` stops the job).
   `bin/vt job status <id> --watch` follows either executor.
8. **Check.** Each part is read back; each copy shows "reassembled ✓". Read the text off the chain by hand with the job
   page's "Reassemble ETH/SOL by hand" command (`docs/vt.md`), or open the transaction in Otterscan (§1) and the local
   Solana explorer.
9. **Take back what is left.** `bin/vt job clawback <id> --chain eth --to <your address> --backup-eth …` (and `--chain sol`).
10. **Receipt and stop.** `bin/vt job receipt <id> --json > receipt.json`; `bin/vt down --network local`; and, when you are
    done with the chains, `bin/vt localnet down` (data is kept; `bin/vt localnet up` brings them back, `--reset` starts clean).

Takeover and recovery: run `bin/vt job run <id> …` from a second terminal while the first is stopped or killed (after 15 s
the lease lapses; the new executor reconciles from the chain first). `bin/vt job resolve` settles a STUCK transaction.
The automated version of this flow is `npm run test:integration` (real `vt job run` and `vt job clawback` against a
local stack on ephemeral ports).

## 1. Local (anvil + Otterscan; Ethereum publication only)

Publishes a synthetic package's note as an Ethereum Ethscription on a local anvil chain and shows it in
a local Etherscan-style explorer. No real funds. *Filled in by Task 25b* (`scripts/local-e2e.sh`).

1. Start anvil and Otterscan with `bin/vt localnet up` (anvil on `127.0.0.1:8545`, chain id 31337; Otterscan on
   `127.0.0.1:5100`). By hand they would be `anvil --chain-id 31337` and
   `docker run --rm -p 127.0.0.1:5100:80 -e ERIGON_URL=http://127.0.0.1:8545 otterscan/otterscan:v2.11.0`
   (the browser fetches the RPC, so the URL is the loopback one; both the variable **name** and the
   **value** are verified in Task 25b, as is anvil allowing the page's CORS origin: its default allows `*`).
3. Deposit ETH: `fund` (local profile) shows `D-railgun-eth`. Send ETH from an anvil dev account, e.g.
   `cast send <D> --value 1ether --private-key <anvil dev key 0> --rpc-url http://127.0.0.1:8545`
   (`local-e2e.sh` does this automatically). The `fund` output and the `cast send` form are verified in Task 25b.
4. The runner sees the deposit; the local-only `LocalDirectPoolAdapter` moves it from `D-railgun-eth` to
   the fresh `pub-<job>-eth` (journaled), and the job waits at `HELD`.
5. Run `release` (type `broadcast`, or pass `--local`; the `--local` flag is verified in Task 25b), with `--profile local --rpc eth=http://127.0.0.1:8545`. The
   runner sends the Ethscription note transaction from `pub-<job>-eth`.
6. Open `http://127.0.0.1:5100/tx/<hash>` and read the input data as text.

## 2. Testnet (Sepolia, Arbitrum/Base Sepolia, Solana devnet, Bitcoin testnet4)

**Held (R77): not maintained.** The same flow with faucet funds, over Tor, on the `testnet` profile. *Filled in by Task 25b.*

## 3. Mainnet (held until `release`)

Funding runs automatically after your deposit; every publication stays held until you run `release`
and type the confirmation. Nothing is public before then. *Filled in by Task 25b.* This legacy flow's sends stay behind
`MAINNET_SEND_ENABLED` (still false): the M2 flip lifted only the canonical `vt` job sends (§0).
