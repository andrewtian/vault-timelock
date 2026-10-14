# broadcast/

Node (v24, native TypeScript type-stripping, no build) project for the Tor-confined
broadcaster and the funding runner. Code comments cite its design notes as spec B (broadcast)
and spec C (funding lifecycle); those notes are not part of this repository.

## Running it

Always through the wrapper, which scrubs the environment (`env -i`) and confines Node with
`sandbox-exec` (only Tor's SOCKS port and explicitly given loopback ports are reachable):

    bin/vt-broadcast tor-check                     # prints exactly: IsTor: true
    bin/vt-broadcast --profile local --rpc eth=http://127.0.0.1:8545 <command>

Networked commands prove their confinement first (`src/net/confine.ts`); measurements in
`feasibility/F5.txt`.

## Green criteria

    npm ci --ignore-scripts          # no package-lock.json diff
    npx tsc --noEmit                 # 0 errors
    npm run test:offline             # scripts/test-offline.sh: 0 fail, 0 skip in both phases
    node test/mutation/run.ts        # KILLED n/n

`npm run green` runs the last three. Versions are exact pins; tests use `node --test` only.
`scripts/test-offline.sh` runs the suite under `env -i` with a synthetic `HOME` (an empty temp dir)
and a loopback-only sandbox (the loopback relays denied: Tor's 9050 and 9150, Chrome DevTools 9222,
the E2EE sidecar 8931 and Ollama 11434; checked by a preflight and by the `suite-sandbox` sentinel
test, which is skipped only outside that phase), except the files that apply sandboxes themselves
(`confine`, `wrapper`, and the mutation runner's own test), which run in an unsandboxed second phase
(macOS cannot nest different sandbox profiles).

## Guards

Every refusal is one line:

    if (!ok) refuse('<guard-id>', '<message>') // @guard:<guard-id>

Guard ids match `^[a-z0-9]+(?:[.-][a-z0-9]+)*$`, appear on exactly one marker line under
`src/**/*.ts` or `bin/*` (in `bin/vt-broadcast` the marker sits in a shell comment), and are listed in `test/mutation/guards.json`
(`{ "<id>": ["test/offline/x.test.ts"] }`). Tests assert the guard id of a refusal.

The mutation runner blanks each marked line in a temp copy (node_modules symlinked), runs
the mapped tests, and requires them to fail (KILLED). Markers and `guards.json` must match one to one
(also checked statically by `test/offline/static-guards.test.ts`). The mapped tests run confined
like the suite: `env -i` (PATH HOME LANG TERM, HOME a fresh temp dir) under the suite sandbox profile
read from `scripts/test-offline.sh`, its unsandboxed-phase files unsandboxed; the `suite-sandbox`
sentinel runs first both ways, and the runner stops (`SENTINEL-FAILED`) unless it passes.

    node test/mutation/run.ts                       # full run: every guard (a task's closing commit)
    node test/mutation/run.ts --changed <git-base>  # targeted: the guards a change touches (fix rounds)
    node test/mutation/run.ts --only <id>[,<id>...] # just these guards
    node test/mutation/run.ts --jobs 1              # sequential; default --jobs min(8, CPUs - 1)

Each of the `--jobs` workers owns one temp copy of the project (copied once; no two workers share
one) and mutates it one guard at a time, writing the line back after the run; after every run the
copy is compared with the project (every file's mode and sha256) and re-made if a test changed it.
Each distinct set of mapped test files runs unmutated once, before any mutant (a set that fails:
`BASELINE-FAILED <id>` for its guards). The per-guard lines (KILLED / SURVIVED / TIMEOUT /
BASELINE-FAILED) are printed sorted by guard id, so two runs diff cleanly whatever `--jobs` was, then
`KILLED k/n` and the wall time. `--changed <git-base>` selects a guard when its marker line, its source
file, one of its mapped test files or its `guards.json` entry differs between `<git-base>` and the
working tree (untracked files included), prints each selected guard with the reasons, and runs only
those; nothing selected prints that and exits 0, and a git error is an ERROR (exit 1). It does not
follow imports, so a change to a shared helper selects nothing by itself: the closing commit of a task
runs the full run. `--root <dir>` points the runner at another project. `--timeout-ms` bounds each
mutated run, `--baseline-timeout-ms` each unmutated one (both 120 s).

`createStore(out, { fairGapMs })` (0..60) shortens the store's 60 ms fairness gap for tests that do
not test fairness; it refuses (`store.fair-gap`) unless `NODE_ENV=test`, which the wrapper never passes.

## On-chain text format (R32-R34)

Published text = two-line header (`vault-timelock/1 unlock=<ISO>\nar://<id>\n`, 94 B) + note + `\n\n` +
`SEALED.txt`. Ethereum prepends `data:,` (6 B). Caps: Arbitrum 94,000 B; Ethereum, Base, Bitcoin, Arweave
98,304 B (prefix included); each destination picks `full`, else `key-only`, else refuses. The Solana memo is
`header + note + "\nsha256:<hex>"` (at most 1,000 bytes, else `published.sol-too-long`); its `sha256:` line
is the SHA-256 of the text exactly as the 98,304 B no-prefix destinations (Base, Bitcoin, the Arweave item)
carry it in that publication (R41): header + note + `\n\n` + the `full` SEALED.txt if that fits 98,304 B,
else the `key-only` one. Tool-generated text is ASCII-only, and
`validate-note` warns on stderr (`warn note.non-ascii: ...`) when a note is not.

`seal-text --write` regenerates nothing automatically. A SEALED.txt written by the old format (its tools
line contains `·`) is refused with `sealed.exists-differs`; to replace it, delete the file, then re-run
`seal-text <pkgDir> --write`.

`seal-text` accepts packages sealed with `--armor` (Task S1): an `.age` file starting with
`-----BEGIN AGE ENCRYPTED FILE-----` is de-armored strictly (canonical only, else
`sealed.armor-noncanonical`) and the decoded binary is used throughout, so the SEALED.txt of an armored
package is byte-identical to the binary one's. The `ARMOR` marker and `unlock-KEY.age` (R45: never
published) are ignored; two-layer means `unlock-TIME.age` + `vault.tar.gz.age`. Every file of the
detected shape must parse as age (`sealed.not-age`), and `chain-info.json` must be drand quicknet
(`sealed.chain-info`). The `key-only` text adds step `1b. fetch ar://<arId> (a tar bundle) and extract
vault.tar.gz.age`.
