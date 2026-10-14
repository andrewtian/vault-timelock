# CLAUDE.md — vault-timelock

## ★ Never look at the contents of 1Password items

This binds every agent session and every subagent working in or for this repo. No task, test, review,
audit or debugging step is a reason to break it.

- **Never run `op` in any form, and never give yourself access to the `op` CLI**: no `op item …`,
  `op vault …`, `op read`, `op document …`, `op inject`, `op run`, `op signin`, no sign-in, desktop-app
  integration, service-account or Connect tokens, `OP_*` environment variables, or wrappers that would
  run `op` for you. Item titles are contents too.
- **Never read, print, grep, diff, hash-compare, decrypt or extract** anything that holds item
  contents: exported item JSON (`items/<id>.json`), attachments (`files/`), `restored/` directories,
  `vault.tar.gz` / `vault.tar.gz.age`, `identity.key`, or any real package in the output directory
  (`$VAULT_TIMELOCK_DIR`, default `~/.local/share/vault-timelock`). Do not even list their contents.
- **Never run `1password-timelock.sh seal` or `open` against a real vault or package** — only
  `--self-test`, which uses a synthetic fake `op` on `PATH` and a temporary `VAULT_TIMELOCK_DIR`.
- **Test data is synthetic only** (made-up item ids and values). Never copy, sample or "anonymize"
  real items into fixtures.
- **If a step needs a real vault or package** (sealing, re-sealing, opening, checking a size or
  count), stop and hand that step to the operator with the exact command; report only what the
  operator chooses to share.
- Subagent briefs must repeat this rule.
