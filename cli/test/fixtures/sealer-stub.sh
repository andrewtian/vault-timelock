#!/bin/sh
# cli/test/fixtures/sealer-stub.sh — the only thing VT_SEALER may name (src/passthrough.ts, vt.sealer-stub-only):
# a stand-in for 1password-timelock.sh / timelock-key.sh in tests. It never touches 1Password or any package; it
# only reports, on stderr:
#   · the arguments it received, one per line;
#   · its environment variable NAMES (never values), read NUL-safe: newlines inside values become \001 first, then
#     each NUL ends a record, so only real names start one. This sh itself adds PWD and SHLVL (and may add OLDPWD
#     and _) before `env` runs; the tests discount exactly those;
#   · the values of TMPDIR and TOR_SOCKS (not secrets), so the tests can see they arrive intact.
# `exit-<n>` as the second argument makes it exit with <n> (exit-status propagation).
printf 'sealer-stub: argc=%s\n' "$#" >&2
for a in "$@"; do printf 'sealer-stub: arg=[%s]\n' "$a" >&2; done
names=$(env -0 | LC_ALL=C tr '\n\000' '\001\n' | LC_ALL=C sed -n 's/^\([^=]*\)=.*/\1/p' | LC_ALL=C sort | LC_ALL=C tr '\n' ' ')
printf 'sealer-stub: env=%s\n' "$names" >&2
printf 'sealer-stub: TMPDIR=[%s] TOR_SOCKS=[%s]\n' "${TMPDIR-<unset>}" "${TOR_SOCKS-<unset>}" >&2
case ${2-} in exit-[0-9]*) exit "${2#exit-}" ;; esac
exit 0
