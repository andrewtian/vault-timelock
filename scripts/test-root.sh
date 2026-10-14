#!/bin/sh
# scripts/test-root.sh — the canonical test runner (Task 0). One source of walls for every workspace:
#   sh scripts/test-root.sh <packages/core|api|cli|web|contract|contract-vectors|integration>
#
# ★★ CONFINED like broadcast's offline suite (one source: SUITE_PROFILE is read from broadcast/scripts/test-offline.sh
#   with the same single-quoted-line rule test/mutation/run.ts uses):
#   · phase A: every test file of the target except those listed in its own-sandbox.list, plus broadcast's sentinel
#     (test/offline/suite-sandbox.test.ts), under env -i (PATH HOME LANG TERM VT_SUITE_SANDBOX=1 VT_SUITE_SENTINEL_FILE)
#     with a synthetic empty HOME, inside sandbox-exec -p "$SUITE_PROFILE": loopback only, Tor and the other relay
#     ports denied, the internet denied;
#   · phase B: the own-sandbox files (tests that apply sandboxes themselves; macOS refuses nesting), unsandboxed, same
#     env minus the sentinel variables;
#   · web: the sentinel under node --test, then vitest under the same profile and env;
#   · green = every phase's TAP shows 0 failed, 0 skipped, 0 todo (and 0 cancelled), at least one test ran, and the
#     sentinel wrote exactly its marker. Anything else exits 1.
# ★ The install must be the one npm 11.21.0 makes (install-strategy=linked; npm 11.6.2's linked reifier links scoped
#   and file: packages wrongly). The links are checked first; a wrong link refuses with the exact fix command.
# Working directory: the workspace (packages/core, api, cli, web), so paths match the mutation runner's copies;
# `contract` and `contract-vectors` run in packages/core; `integration` runs at the repository root.
set -eu
set -f
unset CDPATH

die() { printf 'test-root: %s\n' "$*" >&2; exit 1; }

ROOT=$(cd -P "$(dirname "$0")/.." && pwd)
[ "$#" -eq 1 ] || die "usage: sh scripts/test-root.sh <packages/core|api|cli|web|contract|contract-vectors|integration>"
TARGET=$1
command -v sandbox-exec >/dev/null 2>&1 || die "sandbox-exec not found: the suite never runs unconfined"
command -v node >/dev/null 2>&1 || die "node not found"

# ── 1. the suite profile, from broadcast's script (one source) ─────────────────────────────────────────────────
OFFLINE=$ROOT/broadcast/scripts/test-offline.sh
SENTINEL_TEST=$ROOT/broadcast/test/offline/suite-sandbox.test.ts
[ -f "$OFFLINE" ] && [ -f "$SENTINEL_TEST" ] || die "broadcast's test-offline.sh or its sentinel test is missing"
SUITE_PROFILE=$(sed -n "s/^SUITE_PROFILE='\([^']*\)'\$/\1/p" "$OFFLINE")
n=$(printf '%s\n' "$SUITE_PROFILE" | grep -c . || true)
[ "$n" = 1 ] || die "cannot read exactly one SUITE_PROFILE line from broadcast/scripts/test-offline.sh"
case $SUITE_PROFILE in *'(deny network-outbound)'*) ;; *) die "SUITE_PROFILE lacks (deny network-outbound)" ;; esac
SENTINEL_MARKER=$(sed -n "s/^SENTINEL_MARKER='\([^']*\)'\$/\1/p" "$OFFLINE")
[ -n "$SENTINEL_MARKER" ] || die "cannot read SENTINEL_MARKER from broadcast/scripts/test-offline.sh"

# ── 2. the install (ruling 1: npm 11.21.0, linked) ──────────────────────────────────────────────────────────────
FIX="run at the repository root: npx --yes npm@11.21.0 ci --ignore-scripts   (then: cd broadcast && npm ci --ignore-scripts)"
link_is() { [ -L "$1" ] && [ "$(cd -P "$1" 2>/dev/null && pwd)" = "$2" ]; }
[ -d "$ROOT/node_modules/.store" ] || die "no linked install (node_modules/.store missing). Fix: $FIX"
for ws in api cli web; do
  link_is "$ROOT/$ws/node_modules/@vault-timelock/core" "$ROOT/packages/core" \
    || die "$ws/node_modules/@vault-timelock/core is not a link to packages/core (an install by another npm?). Fix: $FIX"
done
for ws in api cli; do
  link_is "$ROOT/$ws/node_modules/vt-broadcast" "$ROOT/broadcast" \
    || die "$ws/node_modules/vt-broadcast is not a link to broadcast/. Fix: $FIX"
done
[ -d "$ROOT/broadcast/node_modules" ] || die "broadcast/node_modules is missing. Fix: cd broadcast && npm ci --ignore-scripts"
link_is "$ROOT/broadcast/node_modules/@vault-timelock/core" "$ROOT/packages/core" \
  || die "broadcast/node_modules/@vault-timelock/core is not a link to packages/core (broadcast's dependency; run: cd broadcast && npx --yes npm@11.21.0 ci --ignore-scripts)"

# ── 3. what to run ─────────────────────────────────────────────────────────────────────────────────────────────
case $TARGET in
  packages/core|api|cli|web) WS=$TARGET; KIND=$TARGET ;;
  contract|contract-vectors) WS=packages/core; KIND=$TARGET ;;
  integration) WS=.; KIND=integration ;;
  *) die "unknown target (use packages/core, api, cli, web, contract, contract-vectors or integration)" ;;
esac
cd "$ROOT/$WS"

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vt-test-root.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$TMPD"' EXIT
SYNTH_HOME=$TMPD/home
mkdir -m 700 "$SYNTH_HOME" || die "cannot create the synthetic HOME"
SENTINEL=$TMPD/sentinel
clean() { env -i PATH="$PATH" HOME="$SYNTH_HOME" LANG="${LANG:-en_US.UTF-8}" TERM="${TERM:-dumb}" "$@"; }

# own-sandbox list: one path per line, '#' comments; every path must exist and use safe characters.
OWN=
OWN_LIST=test/own-sandbox.list
[ "$KIND" = integration ] && OWN_LIST=test/integration/own-sandbox.list
if [ -f "$OWN_LIST" ]; then
  for f in $(sed -e 's/#.*//' "$OWN_LIST"); do
    case $f in *[!A-Za-z0-9/._-]*) die "unexpected characters in $OWN_LIST: $f" ;; esac
    [ -f "$f" ] || die "$OWN_LIST names a missing file: $f"
    OWN="$OWN $f"
  done
fi

list_tests() { # <dir> <find -name patterns...>
  d=$1; shift
  [ -d "$d" ] || return 0
  find "$d" -type f \( "$@" \) | sort
}
case $KIND in
  packages/core|api|cli) FILES=$(list_tests test -name '*.test.ts' -o -name '*.test.js' -o -name '*.test.mjs') ;;
  contract)
    FILES=contract/static.contract.test.ts
    # npm run contract = static, plus the vectors once the job module (E1) exists in this tree (I1 onwards).
    if [ -f src/job/index.ts ]; then FILES="$FILES $(list_tests contract/vectors -name '*.contract.test.ts')"; fi ;;
  contract-vectors) FILES=$(list_tests contract/vectors -name '*.contract.test.ts') ;;
  integration) FILES=$(list_tests test/integration -name '*.test.ts') ;;
  web) FILES= ;;
esac
SUITE=
for f in $FILES; do
  case $f in *[!A-Za-z0-9/._-]*) die "unexpected characters in a test file name: $f" ;; esac
  case " $OWN " in *" $f "*) continue ;; esac
  SUITE="$SUITE $f"
done
[ "$KIND" = web ] || [ -n "$SUITE$OWN" ] || die "no test files for $TARGET"

# tap_ok <phase> <tap file>: node --test's TAP summary must show fail/cancelled/skipped/todo 0 and tests >= 1.
tap_ok() {
  for k in fail cancelled skipped todo; do
    grep -qx "# $k 0" "$2" || { printf 'test-root: phase %s: TAP does not show "# %s 0" (%s)\n' "$1" "$k" "$(grep -E '^# (tests|pass|fail|cancelled|skipped|todo) ' "$2" | tr '\n' ' ')" >&2; return 1; }
  done
  t=$(sed -n 's/^# tests \([0-9][0-9]*\)$/\1/p' "$2")
  [ -n "$t" ] && [ "$t" -ge 1 ] || { printf 'test-root: phase %s: no tests ran\n' "$1" >&2; return 1; }
  printf 'test-root: phase %s: %s\n' "$1" "$(grep -E '^# (tests|pass|fail|skipped|todo) ' "$2" | tr '\n' ' ')"
}
sentinel_ok() {
  if [ "$(cat "$SENTINEL" 2>/dev/null)" = "$SENTINEL_MARKER" ]; then echo "test-root: sentinel ran and passed ($SENTINEL_MARKER)"; return 0; fi
  echo "test-root: the sentinel did not run and pass: not green" >&2; return 1
}
a=0; b=0
if [ "$KIND" = web ]; then
  # ── web: sentinel (node --test) + vitest, both inside the suite sandbox ─────────────────────────────────────
  echo "test-root: web phase A (suite sandbox): sentinel, then vitest"
  clean VT_SUITE_SANDBOX=1 VT_SUITE_SENTINEL_FILE="$SENTINEL" sandbox-exec -p "$SUITE_PROFILE" \
    node --test --test-reporter=spec --test-reporter=tap --test-reporter-destination=stdout --test-reporter-destination="$TMPD/s.tap" "$SENTINEL_TEST" || a=1
  sentinel_ok || a=1
  tap_ok sentinel "$TMPD/s.tap" || a=1
  [ -f node_modules/vitest/vitest.mjs ] || die "vitest is not installed in web/. Fix: $FIX"
  if clean VT_SUITE_SANDBOX=1 sandbox-exec -p "$SUITE_PROFILE" node node_modules/vitest/vitest.mjs run --reporter=tap-flat > "$TMPD/w.tap" 2> "$TMPD/w.err"; then :; else a=1; fi
  cat "$TMPD/w.tap"
  [ -s "$TMPD/w.err" ] && sed 's/^/vitest: /' "$TMPD/w.err" >&2
  plan=$(sed -n 's/^1\.\.\([0-9][0-9]*\)$/\1/p' "$TMPD/w.tap" | head -n 1)
  okc=$(grep -c '^ok ' "$TMPD/w.tap" || true)
  notok=$(grep -c '^not ok ' "$TMPD/w.tap" || true)
  skip=$(grep -ciE '^(not )?ok .*# (skip|todo)' "$TMPD/w.tap" || true)
  if [ -n "$plan" ] && [ "$plan" -ge 1 ] && [ "$notok" = 0 ] && [ "$skip" = 0 ] && [ "$okc" = "$plan" ]; then
    echo "test-root: phase vitest: tests $plan pass $okc fail 0 skipped 0 todo 0"
  else
    echo "test-root: phase vitest: plan ${plan:-none}, ok $okc, not ok $notok, skip/todo $skip: not green" >&2; a=1
  fi
else
  # ── phase A: confined ──────────────────────────────────────────────────────────────────────────────────────
  echo "test-root: $TARGET phase A (suite sandbox: loopback only, relay ports denied):$SUITE + sentinel"
  # shellcheck disable=SC2086
  if clean VT_SUITE_SANDBOX=1 VT_SUITE_SENTINEL_FILE="$SENTINEL" sandbox-exec -p "$SUITE_PROFILE" \
    node --test --test-reporter=spec --test-reporter=tap --test-reporter-destination=stdout --test-reporter-destination="$TMPD/a.tap" $SUITE "$SENTINEL_TEST"; then :; else a=1; fi
  sentinel_ok || a=1
  tap_ok A "$TMPD/a.tap" || a=1
  # ── phase B: own sandboxes, unsandboxed ────────────────────────────────────────────────────────────────────
  if [ -n "$OWN" ]; then
    echo "test-root: $TARGET phase B (files that apply their own sandbox):$OWN"
    # shellcheck disable=SC2086
    if clean node --test --test-reporter=spec --test-reporter=tap --test-reporter-destination=stdout --test-reporter-destination="$TMPD/b.tap" $OWN; then :; else b=1; fi
    tap_ok B "$TMPD/b.tap" || b=1
  else
    echo "test-root: $TARGET phase B: none (own-sandbox list empty)"
  fi
fi

echo "test-root: $TARGET phase A exit $a, phase B exit $b"
[ "$a" = 0 ] && [ "$b" = 0 ]
