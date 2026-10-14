#!/bin/sh
# scripts/test-offline.sh — the offline suite (spec B §6.1; Task 7, 7b). Phase A: every test file
# but two, confined by the kernel to LOOPBACK ONLY (Tor's SOCKS ports denied). Phase B: the two
# files that apply sandboxes themselves, unsandboxed (see below).
# `npm run test:offline` runs this; the "green" criteria run through it.
#
# ─────────────────────────────────────────────────────────────────────────────────────────────
# ★★★ "OFFLINE" IS ENFORCED, NOT PROMISED. Phase A runs every test file under sandbox-exec with
#   outbound connections allowed to loopback ports only, so a test (or an SDK it loads) that
#   reaches for the internet gets EPERM instead of putting a packet on the wire. The fake SOCKS and
#   HTTP servers are loopback, so they still work.
#   Loopback relays are denied as well: they are loopback, but they ARE the internet. Tor's SOCKS
#   ports (9050, and 9150 for Tor Browser), and since Task H0 (audit SA-N1) the other loopback
#   listeners on this machine that forward to the internet: Chrome DevTools 9222 (drives the real
#   browser), the E2EE sidecar 8931 (forwards to a remote provider), Ollama 11434 (pulls models).
#   Measured (feasibility/F5.txt, H0 addendum): a port deny only takes effect written as "*:<port>"
#   AFTER the loopback allow ("localhost:9050" there is silently ignored), as ONE deny rule listing
#   every port, with "*:9050" as that rule's FIRST filter. With other first ports (9222, 9150, 9049,
#   9151, 12345, ... tried) some or all of the rule's ports were silently NOT denied. Keep 9050 first.
#   Nothing explains the quirk, so nothing is trusted: the preflight and the sentinel check every port.
#   Phase A also sets VT_SUITE_SANDBOX=1, and test/offline/suite-sandbox.test.ts then checks from
#   INSIDE the run that the environment is clean, HOME is synthetic, and TEST-NET-1 and every denied
#   port give EPERM (a sentinel: without the variable it is skipped). A skip would still let node
#   --test exit 0, so the sentinel also writes a marker to VT_SUITE_SENTINEL_FILE, and phase A fails
#   unless that file holds exactly the expected marker.
#   Both phases also write a TAP report, and a phase fails unless it shows 0 skipped and 0 todo.
#
# ★★ Phase B: the files that apply sandboxes THEMSELVES run outside the suite sandbox, because
#   macOS refuses to apply a different profile inside a sandbox (sandbox_apply EPERM, exit 71), and
#   their "unsandboxed" arm must really be unsandboxed (F5.txt). Since Task H0 that includes
#   test/mutation/runner.test.ts: the mutation runner it drives sandboxes its children with this very
#   profile. What they can reach:
#     · the 192.0.2.1:9 confinement probe under test (TEST-NET-1, never routed);
#     · loopback listeners they start themselves;
#     · nothing else: every wrapper they start is confined by the wrapper's own profile, and wherever
#       tor-check runs outside it, it runs under a profile that denies Tor's ports (and only them),
#       so even a mutated assertConfined() can't open a socket to Tor. confine.test.ts runs only
#       assertConfined, never the gate. The runner's children run under SUITE_PROFILE.
#   test/mutation/run.ts reads SUITE_PROFILE and OWN_SANDBOX from THIS file (one source): keep both
#   as single-quoted one-line assignments.
#
# ★ Both phases run under env -i (PATH HOME LANG TERM; phase A adds VT_SUITE_SANDBOX=1 and the
#   sentinel file): a provider key such as ALCHEMY_API_KEY, DEBUG, NODE_OPTIONS and npm's variables never
#   reach a test. HOME is synthetic, $TMPD/home, an empty directory removed on exit (Task H0, K31): no
#   test can write the real ~/.local/share/vault-timelock. Nothing in the suite needs the real HOME.
#
# Preflight, a negative control: inside the suite profile, a loopback listener must answer while
# 192.0.2.1:9 and every denied loopback port give EPERM. Otherwise the suite does not run. Probe
# order, so a broken profile never reaches a live listener: TEST-NET-1 first, then each port on
# [::1] before 127.0.0.1 (the relays listen on 127.0.0.1), stopping at the first answer that is
# not EPERM. Nothing is ever sent on a socket.
# ─────────────────────────────────────────────────────────────────────────────────────────────
set -eu
set -f
unset CDPATH

die() { printf 'test-offline: %s\n' "$*" >&2; exit 1; }

ROOT=$(cd -P "$(dirname "$0")/.." && pwd)
cd "$ROOT"
command -v sandbox-exec >/dev/null 2>&1 || die "sandbox-exec not found: the suite never runs unconfined"
command -v node >/dev/null 2>&1 || die "node not found"

# The denied ports: Tor 9050 (FIRST: see the banner), Tor Browser 9150, Chrome DevTools 9222, the
# E2EE sidecar 8931, Ollama 11434. The preflight and the sentinel check exactly these.
SUITE_PROFILE='(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))(deny network-outbound (remote ip "*:9050") (remote ip "*:9150") (remote ip "*:9222") (remote ip "*:8931") (remote ip "*:11434"))'
RELAY_PORTS='9050 9150 9222 8931 11434'
OWN_SANDBOX='test/offline/confine.test.ts test/offline/wrapper.test.ts test/mutation/runner.test.ts'
# test/offline/suite-sandbox.test.ts writes exactly this after passing in phase A.
SENTINEL_MARKER='sentinel: env clean, HOME synthetic, EPERM on 192.0.2.1:9 and loopback 9050 9150 9222 8931 11434'

TMPD=$(mktemp -d "${TMPDIR:-/tmp}/vt-test-offline.XXXXXX") || die "mktemp failed"
trap 'rm -rf "$TMPD"' EXIT
SENTINEL=$TMPD/sentinel
SYNTH_HOME=$TMPD/home
mkdir -m 700 "$SYNTH_HOME" || die "cannot create the synthetic HOME"

clean() { env -i PATH="$PATH" HOME="$SYNTH_HOME" LANG="${LANG:-en_US.UTF-8}" TERM="${TERM:-dumb}" "$@"; }
# Both phases run node --test with the usual spec output on the terminal plus a TAP copy
# (--test-reporter=tap --test-reporter-destination=<file>) to check the counts.
# no_skips <phase> <tap file>: the TAP summary must say 0 skipped and 0 todo.
no_skips() {
  if grep -qx '# skipped 0' "$2" && grep -qx '# todo 0' "$2"; then return 0; fi
  printf 'test-offline: phase %s skipped or left todo tests (green means 0 skip): %s\n' "$1" "$(grep -E '^# (skipped|todo) ' "$2" | tr '\n' ' ')" >&2
  return 1
}

# ── preflight ────────────────────────────────────────────────────────────────────────────────
# Prints "ok", or the first probe whose answer was wrong (and stops there: see the probe order above).
PREFLIGHT='
const net = require("node:net")
const attempt = (host, port) => new Promise((done) => {
  const s = net.connect({ host, port })
  const t = setTimeout(() => { s.destroy(); done("timeout") }, 2000)
  s.on("connect", () => { clearTimeout(t); s.destroy(); done("connected") })
  s.on("error", (e) => { clearTimeout(t); done(e.code || "error") })
})
const srv = net.createServer((c) => c.end())
srv.listen(0, "127.0.0.1", async () => {
  const want = [["127.0.0.1", srv.address().port, "connected"], ["192.0.2.1", 9, "EPERM"]]
  for (const p of process.argv.slice(1)) want.push(["::1", Number(p), "EPERM"], ["127.0.0.1", Number(p), "EPERM"])
  let out = "ok"
  for (const [host, port, expect] of want) {
    const got = await attempt(host, port)
    if (got !== expect) { out = host + ":" + port + "=" + got + " (want " + expect + ")"; break }
  }
  srv.close()
  console.log(out)
})'
# $RELAY_PORTS unquoted on purpose: a fixed list of numbers, one argument each.
got=$(clean sandbox-exec -p "$SUITE_PROFILE" node -e "$PREFLIGHT" $RELAY_PORTS 2>&1) || die "preflight did not run: $got"
[ "$got" = ok ] || die "the suite sandbox is not what it claims (want: loopback listener reachable; 192.0.2.1:9 and loopback $RELAY_PORTS EPERM; got $got)"
echo "test-offline: preflight ok (loopback reachable; 192.0.2.1 and loopback $RELAY_PORTS denied)"

# ── the file lists ───────────────────────────────────────────────────────────────────────────
for f in $OWN_SANDBOX; do [ -f "$f" ] || die "missing $f"; done
SUITE=
for f in $(find test/offline -name '*.test.ts' | sort) $(find test/mutation -maxdepth 1 -name '*.test.ts' | sort); do
  case $f in *[!A-Za-z0-9/._-]*) die "unexpected characters in a test file name: $f" ;; esac
  case " $OWN_SANDBOX " in *" $f "*) continue ;; esac
  SUITE="$SUITE $f"
done
[ -n "$SUITE" ] || die "no test files found"

# ── phase A: everything else, confined ───────────────────────────────────────────────────────
echo "test-offline: phase A (suite sandbox: loopback only, relay ports $RELAY_PORTS denied)"
if clean VT_SUITE_SANDBOX=1 VT_SUITE_SENTINEL_FILE="$SENTINEL" sandbox-exec -p "$SUITE_PROFILE" \
  node --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=tap --test-reporter-destination="$TMPD/a.tap" $SUITE; then a=0; else a=$?; fi
if [ "$(cat "$SENTINEL" 2>/dev/null)" = "$SENTINEL_MARKER" ]; then
  echo "test-offline: phase A sentinel ran and passed ($SENTINEL_MARKER)"
else
  echo "test-offline: phase A sentinel did not run and pass (suite-sandbox.test.ts): phase A is not green" >&2
  [ "$a" != 0 ] || a=1
fi
no_skips A "$TMPD/a.tap" || { [ "$a" != 0 ] || a=1; }

# ── phase B: the files that apply their own sandboxes ────────────────────────────────────────
echo "test-offline: phase B (files that apply their own sandbox: $OWN_SANDBOX)"
if clean node --test --test-reporter=spec --test-reporter-destination=stdout --test-reporter=tap --test-reporter-destination="$TMPD/b.tap" $OWN_SANDBOX; then b=0; else b=$?; fi
no_skips B "$TMPD/b.tap" || { [ "$b" != 0 ] || b=1; }

echo "test-offline: phase A exit $a, phase B exit $b"
[ "$a" = 0 ] && [ "$b" = 0 ]
