#!/bin/sh
# timelock-key.sh — seal a secret to a drand round: no one can open the package before that round
# unless t of drand quicknet's key shares are combined (collusion, theft or compulsion) or
# BLS12-381 is broken (e.g. by a quantum computer); then delete a source FILE (a directory source
# is kept; symlinks, hard-linked files and special files are refused).
#
#   sh tools/timelock-key.sh seal <path|-> [DURATION] [--armor] [--clearnet] [--jitter DURATION]   # `-` = stdin
#   sh tools/timelock-key.sh open <package-dir> [--clearnet]   # works only after the round
#   sh tools/timelock-key.sh duration <DURATION>       # print its seconds; no network
#   sh tools/timelock-key.sh --self-test               # real 60 s seals through Tor: refuse before their round, open after (tests the pipeline, not a given package)
#   DURATION: a bare number of YEARS (default 10), or N<unit> terms in the order y d h m s:
#   30d, 1h, 40m, 365d, 1y30d, 1d12h, 90s (m = minutes, no month unit; at most 100y)
#   --armor: the sealed file is written ASCII-armored (PEM); `open` reads either form
#   packages land in ${VAULT_TIMELOCK_DIR:-${XDG_DATA_HOME:-~/.local/share}/vault-timelock}/
#   (never the cwd); `open` also accepts a bare package name from there. `-` seals stdin raw.
#   drand is reached ONLY through Tor (127.0.0.1:9050); --clearnet is the explicit opt-out (R40)
#   --jitter: the maximum random offset added to the round (default min(24h, DURATION/10); 0 = none)
#   every seal ends by writing SEALED.txt (the self-contained text to publish) with vt-broadcast
#   no --plaintext here (Task SP): `open` already restores the sealed file or directory itself, which IS
#   the plaintext (1password-timelock.sh open --plaintext writes SEALED-plaintext.txt for a vault)
#
# ─────────────────────────────────────────────────────────────────────────────────────────────
# ★★★ WHAT THIS RELIES ON, BECAUSE THE CRYPTOGRAPHY IS NOT THE WEAK PART
#
# There is no way to make a file undecryptable-until-a-date with local computation alone. A date is
# not a secret; anything you can compute now, an attacker can compute now. Every real scheme borrows
# the passage of time from something outside your machine, and the only question worth asking is
# what that something is and whether it will still be there.
#
# This uses **drand timelock encryption (tlock)** on the League of Entropy `quicknet` chain. drand
# emits a threshold BLS signature every 3 seconds. tlock encrypts to a future ROUND; the decryption
# key IS the signature at that round. Fewer than t key shares cannot produce it early (under
# BLS12-381's assumptions); t or more shares together can, at any time and without trace, whether
# their holders collude or the shares are stolen or compelled, and shares from before a reshare count.
#
# ★★ THE BET IS THEREFORE: *does the League of Entropy still run this chain, with this public key,
# in ten years?* For AVAILABILITY that is a network-survival bet, and it is the thing most likely to
# fail. CONFIDENTIALITY before the date is a separate bet: that fewer than t key shares are ever
# combined and that BLS12-381 holds, which a large quantum computer would end (docs/CRYPTO.md). quicknet's genesis is 2023-08-23. **Ten years is a long time to ask of any
# infrastructure, which is why §4 of the generated README describes a second, human path.**
#
# ★ REJECTED, and why:
#   · **Sequential-work puzzles / VDFs** (Rivest LCS35) — trustless, needs nobody. But you calibrate
#     in squarings-per-second on TODAY's hardware. Rivest's own 35-year puzzle fell in 2 months to a
#     better implementation. **Over a decade the calibration error exceeds the horizon.**
#   · **An executor, a lawyer, a safe-deposit box** — not a timelock, a person. Good as a SECOND
#     path, useless as the only one.
#   · **A cloud KMS key with a scheduled policy** — a vendor's access control, changeable by that
#     vendor, a court, or whoever holds the account in ten years.
# ─────────────────────────────────────────────────────────────────────────────────────────────
set -eu
unset CDPATH   # every `cd "$(dirname ...)"` below must go exactly there, silently

CHAIN=52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971   # drand quicknet
GENESIS=1692803367; PERIOD=3   # quicknet's genesis_time and period: what turns a round into a UTC time
MIRRORS="https://api.drand.sh https://api2.drand.sh https://api3.drand.sh"
# the archive scrub (Task S2 §2), IDENTICAL in both tools: ustar (no pax records, so no xattrs), no
# mac metadata / xattrs / ACLs / file flags, every entry owned by 0/0 nobody/nobody. Unquoted on use.
TAR_SCRUB='--format ustar --no-mac-metadata --no-xattrs --no-acls --no-fflags --uid 0 --gid 0 --uname nobody --gname nobody'   # @mut:scrub
# timelock-key.sh only: bsdtar's own gzip, no MTIME (it streams; 1password-timelock.sh gzips a file)
TAR_GZIP='--options gzip:!timestamp,gzip:compression-level=9'   # @mut:gzip
# Where packages go: the same data dir as 1password-timelock.sh (and Part A's publish), never the cwd
# (audit SA-N10): a package written wherever the shell happened to be standing is one nobody finds.
OUT=${VAULT_TIMELOCK_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/vault-timelock}
# vt-broadcast writes SEALED.txt at the end of every seal (Task S2 §5): the repo's own broadcast/
# tool beside this script, or VT_BROADCAST (the self-test points it at the repo's copy)
VTB=${VT_BROADCAST:-$(cd "$(dirname "$0")" && pwd)/broadcast/bin/vt-broadcast}

die() { printf '%s\n' "$*" >&2; exit 1; }

TLE=${TLE:-tle}
# ★ tle v1.2.0 ONLY accepts long flags with `=`. `-c X -r N -o F` fails with the misleading
#   "only one of -m/-d/-e must be passed". Measured 2026-09-19; do not "simplify" these.
need() {
  command -v "$TLE" >/dev/null 2>&1 || die \
"tle is missing, and it performs the sealing. It is drand's OWN timelock CLI:

  go install github.com/drand/tlock/cmd/tle@v1.2.0

(not in brew as of 2026-09; set TLE=/path/to/tle to use a build elsewhere).
Chosen over third-party age plugins deliberately: \`tle\` is maintained by the same
project that runs the beacon, so the tool and the chain retire together or not at all."
  tar --version 2>/dev/null | grep -q bsdtar || die "tar is not bsdtar (macOS /usr/bin/tar): the archive scrub uses bsdtar's flags"
  command -v node >/dev/null 2>&1 || die "node is not installed (v24, https://nodejs.org): the seal serves the pinned drand chain info to tle on loopback"
  command -v jq >/dev/null 2>&1 || die "jq is not installed (macOS has /usr/bin/jq; else brew install jq): drand's chain info is parsed as JSON"
}

# ── ★★ DRAND, ONLY THROUGH TOR (operator R40; Task S1 §6; audit K18, SA-N6, SA-N8) ─────────────
#    IDENTICAL in 1password-timelock.sh and timelock-key.sh (each self-test compares the functions).
#    WHY: `tle --decrypt` asks drand for the EXACT future round (GET /<chain>/public/<round>) before
#    it can say "too early", and a later publication prints that round. Over clearnet the request
#    ties this machine's IP to the package for good. So every drand request goes through Tor's SOCKS
#    port as role "drand.<UTC minute>" (IsolateSOCKSAuth: its own circuit, rotated each minute), and
#    nothing runs if Tor does not answer. `--clearnet` is the one, named opt-out; a package sealed
#    with it is re-sealed over Tor before any publication (R40).
#      · curl: socks5h:// (names resolve INSIDE Tor; socks5:// would leak DNS) and --noproxy '', so a
#        NO_PROXY in the environment cannot exempt a host.
#      · tle (Go): HTTPS_PROXY and https_proxy = the same socks5h:// URL (measured 2026-10-09: tle
#        v1.2.0 accepts socks5h://), with NO_PROXY/no_proxy REMOVED: Go skips the proxy for any host
#        they list, and NO_PROXY=* would mean "go direct".
#      · quicknet is PINNED (SA-N8; Task S2 §3): the fetched info must carry exactly CHAIN, GENESIS,
#        PERIOD, PUBKEY and SCHEME, so no mirror or exit node can move the unlock time by serving
#        other parameters. The chain hash binds period, genesis, public key, group hash and beacon
#        id, NOT the scheme (drand common/chain/info.go; expert review E4).
#      · ★ tle ENCRYPTS WITH THE PINNED PARAMETERS, not its own fetch (E4). tle takes the scheme
#        from its OWN GET /<chain>/info and checks only the chain hash there (measured 2026-10-09,
#        tle v1.2.0 against a loopback server: a wrong period is refused, "does not advertise the
#        expected drand group"; a hash-valid info saying bls-unchained-on-g1 is ACCEPTED and tle
#        encrypts to an identity drand never signs). So the seal serves the pinned, checked
#        chain-info.json to tle from 127.0.0.1 (info_serve; node, loopback only, that one path) and
#        encrypts with --network=http://127.0.0.1:<port>. Encrypting makes no drand request at all.
#      · the negative control is LOCAL first (assert_future: the pinned parameters and the clock),
#        then drand itself through Tor (assert_shut): tle's "too early" on the file exactly as
#        written, AND the relay's HTTP 425 for the round (tle calls any fetch failure "too early").
#    The lines marked "@mut:" are disabled one at a time by the self-test's mutation arms.
CLEARNET=0
TOR_SOCKS=127.0.0.1:9050
# PUBKEY and SCHEME: as served by https://api.drand.sh/52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971/info,
# fetched through Tor on 2026-10-09 (its hash recomputes to CHAIN)
PUBKEY=83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a
SCHEME=bls-unchained-g1-rfc9380
GROUPHASH=f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e
# INFO_PINNED: quicknet's chain info, canonical (jq -cS), built from the pins alone. It is what tle is
# served and what chain-info.json holds: the fetched bytes are only COMPARED with it (S2 re-review I-1;
# the self-test recomputes CHAIN from these fields)
INFO_PINNED='{"genesis_time":'"$GENESIS"',"groupHash":"'"$GROUPHASH"'","hash":"'"$CHAIN"'","metadata":{"beaconID":"quicknet"},"period":'"$PERIOD"',"public_key":"'"$PUBKEY"'","schemeID":"'"$SCHEME"'"}'
MARGIN_ROUNDS=5   # the local control's margin: 5 rounds = 15 s of clock skew
drand_proxy() {
  echo "socks5h://drand.$(date -u +%Y%m%dT%H%MZ):x@$TOR_SOCKS"
}
tor_preflight() {
  if [ "$CLEARNET" = 1 ]; then
    echo "  ★ --clearnet: drand is contacted DIRECTLY, not through Tor. drand (and its CDN) see this IP ask for this round; re-seal over Tor before publishing (R40)."
    return 0
  fi
  command -v nc >/dev/null 2>&1 || die "nc is missing: it checks that Tor's SOCKS port answers before any drand request"
  _ts=$(printf '\005\001\000' | nc -w 5 "${TOR_SOCKS%:*}" "${TOR_SOCKS#*:}" 2>/dev/null | od -An -tx1 | tr -d ' \n') || _ts=
  [ "$_ts" = 0500 ] || die "★ Tor is not answering on $TOR_SOCKS (no SOCKS5 reply). drand is reached ONLY through Tor (R40): start tor, or pass --clearnet to contact drand directly (then re-seal over Tor before publishing)."   # @mut:tor-preflight
  echo "  drand      through Tor ($TOR_SOCKS, socks5h, role drand.<UTC minute>); quicknet pinned"
}
drand_curl() {
  if [ "$CLEARNET" = 1 ]; then curl -fsS --max-time 30 "$1"; return; fi
  curl -fsS --max-time 60 --retry 2 --noproxy '' --proxy "$(drand_proxy)" "$1"   # @mut:curl-proxy
}
tle_env() {
  if [ "$CLEARNET" = 1 ]; then "$TLE" "$@"; return; fi
  _tp=$(drand_proxy)
  env -u NO_PROXY -u no_proxy HTTPS_PROXY="$_tp" https_proxy="$_tp" "$TLE" "$@"   # @mut:tle-proxy
}
tle_net() {
  # tle_net ARGS: tle_env with up to 3 attempts on a NETWORK error (Tor circuits are slow to build).
  # Its input must be a FILE argument, never stdin: a retry would read a consumed stdin as EMPTY.
  eval "_tf=\${$#}"
  [ -f "$_tf" ] || die "tle_net: the input must be a file argument, not stdin"
  _ta=1
  while :; do
    if _te=$(tle_env "$@" 2>&1 </dev/null); then return 0; fi
    case $_te in
      *"doing request"*|*"TLS handshake timeout"*|*"deadline exceeded"*) [ "$_ta" -lt 3 ] || break ;;
      *) break ;;
    esac
    _ta=$((_ta + 1)); sleep 3
  done
  printf '%s\n' "$_te" >&2
  return 1
}
# chain_info: GET /<CHAIN>/info through Tor, checked against the pins, and the PINNED bytes returned.
# The fetched body must be exactly ONE JSON value (jq -n '[inputs]'), repeat no key (jq --stream sees
# every occurrence) and be EQUAL, as a JSON value, to INFO_PINNED: no extra key, no key differing only
# in case (drand's Go decoder folds case and reads the first value: a "schemeid" beside "schemeID", or
# a second document, would make it read something jq never checked; S2 re-review I-1). It then prints
# INFO_PINNED itself, never the fetched bytes: chain-info.json and what tle is served are the constant.
chain_info() {
  for h in $MIRRORS; do
    if _ci=$(drand_curl "$h/$CHAIN/info" 2>/dev/null); then
      _cn=$(printf '%s' "$_ci" | jq -n '[inputs] | length' 2>/dev/null) || _cn=
      [ "$_cn" = 1 ] || die "★ drand chain info from $h is not exactly one JSON value: refusing (a checker and tle could read different values)"   # @mut:pin-one
      _cd=$(printf '%s' "$_ci" | jq -n --stream '[inputs | select(length == 2) | .[0]] | length > 0 and length == (unique | length)' 2>/dev/null) || _cd=
      [ "$_cd" = true ] || die "★ drand chain info from $h is not JSON, or repeats a key: refusing (a checker and tle could read different values)"   # @mut:pin-dup
      printf '%s' "$_ci" | jq -e --argjson w "$INFO_PINNED" '. == $w' >/dev/null 2>&1 || die "★ drand chain info from $h does not match pinned quicknet exactly (hash, genesis_time, period, public_key, schemeID, groupHash, beaconID, and no other key). Refusing: the unlock time would rest on parameters nobody pinned."   # @mut:pin
      printf '%s' "$INFO_PINNED"; return 0
    fi
  done
  die "no drand mirror answered$( [ "$CLEARNET" = 1 ] || echo ' through Tor' )"
}
assert_future() {
  # the LOCAL negative control: no network, only the pinned parameters and the clock
  _cur=$(( ($(date -u +%s) - GENESIS) / PERIOD + 1 ))
  [ "$1" -gt $(( _cur + MARGIN_ROUNDS )) ] || die "★ REFUSING: round $1 is not safely in the future (current round $_cur; it must be more than $MARGIN_ROUNDS rounds = $(( MARGIN_ROUNDS * PERIOD )) s ahead). Nothing would be locked."   # @mut:local-control
}
# info_serve DIR: serve DIR/chain-info.json (the pinned, checked info) to tle as GET /<CHAIN>/info on
# 127.0.0.1:<ephemeral port>, 404 for anything else; sets INFO_PORT and INFO_PID. node (env -i, no
# NODE_OPTIONS) exits by itself after 10 minutes; info_stop ends it, and so do the traps.
info_serve() {
  rm -f "$1/.info-port"
  env -i PATH="$PATH" HOME="$HOME" node -e '
    const fs = require("fs"), http = require("http")
    const [file, chain, portFile] = process.argv.slice(1)
    const body = fs.readFileSync(file)
    const srv = http.createServer((q, r) => {
      if (q.method === "GET" && q.url === `/${chain}/info`) { r.writeHead(200, { "content-type": "application/json", "content-length": body.length }); r.end(body) }
      else { r.writeHead(404); r.end() }
    })
    srv.listen(0, "127.0.0.1", () => fs.writeFileSync(portFile, String(srv.address().port)))
    setTimeout(() => process.exit(0), 600000).unref()' "$1/chain-info.json" "$CHAIN" "$1/.info-port" </dev/null >/dev/null 2>&1 &
  INFO_PID=$!
  _iw=0
  while [ ! -s "$1/.info-port" ] && [ "$_iw" -lt 100 ]; do sleep 0.1; _iw=$((_iw + 1)); done
  INFO_PORT=$(cat "$1/.info-port" 2>/dev/null) || INFO_PORT=
  rm -f "$1/.info-port"
  case $INFO_PORT in ''|*[!0-9]*) info_stop; die "★ could not start the loopback chain-info server (node): refusing to let tle fetch the parameters itself" ;; esac
}
info_stop() { if [ -n "${INFO_PID:-}" ]; then kill "$INFO_PID" 2>/dev/null || true; wait "$INFO_PID" 2>/dev/null || true; fi; INFO_PID=; }
# drand_status ROUND: the HTTP status of GET /<CHAIN>/public/<ROUND>, through Tor; mirrors in order
# until one answers; 000 when none does. if/else, never `a && b || c`: a curl whose -w output was
# printed must not run a second curl after it (expert review m9).
drand_status() {
  for h in $MIRRORS; do
    if [ "$CLEARNET" = 1 ]; then _hc=$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "$h/$CHAIN/public/$1") || _hc=000
    else _hc=$(curl -s -o /dev/null -w '%{http_code}' --max-time 60 --retry 2 --noproxy '' --proxy "$(drand_proxy)" "$h/$CHAIN/public/$1") || _hc=000; fi   # @mut:status-proxy
    case $_hc in ''|000) continue ;; esac
    echo "$_hc"; return 0
  done
  echo 000
}
assert_shut() {
  # assert_shut FILE ROUND: drand itself, through Tor, twice; any other outcome fails closed: SHUT is
  # shown, never inferred from an error. (1) tle --decrypt of FILE exactly as written must fail
  # with "too early" (it parses as a tlock age file for this chain, and U decodes in G2). But tle
  # v1.2.0 reports ANY failure to fetch the round's signature as "too early" (a timeout, a 5xx, a
  # Tor failure: tlock_age.go Unwrap; claims review F-3), so (2) the relay must answer
  # GET /<chain>/public/<ROUND> with HTTP 425 Too Early: its own, unauthenticated statement, by
  # its own clock, that it has no signature for the round yet (expert review m9).
  if _sh=$(tle_net --decrypt --output=/dev/null "$1" 2>&1); then die "★ REFUSING: $1 OPENS RIGHT NOW. Its round is not in the future; nothing is locked."; fi   # @mut:drand-control
  case $_sh in *"too early"*) ;; *) die "★ could not confirm through drand that $1 is shut: $_sh" ;; esac   # @mut:drand-reason
  _hs=$(drand_status "$2")
  [ "$_hs" = 425 ] || die "★ REFUSING: drand did not answer HTTP 425 (Too Early) for round $2$( [ "$CLEARNET" = 1 ] || echo ' through Tor' ): HTTP $_hs$( [ "$_hs" != 000 ] || echo ' (no answer: a network or Tor failure)' ). Shut must be shown, not inferred from an error."   # @mut:drand-425
}
# ── ★ THE RANDOM OFFSET: the round must not date the seal (Task S2 §6; expert review E6) ────────
#    R = round_for(now + L) with a guessable duration L (10 y, or any whole number of units) gives
#    t(R) − L = the sealing instant to within 3 s, to be matched against 1Password's server-side
#    record of the export, drand relay logs and the upload time. So the target is now + L + J, with
#    J uniform in [0, Jmax] from the OS CSPRNG (/dev/urandom, 4 bytes per try, rejection sampling:
#    no modulo bias), drawn once and never printed: the outputs print t(R) (true) and Jmax. Default
#    Jmax = min(24 h, L/10), scale-free: 10 y and 30d -> 24 h, 1h -> 6 min, 10m -> 1 min. --jitter
#    <DURATION> sets Jmax (not above L); --jitter 0 disables it, with a warning. TL_TEST_SECONDS
#    (self-test) has no offset; TL_JITTER_SOURCE (self-test seam) replaces /dev/urandom.
#    (The seal's own drand requests for round R, through Tor, are made at the sealing moment: a
#    relay log still sees WHEN round R was asked for. The offset removes the arithmetic link only.)
jitter_default() { _jd=$(( $1 / 10 )); [ "$_jd" -le 86400 ] || _jd=86400; echo "$_jd"; }
jitter_draw() {
  _jn=$(( $1 + 1 )); _jl=$(( 4294967296 / _jn * _jn )); _jt=0
  while :; do
    _jr=$(od -An -N4 -tu4 < "${TL_JITTER_SOURCE:-/dev/urandom}" | tr -d ' \n')
    case $_jr in ''|*[!0-9]*) die "could not read 4 random bytes for the round offset" ;; esac
    [ "$_jr" -ge "$_jl" ] || break
    _jt=$((_jt + 1)); [ "$_jt" -lt 64 ] || die "the random source kept giving rejected values (TL_JITTER_SOURCE?)"
  done
  echo $(( _jr % _jn ))
}
# dur_text SECONDS: d h m s terms, never y (a README must not say "year"): 86400 -> 1d, 360 -> 6m
dur_text() {
  _ds=$1; _do=
  [ $(( _ds / 86400 )) = 0 ] || _do="$_do$(( _ds / 86400 ))d"; _ds=$(( _ds % 86400 ))
  [ $(( _ds / 3600 )) = 0 ] || _do="$_do$(( _ds / 3600 ))h"; _ds=$(( _ds % 3600 ))
  [ $(( _ds / 60 )) = 0 ] || _do="$_do$(( _ds / 60 ))m"; _ds=$(( _ds % 60 ))
  [ "$_ds" = 0 ] || _do="$_do${_ds}s"
  echo "${_do:-0s}"
}
# jitter_setup: after SECS/REQ, before sealing. Sets JMAX and extends REQ (never with J itself).
jitter_setup() {
  JMAX=0
  if [ -n "${TL_TEST_SECONDS:-}" ]; then return 0; fi
  if [ "$JIT_ARG" = 0 ]; then
    REQ="$REQ (no random offset: --jitter 0)"
    echo "  ★ --jitter 0: no random offset. The round then gives away the moment of sealing to within 3 s (unlock time minus the duration), to be matched with 1Password's server-side record of the export, drand relay logs and the upload time."
    return 0
  fi
  if [ -n "$JIT_ARG" ]; then JMAX=$(duration_seconds "$JIT_ARG") || exit 1
    [ "$JMAX" -le "$SECS" ] || die "--jitter $JIT_ARG ($JMAX s) is longer than the duration ($SECS s): an offset is not a second duration"
  else JMAX=$(jitter_default "$SECS"); fi
  [ "$JMAX" = 0 ] || REQ="$REQ (+ random offset up to $(dur_text "$JMAX"))"
  [ -z "${TL_JITTER_SOURCE:-}" ] || REQ="$REQ; offset drawn from TL_JITTER_SOURCE (self-test)"
}
# Round 1 lands at genesis, so round N is at genesis + (N-1)*period.
# Inverting: floor((T-genesis)/period) + 1 is the LAST round at or before T (at most period-1 s
# early), i.e. the round drand publishes in the same period as T.
round_for() { echo $(( ($1 - $2) / $3 + 1 )); }
# a round's UTC time, YYYY-MM-DDTHH:MM:SSZ: round N lands at genesis + (N-1)*period
iso_of() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
round_iso() { iso_of $(( GENESIS + ($1 - 1) * PERIOD )); }
# round_of DIR: the round as `open` prints it. A package may come from anywhere (a fetched bundle is
# untrusted text), so DIR/round is printed only when it is a round number (1-16 digits, no leading
# zero: seal-text's sealed.round), never raw (Task S1 review). IDENTICAL in both tools.
round_of() {
  _rf=$(head -c 64 "$1/round" 2>/dev/null) || _rf=
  case $_rf in ''|0*|*[!0-9]*|?????????????????*) _rf="(invalid round file)" ;; esac   # @mut:round-text
  echo "$_rf"
}

# ── ★ THE DURATION GRAMMAR (Task S1 §1: terms such as 30d, 1h, 40m, 365d) ──────────
#    IDENTICAL in 1password-timelock.sh and timelock-key.sh: each --self-test extracts this function
#    from BOTH files and requires the two texts to be byte-identical, so the tools cannot drift apart.
#    It is also the contract for Part D's parseDuration (D-R26).
#      N            a bare number = N YEARS (backward compatible: `seal Private 10`)
#      N<unit>...   the sum of the terms, no spaces, each unit at most once, in the order y d h m s:
#                   y = 31556952 s (365.2425 d, the Gregorian mean)  d = 86400  h = 3600
#                   m = 60 (MINUTES; there is no month unit: say 30d)  s = 1
#    N is 1-10 decimal digits, no sign, no leading zero, never 0, so no total is 0. The total is at
#    most 100 y = 3155695200 s: past that the bet is drand quicknet's survival, not the lock. The
#    10-digit cap keeps every product and sum far inside the shell's 64-bit $(( )).
#    Prints the seconds; anything else dies naming the argument and the accepted grammar. The lines
#    marked "@mut:" are the ones the self-test's mutation arms disable, one at a time.
duration_seconds() {
  _dg="accepted: a bare number of YEARS (10), or N<unit> terms with no spaces, units y d h m s in that order, each at most once (30d 1h 40m 365d 1y30d 1d12h 90s); m = minutes, no month unit; N is 1-10 digits, no sign, no leading zero, never 0; total at most 100y"
  case $1 in
    '') die "duration '' is empty — $_dg" ;;
    *[!0-9ydhms]*) die "duration '$1' has a character outside 0-9 y d h m s — $_dg" ;;
  esac
  _dr=$1; _dt=0; _dl=ydhms
  case $_dr in *[!0-9]*) ;; *) _dr="${_dr}y" ;; esac   # a bare N is N years
  while [ -n "$_dr" ]; do
    _dn=${_dr%%[!0-9]*}; _dr=${_dr#"$_dn"}
    _du=${_dr%"${_dr#?}"}; _dr=${_dr#?}
    [ -n "$_dn" ] || die "duration '$1': unit '$_du' has no number — $_dg"
    [ -n "$_du" ] || die "duration '$1': number '$_dn' has no unit — $_dg"
    case $_dn in 0) die "duration '$1': a term is zero, and a zero total locks nothing — $_dg" ;; esac   # @mut:zero
    case $_dn in 0?*) die "duration '$1': '$_dn' has a leading zero — $_dg" ;; esac
    [ ${#_dn} -le 10 ] || die "duration '$1': '$_dn' has more than 10 digits — $_dg"
    case $_dl in *"$_du"*) ;; *) die "duration '$1': unit '$_du' is repeated or out of order (y d h m s) — $_dg" ;; esac   # @mut:order
    _dl=${_dl#*"$_du"}
    case $_du in y) _dm=31556952 ;; d) _dm=86400 ;; h) _dm=3600 ;; m) _dm=60 ;; *) _dm=1 ;; esac
    _dt=$(( _dt + _dn * _dm ))
  done
  [ "$_dt" -le 3155695200 ] || die "duration '$1' is $_dt s, beyond 100 years (3155695200 s); drand quicknet survival is the bet — $_dg"   # @mut:cap
  echo "$_dt"
}


# ★ Destroy plaintext, and say honestly what that is (README §5; audit SA-N7): an UNLINK. On APFS
#   and on SSDs no overwrite reaches the old blocks (copy-on-write, wear levelling); `rm -P` has no
#   effect on current macOS and there is no `shred`. FileVault protects the stale blocks; piping the
#   secret in with `-` keeps it off disk altogether. Refuses to report success while it still exists.
obliterate() {
  for f in "$@"; do
    [ -e "$f" ] || continue
    rm -f "$f" 2>/dev/null || true
    if [ -e "$f" ]; then die "could not remove $f — refusing to report success"; fi
  done
}

# tar_entries_ok TARBALL: LIST before extracting, and refuse unless EVERY entry is a regular file or
# a directory with a relative path and no ".." component (commit security review of 827e4ed). A
# package may come from anywhere (fetched from Arweave; anyone can tlock anything to a past round,
# which opens at once), and a symlink, hardlink, device or fifo entry, or a path out of the target,
# would let it write outside the new directory `open` extracts into. bsdtar's own defaults (no -P;
# measured 2026-10-09, bsdtar 3.5.3 / libarchive 3.7.4) add a second wall: they strip a leading "/",
# refuse ".." and refuse to extract through a symlink. -tv marks the type in column 1 (- d h l p c
# b); -t gives one escaped name per line, so the two listings have the same number of lines.
# IDENTICAL in both tools (the self-test compares it).
tar_entries_ok() {
  _tv=$(tar -tvzf "$1" 2>/dev/null) && _tn=$(tar -tzf "$1" 2>/dev/null) && [ -n "$_tn" ] \
    && [ "$(printf '%s\n' "$_tv" | wc -l)" = "$(printf '%s\n' "$_tn" | wc -l)" ] \
    || die "★ refusing to extract $(basename "$1"): it does not list as a gzipped tar"
  _tb=$(printf '%s\n' "$_tv" | grep -v '^[-d]' | head -1)
  [ -z "$_tb" ] || die "★ refusing to extract $(basename "$1"): an entry is not a regular file or a directory (a symlink, hardlink, device or fifo): $_tb"   # @mut:tar-type
  _tb=$(printf '%s\n' "$_tn" | while IFS= read -r _n; do case "/$_n/" in (//*|*/../*) printf '%s\n' "$_n"; break ;; esac; done)
  [ -z "$_tb" ] || die "★ refusing to extract $(basename "$1"): an absolute path or a '..' component: $_tb"   # @mut:tar-path
}
# extract_verified TARBALL DIR: extract an UNTRUSTED tarball into DIR, a NEW directory this run just
# created (mkdir -m 700, never -p), and VERIFY THE RESULT ON DISK (S2 safety review, parser
# differential). The listing (tar_entries_ok) is only the first wall: a macOS AppleDouble member
# ("._y") is invisible to tar -t / tar -tv and their line counts, yet libarchive MERGES it into the
# next entry on extraction: measured 2026-10-09 (bsdtar 3.5.3, synthetic), the next entry, listed
# as a regular file, lands as a SYMLINK, or the extracted files and DIR itself gain an "everyone
# allow read,write,delete" ACL and xattrs. So:
#   · --no-mac-metadata: no AppleDouble merge of ACLs/xattrs (the only flag that stops it, measured);
#     --no-xattrs --no-acls --no-fflags as well;
#   · then, ON DISK (inodes, not a listing): every entry under DIR is a regular file or a directory,
#     and nothing under DIR, DIR included, carries an xattr or an ACL (ls -l marks "@" / "+").
#     With no symlink possible, every path is inside DIR (bsdtar also refuses ".." and "/").
#   Any failure removes DIR (attacker-shaped entries and decrypted plaintext alike) and refuses.
# IDENTICAL in both tools (the self-test compares it).
extract_verified() {
  tar_entries_ok "$1"
  tar --no-mac-metadata --no-xattrs --no-acls --no-fflags -xzf "$1" -C "$2" || { xv_remove "$2"; die "★ the archive did not extract: $(basename "$1")"; }   # @mut:xtract
  # the tree is OURS (a new 0700 dir): owner rwx on every directory (pre-order, so find then descends)
  # and rw on every file, BEFORE the walk: a mode-000 directory hid its contents from it, and find's
  # failure was lost in a pipeline (S2 re-review I-2). No pipelines below: every status is checked.
  find "$2" -type d -exec chmod u+rwx {} \; && find "$2" -type f -exec chmod u+rw {} + || { xv_remove "$2"; die "★ refusing $(basename "$1"): the extracted tree could not be opened up for checking"; }   # @mut:xv-chmod
  _xb=$(find "$2" -mindepth 1 ! -type f ! -type d) || { xv_remove "$2"; die "★ refusing $(basename "$1"): the extracted tree could not be walked"; }
  [ -z "$_xb" ] || { xv_remove "$2"; die "★ refusing $(basename "$1"): on disk, an extracted entry is not a regular file or a directory (a merged AppleDouble member?): $(printf '%s\n' "$_xb" | head -1)"; }   # @mut:disk-type
  _xa=$(find "$2" -exec ls -ld {} +) || { xv_remove "$2"; die "★ refusing $(basename "$1"): the extracted tree could not be listed"; }
  _xa=$(printf '%s\n' "$_xa" | awk '$1 ~ /[@+]$/')
  [ -z "$_xa" ] || { xv_remove "$2"; die "★ refusing $(basename "$1"): on disk, the extraction carries extended attributes or an ACL (a merged AppleDouble member?)"; }   # @mut:disk-attr
}
# xv_remove DIR: remove a refused extraction, and VERIFY it is gone: it may hold decrypted content
xv_remove() {
  # (|| true: under set -e a failing rm here would end the shell before the check below reports it)
  find "$1" -type d -exec chmod u+rwx {} \; 2>/dev/null || true; rm -rf "$1" 2>/dev/null || true
  [ ! -e "$1" ] || die "★ could not remove $1 after refusing it: decrypted content may remain there. Remove it by hand (chmod -R u+rwX, then rm -rf)."   # @mut:xv-gone
}

# need_vtb: SEALED.txt is written by vt-broadcast at the END of a seal (Task S2 §5), so the tool is
# checked at the START, before anything is read or exported: a seal never stops after the secret left
# its source for want of it. `env-names` runs the whole wrapper (env -i, sandbox, node, the install).
need_vtb() {
  [ -x "$VTB" ] && "$VTB" env-names >/dev/null 2>&1 \
    || die "the broadcast tool is not runnable ($VTB): it writes SEALED.txt at the end of the seal. Install it with (cd broadcast && npm ci --ignore-scripts), or set VT_BROADCAST=/path/to/broadcast/bin/vt-broadcast"   # @mut:need-vtb
}
# write_sealed_txt: the LAST step of a seal (Task S2 §5): vt-broadcast seal-text --write puts
# SEALED.txt, the self-contained text (format vault-timelock-sealed/1, spec B §5.6), into the finished
# package and the seal prints its path, size and SHA-256. If it cannot be written the seal has NOT
# finished: the package is kept (it verified above) and the message says how to write the text.
write_sealed_txt() {
  if ! _sw=$("$VTB" seal-text "$PKG" --write 2>&1); then   # @mut:sealed-txt
    die "★ SEALED.txt could not be written ($_sw). The package is complete and kept at $PKG/. Write the text with: $VTB seal-text $PKG --write -- until then this seal has NOT finished."
  fi
  [ -f "$PKG/SEALED.txt" ] || die "★ vt-broadcast reported success but $PKG/SEALED.txt is missing: this seal has NOT finished."
  echo "  SEALED.txt $PKG/SEALED.txt  $(wc -c < "$PKG/SEALED.txt" | tr -d ' ') bytes  sha256 $(shasum -a 256 "$PKG/SEALED.txt" | cut -d' ' -f1)"
}

# src_id PATH: inode, size, and the (nanosecond) mtime and ctime, for the re-check before deletion
src_id() { stat -f '%i %z %Fm %Fc' "$1" 2>/dev/null || stat -c '%i %s %Y %Z' "$1" 2>/dev/null || echo gone; }

# ── seal ─────────────────────────────────────────────────────────────────────────────────────
cmd_seal() {
  SRC=${1:?usage: seal <path|-> [DURATION] [--armor] [--clearnet]}
  shift
  # at most one DURATION (the grammar above), options before or after it; anything not starting
  # with -- is the duration, so `-1d` reaches the grammar and is refused there, with the grammar
  DUR=10; HAVE_DUR=0; ARMOR_FLAG=""; JIT_ARG=""
  while [ $# -gt 0 ]; do
    case "$1" in
      # --armor (Task S1 §2): the sealed .age is PEM-armored age, name unchanged; unquoted
      # $ARMOR_FLAG below is empty or exactly --armor
      --armor) ARMOR_FLAG=--armor; shift ;;
      --jitter) JIT_ARG=${2:?--jitter needs a DURATION (0 disables the random offset)}; shift 2 ;;   # Task S2 §6
      --clearnet) CLEARNET=1; shift ;;   # the ONLY way past Tor (R40); named in the banner
      --*) die "unexpected option: $1" ;;
      *) [ "$HAVE_DUR" = 0 ] || die "more than one duration: '$DUR' and '$1' — give at most one"
         DUR=$1; HAVE_DUR=1; shift ;;
    esac
  done
  SECS=$(duration_seconds "$DUR") || exit 1
  # the duration exactly as typed; a bare number is the only form that means years
  if [ "$HAVE_DUR" = 0 ]; then REQ="10 (years, the default)"
  else case $DUR in *[!0-9]*) REQ=$DUR ;; *) REQ="$DUR (years)" ;; esac; fi
  # TL_TEST_SECONDS exists ONLY so --self-test can reach the open-after-the-round path: a seal that
  # can never be opened inside a test cannot tell LOCKED from BROKEN.
  if [ -n "${TL_TEST_SECONDS:-}" ]; then
    case $TL_TEST_SECONDS in *[!0-9]*) die "TL_TEST_SECONDS must be whole seconds" ;; esac
    SECS=$TL_TEST_SECONDS; REQ="$REQ; overridden by TL_TEST_SECONDS=$TL_TEST_SECONDS (self-test)"
  fi
  jitter_setup
  if [ "$SRC" != "-" ]; then
    # Trailing slashes go first: `seal linkdir/` (tab completion adds the slash) passes -L and looks
    # like the directory the link points at, while `tar -C <parent> linkdir` seals JUST THE LINK
    # (Task S1 re-review). A symlink source is refused, by -L and by find (which never follows its
    # starting point): tar would seal the link, not its target.
    while :; do case $SRC in /) break ;; */) SRC=${SRC%/} ;; *) break ;; esac; done
    [ -e "$SRC" ] || [ -L "$SRC" ] || die "no such path: $SRC"
    [ ! -L "$SRC" ] && [ -z "$(cd "$(dirname "$SRC")" && find "$(basename "$SRC")" -maxdepth 0 -type l)" ] \
      || die "$SRC is a symlink: tar would seal the link, not its target. Seal the target itself."   # @mut:src-symlink
    # ★ Refuse NOW what `open` would refuse at unlock time (tar_entries_ok): every entry must be a
    #   regular file with ONE link, or a directory. A symlink, hardlink, FIFO, socket or device
    #   would seal fine and leave a package this tool cannot open (and a FIFO "source" would be
    #   sealed as an empty special entry, then unlinked). A hard-linked file also survives its
    #   deletion through the other link.
    _sb=$(cd "$(dirname "$SRC")" && find "$(basename "$SRC")" \( ! -type f ! -type d \) -o \( -type f -links +1 \) | head -1)
    [ -z "$_sb" ] || die "★ refusing to seal $SRC: '$_sb' is not a regular file or a directory (a symlink, FIFO, socket or device), or is a hard-linked file. open refuses such entries at unlock time, so this tool could not open the package."   # @mut:seal-entries
  fi
  need
  need_vtb

  # Tor and drand first (R40): nothing is read or written until drand answered through Tor, and the
  # chain info it answered with is PINNED quicknet (GENESIS and PERIOD below are those pins).
  tor_preflight
  INFO=$(chain_info) || exit 1

  NOW=$(date -u +%s)
  J=0; [ "$JMAX" = 0 ] || J=$(jitter_draw "$JMAX")   # drawn once, never printed
  TARGET=$(( NOW + SECS + J ))   # @mut:jitter
  ROUND=$(round_for "$TARGET" "$GENESIS" "$PERIOD")
  # the round's own time (the round of TARGET's period, at most PERIOD-1 s before TARGET), not
  # TARGET: that is when it opens
  WHEN=$(round_iso "$ROUND")
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  echo "  unlock     $WHEN  (drand round $ROUND; requested: $REQ)"
  assert_future "$ROUND"   # before encrypting anything: a horizon inside the margin is refused here

  # The package goes to the data dir, never the cwd (audit SA-N10): a NEW dir (no -p), 0700 whatever
  # the umask. Until it is complete the traps remove it: a half package nobody vouched for.
  [ ! -L "$OUT" ] || die "★ $OUT is a symlink: refusing to write packages through it"   # @mut:out-symlink
  mkdir -p -m 700 "$OUT" || die "could not create $OUT"
  if [ "$SRC" = "-" ]; then PKG="$OUT/timelock-$STAMP"; else PKG="$OUT/$(basename "$SRC")-timelock-$STAMP"; fi   # @mut:out-dir
  mkdir -m 700 "$PKG" || die "could not create a new package dir $PKG"   # @mut:pkg-mode
  PKG_PARTIAL=$PKG
  trap 'info_stop; [ -z "${PKG_PARTIAL:-}" ] || rm -rf "$PKG_PARTIAL"' EXIT
  trap 'info_stop; [ -z "${PKG_PARTIAL:-}" ] || rm -rf "$PKG_PARTIAL"; exit 130' HUP INT TERM
  # the pinned, checked chain info, served to tle on loopback: tle encrypts with exactly this (E4)
  printf '%s' "$INFO" > "$PKG/chain-info.json"
  info_serve "$PKG"

  # ★★ NOTHING PLAINTEXT IS EVER A FILE HERE. A plaintext archive written to disk and deleted
  #    afterwards is recoverable on APFS (copy-on-write) and on any SSD (wear levelling).
  #    · `-`: stdin goes STRAIGHT into tle --encrypt, raw (no tar, no temp file: audit K19), as
  #      payload.age + `encoding` = raw, the one-layer content shape seal-text and publish detect.
  #    · a path: tar is piped into tle; the only plaintext on disk is whatever was ALREADY there.
  #    tle's exit status is checked on both. A NETWORK error (a slow Tor circuit) is retried for a
  #    path, whose tar simply re-reads the source; never for stdin, which a retry would see EMPTY.
  if [ "$SRC" = "-" ]; then
    SEALED=payload.age
    _te=$(tle_env --encrypt --chain="$CHAIN" --round="$ROUND" --output="$PKG/payload.age" --network="http://127.0.0.1:$INFO_PORT" $ARMOR_FLAG 2>&1) || die "sealing failed (tle): $_te"   # @mut:stdin-check
    echo raw > "$PKG/encoding"
  else
    SEALED=secret.tar.gz.age
    # ★ THE ARCHIVE CARRIES NO METADATA OF THE SEALING ACCOUNT (Task S2 §2; claims review F-11):
    #   measured 2026-10-09 (bsdtar 3.5.3), a plain `tar czvf` wrote the login name as every entry's
    #   owner, uid 501, the files' xattrs as pax records and the gzip header's MTIME, all public at
    #   the round. tar $TAR_SCRUB writes ustar (no pax records, so no xattrs; --no-xattrs and
    #   --no-mac-metadata too), owner 0/0 nobody/nobody; COPYFILE_DISABLE=1 (no AppleDouble ._ files);
    #   $TAR_GZIP: bsdtar's own gzip with MTIME 0, its piped output zero-padded to 10,240 B as before.
    #   ★ The SOURCE is never modified (no touch, no chmod): its own mtimes and modes stay in the
    #   archive, and they become public at the round with the rest of its content. A path too long
    #   for ustar (100 + 155 chars) or a file over 8 GiB makes tar fail: refused, source untouched.
    # ★ FAIL CLOSED ON TAR TOO (controller ruling, Task S1 review). A pipeline's status is its LAST
    #   command's, so `tar | tle` alone would seal a tar that failed half-way (an unreadable file) or
    #   archived less than the source, and then delete the source. So tar's exit status and its -v
    #   entry list come back too, in memory through fd 5 (interleaved with tle's output; no file),
    #   and BOTH must be right: status 0, and exactly the entries `find` lists for the source.
    #   Otherwise nothing is sealed and the source is never touched.
    SRCLIST=$(cd "$(dirname "$SRC")" && find "$(basename "$SRC")" | LC_ALL=C sort)
    SRCID=$(src_id "$SRC")   # what "the same source" means at deletion time (re-checked there)
    # a stat that fails in both forms gives "gone", and "gone" = "gone" would let the re-check before
    # DELETION pass vacuously: refuse now, before anything is read or encrypted (S2 re-review M-5)
    case $SRCID in ''|gone) die "★ cannot identify $SRC (stat failed): refusing to seal a source whose identity this tool could not re-check before deleting it. Nothing was sealed; the source is untouched." ;; esac   # @mut:src-id-known
    _ta=1
    while :; do
      _st=0
      _out=$( { { COPYFILE_DISABLE=1 tar $TAR_SCRUB -czvf - $TAR_GZIP -C "$(dirname "$SRC")" "$(basename "$SRC")" 2>&5; echo "tar-exit $?" >&5; } \
        | tle_env --encrypt --chain="$CHAIN" --round="$ROUND" --output="$PKG/secret.tar.gz.age" --network="http://127.0.0.1:$INFO_PORT" $ARMOR_FLAG >&5 2>&5; } 5>&1 ) || _st=$?   # @mut:armor-path
      _te=$(printf '%s\n' "$_out" | grep -v -e '^a ' -e '^tar-exit ' || true)
      if [ "$_st" != 0 ]; then   # tle failed: a NETWORK error is retried (tar re-reads the source)
        case $_te in
          *"doing request"*|*"TLS handshake timeout"*|*"deadline exceeded"*) [ "$_ta" -lt 3 ] || die "sealing failed (tle): $_te" ;;
          *) die "sealing failed (tle): $_te" ;;
        esac
        _ta=$((_ta + 1)); sleep 3; continue
      fi
      # a failing tar shows up as `tar-exit N` or, when errexit ends the group first, as NO status
      # line at all: so this is a POSITIVE match on "= 0" and must stay one (Task S1 re-review)
      [ "$(printf '%s\n' "$_out" | sed -n 's/^tar-exit //p')" = 0 ] || die "★ tar FAILED while archiving $SRC: NOTHING was sealed and the source is untouched. $_te"   # @mut:tar-status
      [ "$(printf '%s\n' "$_out" | sed -n 's/^a //p' | LC_ALL=C sort)" = "$SRCLIST" ] || die "★ the archive does not hold exactly the source's entries (find vs tar -v): NOTHING was sealed and the source is untouched."   # @mut:tar-listing
      break
    done
  fi
  [ -s "$PKG/$SEALED" ] || die "sealed file is empty — refusing to continue"
  info_stop

  echo "$ROUND" > "$PKG/round"
  # informational only: readers (open, seal-text, publish) detect armor by CONTENT, never by this
  if [ -n "$ARMOR_FLAG" ]; then
    echo pem > "$PKG/ARMOR"
    ARMORED="yes: the .age file is PEM-armored age (marker file ARMOR);
                      tle --decrypt reads it as is, like the binary form"
  else ARMORED="no (binary age)"; fi
  if [ "$CLEARNET" = 1 ]; then
    VIA="CLEARNET (--clearnet): drand saw this IP ask for round $ROUND.
                      Re-seal over Tor before publishing this anywhere (R40)."
  else VIA="through Tor only (R40)"; fi

  # ★★★ THE NEGATIVE CONTROL. Sealing and not proving it is SHUT is theatre: a round accidentally in
  #     the past yields a byte-identical-looking package that is already open. Locally (the pinned
  #     parameters and the clock), then drand through Tor: tle's "too early" for the file exactly as
  #     written (armored or not) AND the relay's HTTP 425 for the round (assert_shut).
  assert_future "$ROUND"
  assert_shut "$PKG/$SEALED" "$ROUND"

  if [ "$SRC" = "-" ]; then
    WHAT="the bytes read from stdin, RAW (no tar), timelock-encrypted
  encoding            raw"
    OPEN_CMDS="env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=content payload.age
    # content = the bytes, as piped in"
    SOURCE_NOTE="Sealed from stdin ('-'): there was no source file, and no plaintext was written
to disk by this tool -- stdin went straight into tle."
  else
    WHAT="a gzipped tarball, timelock-encrypted"
    OPEN_CMDS="env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=secret.tar.gz secret.tar.gz.age
    mkdir restored && tar -xzf secret.tar.gz -C restored"
    if [ -d "$SRC" ]; then
      SOURCE_NOTE="The source was a DIRECTORY: this tool never deletes one. It was left in place;
verify this package, then delete it yourself if you mean to."
    else
      SOURCE_NOTE="This tool UNLINKS (deletes) the source file it was given. It does not overwrite it,
and on APFS and on any SSD an overwrite would not reach the old blocks anyway."
    fi
  fi

  cat > "$PKG/README.txt" <<EOF
================================================================================
 THIS PACKAGE CANNOT BE OPENED UNTIL $WHEN
================================================================================

Sealed $(date -u +%Y-%m-%dT%H:%M:%SZ). Unlocks $WHEN (UTC), when drand publishes
round $ROUND. Requested: $REQ.

Contents:

  $SEALED$( [ "$SEALED" = payload.age ] && printf '         ' || printf '   ' )$WHAT
  round               $ROUND
  chain-info.json     drand quicknet's parameters, as pinned at sealing
  SEALED.txt          the self-contained text to publish: $SEALED as text, the drand
                      parameters and the literal commands that open it
  ASCII armor         $ARMORED
  drand contacted     $VIA
  README.txt          this file

--------------------------------------------------------------------------------
 1. WHAT IT IS
--------------------------------------------------------------------------------
$SEALED is encrypted to drand round $ROUND (tlock: identity-based encryption on
BLS12-381). drand is a public randomness beacon run by the League of Entropy; every
$PERIOD seconds it publishes a threshold BLS signature. The decryption key for this
file is the signature for round $ROUND, which the network is designed to publish at
$WHEN.

Opening it earlier needs t or more quicknet key shares combined (by colluding
operators, or by whoever steals or compels them; shares from before a reshare
count) -- together they can compute that signature at any time, without trace --
or a break of BLS12-381's pairing assumptions, which a large quantum computer
would be. Short of these, fewer than t shares cannot produce it, and neither can
whoever sealed this.

--------------------------------------------------------------------------------
 2. HOW TO OPEN IT, once $WHEN has passed
--------------------------------------------------------------------------------
    go install github.com/drand/tlock/cmd/tle@v1.2.0

    $OPEN_CMDS

  (through Tor, as at sealing; without Tor drop the env prefix, and drand sees your
  IP ask for this round. SEALED.txt beside this file has the same steps.)
  or, with this tool (it lists a tarball before extracting, and writes only into a
  new opened-<UTC time>/ directory): sh timelock-key.sh open .

\`tle\` is drand's own CLI, from the project that runs the beacon. If Go no longer
exists either, see §3 -- the file format is open and the signature is a public HTTP GET.

--------------------------------------------------------------------------------
 3. IF THAT TOOLING NO LONGER EXISTS
--------------------------------------------------------------------------------
SEALED.txt, beside this file, is self-contained: $SEALED as text and the literal
commands that open it. $SEALED is a standard age file carrying a tlock recipient
stanza. What you need is the drand signature at round $ROUND on chain
$CHAIN

    curl --noproxy '' --proxy socks5h://127.0.0.1:9050 https://api.drand.sh/$CHAIN/public/$ROUND

Any tlock implementation can take that signature and open the file. The scheme is
bls-unchained-g1-rfc9380. The chain's public key is in chain-info.json beside this
file, and is also served live at:

    curl --noproxy '' --proxy socks5h://127.0.0.1:9050 https://api.drand.sh/$CHAIN/info

Mirrors, in case api.drand.sh is gone: api2.drand.sh, api3.drand.sh.

--------------------------------------------------------------------------------
 4. IF DRAND IS GONE ENTIRELY
--------------------------------------------------------------------------------
Then this file is not openable, and that was the risk accepted when it was sealed.
A long timelock is a bet on a network outliving its horizon.

If you are the person who sealed this: that is why you were meant to store a SECOND,
human path alongside it -- e.g. a Shamir split (\`ssss\`, or \`age\` + 3-of-5 shares)
held by people who do not know each other. A timelock stops early opening (under the
assumptions in section 1); a Shamir split stops PERMANENT loss. They fail in opposite directions, which is the reason to
have both.

--------------------------------------------------------------------------------
 5. ON THE DESTRUCTION OF THE ORIGINAL -- READ THIS, IT IS NOT A FORMALITY
--------------------------------------------------------------------------------
$SOURCE_NOTE
**Deleting is not erasing.** Copy-on-write (APFS) leaves the old blocks intact; wear
levelling means the drive decides where bytes go, not the filesystem.
Deleted-but-recoverable is the honest description.

What actually protects the plaintext:
  · FileVault -- if the volume is encrypted at rest, the stale blocks are ciphertext.
  · Never writing it down: pipe the secret in with \`-\` so it exists only in memory.
  · Time Machine, Spotlight, and any cloud-synced folder will have taken a copy of a
    plaintext file that ever sat in one. Deleting the original does not reach those.
================================================================================
EOF

  PKG_PARTIAL=""; trap - EXIT HUP INT TERM   # the package is complete from here on
  # ★ the last step of the package: no SEALED.txt, no success, and then the source is NOT deleted
  write_sealed_txt

  # Destroy the source only AFTER the package verifies, and only a FILE: a directory source is never
  # deleted (controller ruling, Task S1 review): too much to lose to one wrong argument.
  if [ "$SRC" != "-" ] && [ ! -d "$SRC" ]; then
    # ★ only the file that was sealed: the same inode, size, mtime and ctime as right before tar.
    #   Anything else (replaced, renamed over, written to during sealing) is NOT deleted.
    [ "$(src_id "$SRC")" = "$SRCID" ] || die "★ source changed during sealing — package kept, source left in place; verify both: $PKG/ and $SRC"   # @mut:src-identity
    obliterate "$SRC"
    if [ -e "$SRC" ]; then die "source still present — refusing to report success"; fi
  fi

  echo "  package    $PKG/"
  echo "  size       $(wc -c < "$PKG/$SEALED" | tr -d ' ') bytes ($SEALED)"
  echo "  round      $ROUND"
  echo "  opens      $WHEN  (drand round $ROUND; requested: $REQ)"
  echo "  verified   does NOT open now (local round check; the drand relay answered HTTP 425 for round $ROUND$( [ "$CLEARNET" = 1 ] && echo ', directly (--clearnet)' || echo ' through Tor' ))"
  [ -z "$ARMOR_FLAG" ] || echo "  armor      the .age is ASCII-armored (PEM); marker file ARMOR"
  [ "$CLEARNET" = 0 ] || echo "  ★ CLEARNET drand saw this IP ask for round $ROUND: re-seal over Tor before publishing (R40)"
  if [ "$SRC" != "-" ] && [ -d "$SRC" ]; then echo "  source     sealed; source directory left in place — verify the package, then delete it yourself"
  elif [ "$SRC" != "-" ]; then echo "  source     unlinked — see README §5 for what that does and does not achieve"; fi
  echo
  echo "  ★ store a Shamir split elsewhere too: a timelock stops early opening (under its assumptions),"
  echo "    a split stops PERMANENT loss, and they fail in opposite directions."
}

# open: the .age may be binary or ASCII-armored (--armor); tle --decrypt detects armor by content
# (measured 2026-10-09, tle v1.2.0), so the same command opens either form. Both shapes this tool
# writes: secret.tar.gz.age (a path: decrypt, then extract) and payload.age + encoding (stdin: raw ->
# `content`; tar+gzip -> extract). drand is asked through Tor only (R40), like every other request.
# ★ Everything is written into a NEW directory, <package>/opened-<UTC stamp>/, created with mkdir
#   WITHOUT -p (commit security review of 827e4ed): a package from elsewhere could carry a symlink
#   called content or secret.tar.gz pointing at one of your files, and decrypting "into the package"
#   would overwrite it. A tarball is listed first: regular files and directories only.
cmd_open() {
  DIR=${1:?usage: open <package-dir> [--clearnet]}
  shift
  while [ $# -gt 0 ]; do
    case "$1" in
      --clearnet) CLEARNET=1; shift ;;
      *) die "unexpected argument: $1" ;;
    esac
  done
  need
  # a bare package name resolves against $OUT; an existing path always wins
  [ -d "$DIR" ] || [ ! -d "$OUT/$DIR" ] || DIR="$OUT/$DIR"
  if [ -f "$DIR/secret.tar.gz.age" ]; then IN=secret.tar.gz.age; PLAIN=secret.tar.gz; TARRED=yes
  elif [ -f "$DIR/payload.age" ]; then
    IN=payload.age
    case "$(cat "$DIR/encoding" 2>/dev/null)" in
      raw) PLAIN=content; TARRED=no ;;
      tar+gzip) PLAIN=content.tar.gz; TARRED=yes ;;
      *) die "payload.age without an encoding file saying raw or tar+gzip" ;;
    esac
  else die "no secret.tar.gz.age or payload.age in $DIR"; fi
  tor_preflight
  OD="$DIR/opened-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -m 700 "$OD" || die "could not create a NEW directory $OD to open into"
  if ! E=$(tle_net --decrypt --output="$OD/$PLAIN" "$DIR/$IN" 2>&1); then   # @mut:open-target
    rm -rf "$OD"
    R=$(round_of "$DIR")
    case $R in *[!0-9]*) UNTIL="the date in README.txt" ;; *) UNTIL="$(round_iso "$R") (UTC)" ;; esac
    case $E in
      *"too early"*)
        # tle says "too early" for ANY failure to fetch the signature (a 5 s timeout over Tor): after
        # the round, by the pinned parameters and the clock, it is a fetch failure (F-17)
        case $R in *[!0-9]*) ;; *) [ "$R" -gt $(( ($(date -u +%s) - GENESIS) / PERIOD + 1 )) ] || die "★ drand did not return round $R's signature (network or Tor; tle reports this as \"too early\"). The round passed at $UNTIL: retry." ;; esac   # @mut:open-passed
        die "★ not yet — locked until $UNTIL, drand round $R." ;;
      *) die "could not open: $E" ;;
    esac
  fi
  if [ "$TARRED" = yes ]; then
    extract_verified "$OD/$PLAIN" "$OD"   # the listing, then the result ON DISK; refusing removes $OD
  fi
  echo "  opened into $OD/ ($PLAIN)"
}

# ── self-test arms that take the SCRIPT UNDER TEST as $1, so a mutation arm can run the very same
#    arm on a mutant copy and require it to FAIL. Each returns 0 (pass) or 1 and explains a failure.
#
# The grammar table (Task S1 §4): every accepted example must give exactly its seconds, and every
# refused one must be refused FOR THE LISTED REASON, naming the argument and the grammar. A refusal
# for the wrong reason is a failure: it is how a dead check hides behind a neighbouring one.
#   A|<arg>|<seconds>     R|<arg>|<reason the message must contain>
GRAMMAR_TABLE='A|10|315569520
A|1|31556952
A|100|3155695200
A|30d|2592000
A|1h|3600
A|40m|2400
A|365d|31536000
A|1y30d|34148952
A|1d12h|129600
A|90s|90
A|1y1d1h1m1s|31647013
A|100y|3155695200
A|36524d|3155673600
A|3155695200s|3155695200
R||is empty
R|0|a term is zero
R|0d|a term is zero
R|1d0h|a term is zero
R|00|leading zero
R|01d|leading zero
R|1.5h|outside 0-9 y d h m s
R|-1d|outside 0-9 y d h m s
R|+1d|outside 0-9 y d h m s
R|1D|outside 0-9 y d h m s
R|10x|outside 0-9 y d h m s
R|1 d|outside 0-9 y d h m s
R|d|has no number
R|1y1|has no unit
R|1d1d|repeated or out of order
R|1h1d|repeated or out of order
R|1m1h|repeated or out of order
R|101|beyond 100 years
R|100y1s|beyond 100 years
R|36525d|beyond 100 years
R|3155695201s|beyond 100 years
R|12345678901s|more than 10 digits'
arm_grammar() {
  printf '%s\n' "$GRAMMAR_TABLE" > "$T/grammar.tsv"; gbad=0
  while IFS='|' read -r k a want; do
    if out=$(sh "$1" duration "$a" 2>&1); then
      [ "$k" = A ] && [ "$out" = "$want" ] || { echo "    '$a' ACCEPTED as '$out' — want $k $want"; gbad=1; }
    else
      case "$k|$out" in
        "R|"*"duration '$a'"*"$want"*"accepted:"*) : ;;
        *) echo "    '$a' REFUSED: $out — want $k $want"; gbad=1 ;;
      esac
    fi
  done < "$T/grammar.tsv"
  return $gbad
}
# the SHARED code is byte-identical in both tools ($1 and its sibling $2): die(), the quicknet and
# archive-scrub constants (CHAIN, GENESIS/PERIOD, MIRRORS, TAR_SCRUB), iso_of, round_iso, round_of, the duration grammar, the
# whole drand-through-Tor block (its constants and functions, up to round_for), and the tar check
shared_text() {
  grep -x 'die() {.*}' "$1"
  grep -E '^(CHAIN|GENESIS|MIRRORS|TAR_SCRUB)=' "$1"
  grep -E '^(iso_of|round_iso)\(\) \{.*\}$' "$1"
  sed -n '/^round_of() {$/,/^}$/p' "$1"
  sed -n '/^duration_seconds() {$/,/^}$/p' "$1"
  sed -n '/^# ── ★★ DRAND, ONLY THROUGH TOR/,/^round_for() /p' "$1"
  sed -n '/^tar_entries_ok() {$/,/^}$/p' "$1"
  sed -n '/^# extract_verified TARBALL DIR/,/^}$/p' "$1"
  sed -n '/^# xv_remove DIR/,/^}$/p' "$1"
}
arm_same_shared() {
  shared_text "$1" > "$T/shared.1"; shared_text "$2" > "$T/shared.2"
  grep -q '^duration_seconds() {$' "$T/shared.1" && grep -q '^assert_shut() {$' "$T/shared.1" && grep -q '^tar_entries_ok() {$' "$T/shared.1" && grep -q '^extract_verified() {$' "$T/shared.1" \
    && grep -q '^round_of() {$' "$T/shared.1" && [ "$(grep -cE '^(CHAIN|GENESIS|MIRRORS|TAR_SCRUB)=|^(iso_of|round_iso)\(\)' "$T/shared.1")" = 6 ] \
    || { echo "    the shared functions are missing from $1"; return 1; }
  cmp -s "$T/shared.1" "$T/shared.2" \
    || { echo "    the shared code differs between $1 and $2:"; diff "$T/shared.1" "$T/shared.2" | sed 's/^/      /'; return 1; }
}
# ── the .age formats (Task S1 §2). Armor is exactly age's: the header line, standard base64 with
#    padding in 64-column lines (only the last may be shorter), the footer line, a final newline.
is_armored() {
  [ "$(tail -c 1 "$1" | od -An -tx1 | tr -d ' \n')" = 0a ] || return 1
  awk 'NR == 1 { if ($0 != "-----BEGIN AGE ENCRYPTED FILE-----") bad = 1; next }
       end { bad = 1 }
       $0 == "-----END AGE ENCRYPTED FILE-----" { end = NR; next }
       { if ($0 !~ /^[A-Za-z0-9+\/]+=*$/ || length($0) > 64 || (prev != "" && length(prev) != 64)) bad = 1; prev = $0 }
       END { exit (bad || !end || prev == "") ? 1 : 0 }' "$1"
}
is_binary_age() { [ "$(head -n 1 "$1")" = "age-encryption.org/v1" ]; }
# make_fakes: $T/fakebin holds an offline `tle` and `curl` for the arms that test plumbing, not
# drand. Both LOG each call to $FAKE_LOG: "TOR" when it went to the Tor proxy exactly as R40
# requires, "DIRECT..." otherwise. The fake curl answers /info with quicknet's real parameters
# (FAKE_DRAND_INFO=hash|genesis|period|key|scheme serves one wrong value; dupfirst|duplast repeat a key;
# multidoc|casekey|longs|extrakey|reorder: S2 re-review I-1). The fake tle ENCRYPTS NOTHING:
# it writes an age-shaped file with a tlock stanza around its input (armored with --armor), and
# answers --decrypt with "too early" (FAKE_TLE_DECRYPT=open: it "opens", writing back what it wrapped; =neterr: a network error;
# FAKE_TLE_FLAKY=<file>: one retryable "doing request" error first). FAKE_TLE_FAIL=1 fails an
# encrypt; FAKE_TLE_LEAK=1 drops a file into $TMPDIR (the control of the TMPDIR arms). Synthetic
# data only; nothing here touches the network.
make_fakes() {
  mkdir -p "$T/fakebin"
  cat > "$T/fakebin/curl" <<'FAKE'
#!/bin/sh
url=; px=; np=no; prev=
for a in "$@"; do
  case $prev in --proxy) px=$a ;; --noproxy) [ -n "$a" ] || np=yes ;; esac
  prev=$a; url=$a
done
case $px in
  socks5h://drand.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9]Z:x@127.0.0.1:9050)
    if [ "$np" = yes ]; then v=TOR; else v=DIRECT-noproxy-not-empty; fi ;;
  '') v=DIRECT ;;
  *) v=DIRECT-other-proxy ;;
esac
[ -z "${FAKE_LOG:-}" ] || echo "curl $v" >> "$FAKE_LOG"
I='{"public_key":"83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a","period":3,"genesis_time":1692803367,"hash":"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971","groupHash":"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e","schemeID":"bls-unchained-g1-rfc9380","metadata":{"beaconID":"quicknet"}}'
case ${FAKE_DRAND_INFO:-good} in
  hash) I=$(printf '%s' "$I" | sed 's/"hash":"52db/"hash":"62db/') ;;
  genesis) I=$(printf '%s' "$I" | sed 's/"genesis_time":1692803367/"genesis_time":1692803368/') ;;
  period) I=$(printf '%s' "$I" | sed 's/"period":3,/"period":30,/') ;;
  key) I=$(printf '%s' "$I" | sed 's/"public_key":"83cf/"public_key":"93cf/') ;;
  scheme) I=$(printf '%s' "$I" | sed 's/bls-unchained-g1-rfc9380/bls-unchained-on-g1/') ;;
  # a repeated key: a decoy FIRST (a JSON parser keeps the last, pinned, value), or a non-hex value
  # LAST (the old sed parse backtracked to the first, pinned, value; JSON keeps the attacker's)
  dupfirst) I=$(printf '%s' "$I" | sed 's/^{/{"public_key":"93cf0f2896adee7e",/') ;;
  duplast) I=$(printf '%s' "$I" | sed 's/}$/,"public_key":"NOT-HEX-attacker"}/') ;;
  # S2 re-review I-1: a second document; a key differing only in case; a key Go case-folds to
  # schemeID (U+017F, the long s); any unknown key; and the pinned info reordered with whitespace
  multidoc) I='{"x":1}'"$I" ;;
  casekey) I=$(printf '%s' "$I" | sed 's/}$/,"schemeid":"synthetic"}/') ;;
  longs) I=$(printf '%s' "$I" | sed 's/}$//')$(printf ',"\305\277chemeID":"synthetic"}') ;;
  extrakey) I=$(printf '%s' "$I" | sed 's/}$/,"synthetic":"x"}/') ;;
  reorder) I=$(printf '%s' "$I" | /usr/bin/jq '{schemeID, period, hash, genesis_time, groupHash, public_key, metadata}') ;;
esac
# /public/<round>: the HTTP status only (-o /dev/null -w '%{http_code}'); FAKE_DRAND_PUBLIC=425 (default),
# any other code, or 000 = no answer (curl exit 28)
case $url in
  */info) printf '%s' "$I" ;;
  */public/*) c=${FAKE_DRAND_PUBLIC:-425}; [ "$c" != 000 ] || exit 28; printf '%s' "$c" ;;
  *) exit 22 ;;
esac
FAKE
  cat > "$T/fakebin/tle" <<'FAKE'
#!/bin/sh
P='socks5h://drand.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9]Z:x@127.0.0.1:9050'
v=TOR
case ${HTTPS_PROXY:-} in $P) ;; *) v=DIRECT ;; esac
case ${https_proxy:-} in $P) ;; *) v=DIRECT ;; esac
[ -z "${NO_PROXY+x}${no_proxy+x}" ] || v="$v-with-NO_PROXY"
mode=encrypt; armor=0; round=; chain=; out=; in=; net=
for a in "$@"; do
  case $a in
    --encrypt) mode=encrypt ;; --decrypt) mode=decrypt ;; --armor) armor=1 ;;
    --round=*) round=${a#--round=} ;; --chain=*) chain=${a#--chain=} ;; --output=*) out=${a#--output=} ;;
    --network=*) net=${a#--network=} ;;
    -*) echo "fake tle: unexpected flag $a" >&2; exit 2 ;;
    *) in=$a ;;
  esac
done
# an encrypt with --network=http://127.0.0.1:<port> fetches the chain info from there, as tle does
# (the REAL curl, not the fake on PATH): LOOPBACK when it is the pinned quicknet info, else it fails
if [ "$mode" = encrypt ] && [ -n "$net" ]; then
  ci=; case $net in http://127.0.0.1:[0-9]*) ci=$(/usr/bin/curl -s --noproxy '*' --max-time 5 "$net/$chain/info" 2>/dev/null) || ci= ;; esac
  # (like tle v1.2.0 it checks the chain hash, not the scheme: the pin is chain_info's job)
  case $ci in *'"hash":"'"$chain"'"'*) v=LOOPBACK ;; *) v=LOOPBACK-UNSERVED ;; esac
fi
[ -z "${FAKE_LOG:-}" ] || echo "tle $mode $v" >> "$FAKE_LOG"
[ "$v" != LOOPBACK-UNSERVED ] || { echo "fake tle: the loopback chain info was not served" >&2; exit 1; }
[ -n "$out" ] || { echo "fake tle: no --output" >&2; exit 2; }
if [ "$mode" = decrypt ]; then
  if [ -n "${FAKE_TLE_FLAKY:-}" ] && [ ! -e "$FAKE_TLE_FLAKY" ]; then
    : > "$FAKE_TLE_FLAKY"
    echo 'creating client: FetchChainInfo err: doing request: Get "https://api.drand.sh/info": net/http: TLS handshake timeout (fake)' >&2; exit 1
  fi
  case ${FAKE_TLE_DECRYPT:-early} in
    open) # strip the fake header (4 lines) of the input, de-armored first if armored
      if [ "$(head -n 1 "$in")" = '-----BEGIN AGE ENCRYPTED FILE-----' ]; then sed '1d;$d' "$in" | base64 -d; else cat "$in"; fi \
        | tail -n +5 > "$out"; exit 0 ;;
    neterr) echo "socks connect tcp 127.0.0.1:9050->api.drand.sh:443: general SOCKS server failure (fake)" >&2; exit 1 ;;
    *) echo "too early to decrypt: expected round (fake) > current round" >&2; exit 1 ;;
  esac
fi
if [ "${FAKE_TLE_FAIL:-0}" = 1 ]; then   # fail MID-STREAM: a partial, non-empty output file
  printf 'age-encryption.org/v1\n-> tlock %s %s\nZmFrZQ\n--- ZmFrZSBtYWMgZmFrZSBtYWMgZmFrZSBtYWMgZmFrZSA\npartial' "$round" "$chain" > "$out"
  cat > /dev/null; echo "fake tle: encryption failed mid-stream (FAKE_TLE_FAIL)" >&2; exit 1
fi
[ "${FAKE_TLE_LEAK:-0}" != 1 ] || echo leaked > "${TMPDIR:-/tmp}/fake-tle-leak.$$"
{ printf 'age-encryption.org/v1\n-> tlock %s %s\nZmFrZQ\n--- ZmFrZSBtYWMgZmFrZSBtYWMgZmFrZSBtYWMgZmFrZSA\n' "$round" "$chain"
  if [ -n "$in" ]; then cat "$in"; else cat; fi; } |
  if [ "$armor" = 1 ]; then
    echo '-----BEGIN AGE ENCRYPTED FILE-----'; base64 | tr -d '\n' | fold -w 64; echo; echo '-----END AGE ENCRYPTED FILE-----'
  else cat; fi > "$out"
# FAKE_TLE_REPLACE=<file>: after encrypting, REPLACE that file (new inode, new content): a source
# that changes between tar and its deletion
if [ -n "${FAKE_TLE_REPLACE:-}" ]; then printf 'replaced' > "$FAKE_TLE_REPLACE.new" && mv "$FAKE_TLE_REPLACE.new" "$FAKE_TLE_REPLACE"; fi
FAKE
  chmod +x "$T/fakebin/curl" "$T/fakebin/tle"
}
# The sandbox profiles. TOR_ONLY is B §6.1's, verbatim: the only outbound connection possible is
# Tor's SOCKS port, so a run under it that reaches drand proves there is no direct path.
TOR_ONLY='(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:9050"))'
# NO_TOR: Tor's SOCKS port unreachable (EPERM), every other port open (a seal's own loopback
# chain-info server included): "Tor is down" for the offline arms, whose fakes need no network
NO_TOR='(version 1)(allow default)(deny network-outbound (remote ip "localhost:9050"))'
# The real SEALS run under TOR_LOOP: B §6.1's profile plus every LOOPBACK port, because a seal serves
# the pinned chain info to tle on 127.0.0.1 (Task S2 §3, E4); still no non-loopback destination.
# The real OPENS run under TOR_ONLY, verbatim. LOOP_ONLY: loopback only (tle against info_serve).
TOR_LOOP="$TOR_ONLY"'(allow network-outbound (remote ip "localhost:*"))'
LOOP_ONLY='(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip "localhost:*"))'
# no_tmp_writes E: a sandbox profile that DENIES every file write below /private/var/folders and
# /private/tmp (where temp files go) except the current arm's package dir $FO, its call log $FL and
# E (the TMPDIR it gives the seal). ★ On macOS a bare `mktemp` IGNORES $TMPDIR (measured 2026-10-09,
# macOS 26.2: it uses the per-user temp dir), so "TMPDIR stays empty" alone cannot see a temp file
# written elsewhere; under this profile any such write fails the seal instead.
no_tmp_writes() {
  mkdir -p "$FO"; : >> "$FL"
  _rfo=$(cd "$FO" && pwd -P); _rfl=$(cd "$(dirname "$FL")" && pwd -P)/$(basename "$FL"); _re=$(cd "$1" && pwd -P)
  printf '(version 1)(allow default)(deny file-write* (subpath "/private/var/folders") (subpath "/private/tmp"))(allow file-write* (subpath "%s") (subpath "%s") (literal "%s"))' "$_rfo" "$_re" "$_rfl"
}
# wait_round R: sleep (no network: the pinned parameters) until round R is due, plus 3 s for drand
wait_round() {
  _due=$(( GENESIS + ($1 - 1) * PERIOD + 3 )); _now=$(date -u +%s)
  if [ "$_due" -gt "$_now" ]; then sleep $(( _due - _now )); fi
}
# mutant ID SED-COMMAND: $T/mut-ID.sh is $SELF with exactly ONE line changed, the line ending in
# "# @mut:MARKER", where MARKER is ID up to a "/" (two mutations of one line: ID marker/variant).
# A marker that is missing, or a mutation that changes nothing, fails the arm: a vacuous mutation
# would report KILLED without testing anything.
mutant() {
  _mf="$T/mut-$(printf '%s' "$1" | tr / -).sh"
  sed "/# @mut:${1%%/*}\$/$2" "$SELF" > "$_mf"
  mn=$(diff "$SELF" "$_mf" | grep -c '^<' || true)
  [ "$mn" -eq 1 ] || { echo "  FAIL MUTANT $1: the mutation changed $mn line(s), not exactly 1"; return 1; }
}
# mut_arm ID SED-COMMAND ARM DESCRIPTION REASON — the arm must FAIL on the mutant, and its log must
# show REASON: a mutant that fails for some other reason (a syntax error, a crash) kills nothing.
# The same arm passes on the unmutated script earlier in this run, so each line shows a check
# failing when removed and the restored check passing.
mut_arm() {
  if mutant "$1" "$2"; then
    if "$3" "$_mf" > "$_mf.log" 2>&1
    then echo "  FAIL MUTANT $1 SURVIVED: $4 — the arm '$3' still passes"; ok=1
    elif grep -q -- "$5" "$_mf.log"
    then echo "  OK   MUTANT $1 killed: $4 makes '$3' FAIL (it passes unmutated, above)"
    else echo "  FAIL MUTANT $1: '$3' failed, but not with \"$5\":"; sed 's/^/       /' "$_mf.log"; ok=1; fi
  else ok=1; fi
}
# check DESCRIPTION ARM SCRIPT...: run one arm on the unmutated script, print OK or FAIL + its log
check() {
  _cd=$1; shift
  if "$@" > "$T/check.log" 2>&1; then echo "  OK   $_cd"
  else echo "  FAIL $_cd"; sed 's/^/       /' "$T/check.log"; ok=1; fi
}
# ── the timelock-key-specific arms ──────────────────────────────────────────────────────────
# offline [VAR=value...] COMMAND...: run COMMAND (usually `sh SCRIPT seal|open ...`) from $T/cwd
# with the fake tle and curl first on PATH, packages under $FO (a fresh dir per arm), the fake call
# log in $FL, a 600 s horizon unless the arm overrides it. Output: $T/out.log. stdin is passed on.
offline() {
  rm -f "$FL"; mkdir -p "$FO" "$T/cwd" "$T/tmp"
  ( cd "$T/cwd" && env VAULT_TIMELOCK_DIR="$FO" TLE=tle PATH="$T/fakebin:$PATH" FAKE_LOG="$FL" \
      TMPDIR="$T/tmp" TL_TEST_SECONDS=600 "$@" ) > "$T/out.log" 2>&1
}
arm_dir() { FO="$T/o-$1"; FL="$T/calls-$1"; rm -rf "$FO" "$FL" "$T/cwd"; }   # each arm: a fresh, empty cwd
pkg_of() { ls -d "$FO"/"$1"timelock-* 2>/dev/null | head -1; }   # pkg_of src- | pkg_of '' (stdin)
show() { sed 's/^/      /' "$@"; }
newsrc() { mkdir -p "$T/srcs"; echo "synthetic-$1" > "$T/srcs/src"; }   # a fresh source, outside the cwd

# --armor reaches the tle call of both seal forms (Task S1 §2)
arm_armor() {
  arm_dir armor; newsrc armor
  offline sh "$1" seal "$T/srcs/src" --armor || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  is_armored "$(pkg_of src-)/secret.tar.gz.age" || { echo "    secret.tar.gz.age is not canonical age ASCII armor"; return 1; }
  [ "$(cat "$(pkg_of src-)/ARMOR" 2>/dev/null)" = pem ] || { echo "    no ARMOR marker saying pem"; return 1; }
  printf 'synthetic stdin' | offline sh "$1" seal - --armor || { echo "    the offline stdin seal failed:"; show "$T/out.log"; return 1; }
  is_armored "$(pkg_of '')/payload.age" || { echo "    payload.age is not canonical age ASCII armor"; return 1; }
}
# every drand-bound call (curl and tle; path seal, stdin seal and open) goes to the Tor proxy as R40
# requires, even with NO_PROXY=* and a decoy HTTPS_PROXY in the environment (Task S1 §6)
arm_routes() {
  arm_dir routes; newsrc routes
  offline NO_PROXY='*' no_proxy='*' HTTPS_PROXY=http://decoy.invalid:1 https_proxy=http://decoy.invalid:1 \
    sh "$1" seal "$T/srcs/src" || { echo "    the offline path seal failed:"; show "$T/out.log"; return 1; }
  cp "$FL" "$FL.all"
  printf 'synthetic stdin' | offline NO_PROXY='*' no_proxy='*' HTTPS_PROXY=http://decoy.invalid:1 https_proxy=http://decoy.invalid:1 \
    sh "$1" seal - || { echo "    the offline stdin seal failed:"; show "$T/out.log"; return 1; }
  cat "$FL" >> "$FL.all"
  if offline NO_PROXY='*' no_proxy='*' HTTPS_PROXY=http://decoy.invalid:1 https_proxy=http://decoy.invalid:1 \
       sh "$1" open "$(pkg_of src-)"; then echo "    the fake package opened"; return 1; fi
  grep -q 'locked until' "$T/out.log" || { echo "    open did not report locked:"; show "$T/out.log"; return 1; }
  cat "$FL" >> "$FL.all"
  [ "$(grep -c '^curl ' "$FL.all")" -ge 4 ] && [ "$(grep -c '^tle encrypt ' "$FL.all")" -ge 2 ] \
    && [ "$(grep -c '^tle decrypt ' "$FL.all")" -ge 3 ] \
    || { echo "    expected curl (info, status), tle encrypt (2 seals) and tle decrypt (2 seals, open) calls:"; show "$FL.all"; return 1; }
  # tle ENCRYPTS with the pinned info served on loopback (no drand request); everything else is Tor
  if grep '^tle encrypt ' "$FL.all" | grep -qv ' LOOPBACK$'; then echo "    an encrypt did NOT use the pinned loopback chain info:"; grep '^tle encrypt ' "$FL.all" | show; return 1; fi
  if grep -v ' TOR$' "$FL.all" | grep -v '^tle encrypt LOOPBACK$' | grep -q .; then echo "    a call did NOT go through Tor:"; grep -v ' TOR$' "$FL.all" | show; return 1; fi
}
# --clearnet is the one bypass, and it says so: banner, README, and every call direct
arm_clearnet() {
  arm_dir clear
  printf 'synthetic stdin' | offline sh "$1" seal - --clearnet || { echo "    the offline --clearnet seal failed:"; show "$T/out.log"; return 1; }
  grep -q -- '--clearnet: drand is contacted DIRECTLY' "$T/out.log" && grep -q 'CLEARNET.*re-seal over Tor' "$T/out.log" \
    && grep -q 'drand contacted     CLEARNET' "$(pkg_of '')/README.txt" \
    || { echo "    the banner or README does not name --clearnet"; show "$T/out.log"; return 1; }
  # (DIRECT whatever the caller's own proxy variables say: --clearnet leaves them as they are)
  [ "$(grep -c ' DIRECT' "$FL")" -ge 3 ] && ! grep -q ' TOR$' "$FL" || { echo "    calls:"; show "$FL"; return 1; }
}
# Tor down (its SOCKS port unreachable) -> refused before any drand call; the source is untouched
arm_tor_down() {
  arm_dir down; newsrc down
  if offline sandbox-exec -p "$NO_TOR" sh "$1" seal "$T/srcs/src"; then echo "    SEALED with Tor unreachable"; return 1; fi
  grep -q 'Tor is not answering on 127.0.0.1:9050' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -s "$FL" ] || { echo "    a drand call ran before the refusal:"; show "$FL"; return 1; }
  [ -f "$T/srcs/src" ] && [ -z "$(ls -A "$FO")" ] || { echo "    the source was touched or something was written"; return 1; }
}
# quicknet pinned: one wrong parameter from a mirror -> refused, for each parameter
arm_pin() {
  for w in scheme hash genesis period key; do   # scheme first: tle itself would accept it
    arm_dir "pin-$w"
    if printf x | offline FAKE_DRAND_INFO=$w sh "$1" seal -; then echo "    a wrong $w was SEALED"; return 1; fi
    grep -q 'does not match pinned quicknet' "$T/out.log" || { echo "    wrong $w refused for another reason:"; show "$T/out.log"; return 1; }
  done
}
# the LOCAL negative control: a horizon inside the margin is refused before anything is encrypted
arm_local_control() {
  arm_dir local
  if printf x | offline TL_TEST_SECONDS=6 sh "$1" seal -; then echo "    a 6-second horizon was SEALED"; return 1; fi
  grep -q 'is not safely in the future' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of '')" ] && ! grep -q '^tle ' "$FL" 2>/dev/null || { echo "    something was sealed or left behind"; return 1; }
}
# drand's control: if the sealed file OPENS now -> refused, and the package does not survive
arm_drand_control() {
  arm_dir open-now
  if printf x | offline FAKE_TLE_DECRYPT=open sh "$1" seal -; then echo "    a package that OPENS NOW was shipped"; return 1; fi
  grep -q 'OPENS RIGHT NOW' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of '')" ] || { echo "    the refused package was left behind"; return 1; }
}
# ...and any answer other than "too early" fails closed (shut must be SHOWN, not inferred)
arm_drand_reason() {
  arm_dir neterr
  if printf x | offline FAKE_TLE_DECRYPT=neterr sh "$1" seal -; then echo "    SEALED although drand never said 'too early'"; return 1; fi
  grep -q 'could not confirm through drand' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of '')" ] || { echo "    the refused package was left behind"; return 1; }
}
# ...and the relay must answer HTTP 425 for the round: 200 (it has the signature), 500, or no
# answer at all (000) refuses, saying which (Task S2 §3)
arm_drand_425() {
  for c in 200 500 000; do
    arm_dir "s425-$c"
    if printf x | offline FAKE_DRAND_PUBLIC=$c sh "$1" seal -; then echo "    SEALED although drand answered HTTP $c, not 425"; return 1; fi
    grep -q "did not answer HTTP 425 (Too Early) for round [0-9]* through Tor: HTTP $c" "$T/out.log" || { echo "    HTTP $c refused for another reason:"; show "$T/out.log"; return 1; }
    [ -z "$(pkg_of '')" ] || { echo "    the refused package was left behind"; return 1; }
  done
}
# after the round, tle's "too early" is a fetch failure, not a lock: open says so (F-17)
arm_open_passed() {
  arm_dir passed
  printf 'synthetic stdin' | offline sh "$1" seal - || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  echo 1000 > "$(pkg_of '')/round"
  if offline sh "$1" open "$(pkg_of '')"; then echo "    the fake package opened"; return 1; fi
  grep -q "drand did not return round 1000's signature (network or Tor" "$T/out.log" && grep -q 'The round passed at 2023-08-23T15:59:24Z (UTC): retry' "$T/out.log" \
    || { echo "    a passed round was reported as locked:"; show "$T/out.log"; return 1; }
}
# a network error (a slow Tor circuit) on the decrypt control is retried, then drand's answer counts
arm_retry() {
  arm_dir retry; rm -f "$T/flaky"
  printf x | offline FAKE_TLE_FLAKY="$T/flaky" sh "$1" seal - || { echo "    a flaky first answer was not retried:"; show "$T/out.log"; return 1; }
  [ "$(grep -c '^tle decrypt ' "$FL")" -ge 2 ] || { echo "    no retry seen:"; show "$FL"; return 1; }
}
# `seal -`: tle's exit status is checked (a failure mid-stream leaves a partial file), and nothing
# survives (audit K19)
arm_stdin_check() {
  arm_dir stdinfail
  if printf 'synthetic stdin' | offline FAKE_TLE_FAIL=1 sh "$1" seal -; then echo "    a failed tle stream was SEALED"; return 1; fi
  grep -q 'sealing failed' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of '')" ] || { echo "    the half package was left behind"; return 1; }
  # and the path form: refused, no half package, and the source NOT destroyed
  arm_dir pathfail; newsrc pathfail
  if offline FAKE_TLE_FAIL=1 sh "$1" seal "$T/srcs/src"; then echo "    a failed path seal was SEALED"; return 1; fi
  grep -q 'sealing failed' "$T/out.log" && [ -z "$(pkg_of src-)" ] && [ -f "$T/srcs/src" ] \
    || { echo "    path seal failure: wrong reason, a half package, or the source destroyed:"; show "$T/out.log"; return 1; }
}
# `seal -` with TMPDIR pointed at an EMPTY dir leaves it empty (A §7.15): stdin goes straight into
# tle, raw, as payload.age + encoding. It runs under no_tmp_writes, so the old
# `tmp=$(mktemp); cat > "$tmp"` leak (which a bare mktemp would put outside TMPDIR) fails the seal.
# The control: a tle that spills into TMPDIR IS caught.
arm_tmpdir() {
  arm_dir tmpdir; E="$T/tmp-stdin"; rm -rf "$E"; mkdir "$E"
  printf 'synthetic stdin' | offline TMPDIR="$E" sandbox-exec -p "$(no_tmp_writes "$E")" sh "$1" seal - \
    || { echo "    the offline stdin seal failed (a temp write is denied here):"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$E")" ] || { echo "    left under TMPDIR:"; ls -A "$E" | show; return 1; }
  P=$(pkg_of '')
  [ -f "$P/payload.age" ] && [ "$(cat "$P/encoding")" = raw ] && [ ! -e "$P/secret.tar.gz.age" ] \
    || { echo "    not the payload.age + encoding=raw shape:"; ls -A "$P" | show; return 1; }
  arm_dir tmpdir-ctl; rm -rf "$E"; mkdir "$E"
  printf 'synthetic stdin' | offline TMPDIR="$E" FAKE_TLE_LEAK=1 sh "$1" seal - || true
  [ -n "$(ls -A "$E")" ] || { echo "    the control failed: a spill into TMPDIR went unseen"; return 1; }
}
# the package goes under $OUT (never the cwd), in a NEW dir that is 0700 under umask 022 (SA-N10);
# `open` finds it by bare name from anywhere
arm_out_dir() {
  arm_dir out; newsrc out
  ( umask 022 && offline sh "$1" seal "$T/srcs/src" ) || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$T/cwd")" ] || { echo "    something landed in the cwd:"; ls -A "$T/cwd" | show; return 1; }
  P=$(pkg_of src-); [ -n "$P" ] || { echo "    no package under the data dir"; return 1; }
  m=$(stat -f %Lp "$P" 2>/dev/null || stat -c %a "$P")
  [ "$m" = 700 ] || { echo "    package dir mode $m under umask 022, not 700"; return 1; }
  if offline sh "$1" open "$(basename "$P")"; then echo "    the fake package opened"; return 1; fi
  grep -q 'locked until' "$T/out.log" || { echo "    open by bare name did not find the package:"; show "$T/out.log"; return 1; }
}
# ── open never follows a planted symlink (commit security review of 827e4ed) ─────────────────
# canary: a file OUTSIDE every package, which a planted symlink points at; it must not change
canary() { echo "canary-not-to-be-touched" > "$T/canary"; cp "$T/canary" "$T/canary.orig"; }
canary_intact() { cmp -s "$T/canary" "$T/canary.orig"; }
# a package whose payload decrypts (fake tle) to the tarball $2, as content tar+gzip
tar_pkg() {
  offline sh "$1" seal - < "$2" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  echo tar+gzip > "$(pkg_of '')/encoding"
}
# crafted tarballs: one with a symlink entry (to the canary), one with a "../x" entry
craft_tars() {
  rm -rf "$T/craft"; mkdir -p "$T/craft/l" "$T/craft/s/t" "$T/craft/h"
  ln -s "$T/canary" "$T/craft/l/link"; tar -czf "$T/link.tgz" -C "$T/craft/l" .
  echo dotdot > "$T/craft/s/x"; ( cd "$T/craft/s/t" && tar -czf "$T/dotdot.tgz" -P ../x )
  echo hard > "$T/craft/h/a"; ln "$T/craft/h/a" "$T/craft/h/b"; tar -czf "$T/hard.tgz" -C "$T/craft/h" .
  tar -czf "$T/abs.tgz" -P "$T/canary" 2>/dev/null   # an ABSOLUTE entry: the canary's own path
}
# symlinks named content, secret.tar.gz and src, planted in both package forms, all pointing at the
# canary: open writes only into a NEW opened-<stamp>/, the canary is byte-identical afterwards
arm_open_symlink() {
  arm_dir plant; newsrc plant; canary
  offline sh "$1" seal "$T/srcs/src" || { echo "    the offline path seal failed:"; show "$T/out.log"; return 1; }
  printf 'synthetic stdin' | offline sh "$1" seal - || { echo "    the offline stdin seal failed:"; show "$T/out.log"; return 1; }
  for P in "$(pkg_of src-)" "$(pkg_of '')"; do
    for n in content secret.tar.gz content.tar.gz src; do ln -s "$T/canary" "$P/$n"; done
    st=0; offline FAKE_TLE_DECRYPT=open sh "$1" open "$P" || st=$?
    canary_intact || { echo "    a planted symlink in $(basename "$P") redirected open's write: the file it points at CHANGED"; return 1; }
    [ "$st" = 0 ] || { echo "    open failed:"; show "$T/out.log"; return 1; }
    O=$(ls -d "$P"/opened-* 2>/dev/null | head -1)
    [ -n "$O" ] && [ ! -L "$O" ] || { echo "    no new opened-<stamp>/ directory"; return 1; }
  done
  [ "$(cat "$(ls -d "$(pkg_of src-)"/opened-* | head -1)/src")" = synthetic-plant ] \
    && [ "$(cat "$(ls -d "$(pkg_of '')"/opened-* | head -1)/content")" = 'synthetic stdin' ] \
    || { echo "    the opened content is not what was sealed"; return 1; }
}
# a tarball with a symlink entry is refused with the reason, and nothing is extracted
arm_open_tar_type() {
  arm_dir tartype; canary; craft_tars; tar_pkg "$1" "$T/link.tgz" || return 1
  P=$(pkg_of '')
  if offline FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    a tarball with a symlink entry was EXTRACTED"; return 1; fi
  grep -q 'refusing to extract content.tar.gz: an entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }   # the LISTING wall
  [ -z "$(find "$P" -type l)" ] && canary_intact || { echo "    a symlink was extracted or the canary changed"; return 1; }
}
# a tarball with a "../x" entry is refused with the reason, and nothing lands outside
arm_open_tar_path() {
  arm_dir tarpath; canary; craft_tars; tar_pkg "$1" "$T/dotdot.tgz" || return 1
  P=$(pkg_of '')
  if offline FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    a tarball with a ../x entry was EXTRACTED"; return 1; fi
  grep -q "an absolute path or a '..' component" "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$P/x" ] || { echo "    ../x was written"; return 1; }
}
# a data dir ($OUT) that is a symlink is refused, and nothing is written through it
arm_out_symlink() {
  arm_dir outlink; rm -rf "$T/outtarget" "$T/outlink"; mkdir "$T/outtarget"; ln -s "$T/outtarget" "$T/outlink"
  if printf x | offline VAULT_TIMELOCK_DIR="$T/outlink" sh "$1" seal -; then echo "    SEALED through a symlinked data dir"; return 1; fi
  grep -q 'is a symlink: refusing to write packages through it' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$T/outtarget")" ] || { echo "    something was written through the symlink"; return 1; }
}
# ── fix round 1 (Task S1 review): tar fails closed, directory sources are kept, untrusted text ─
# make_tarbin: $T/tarbin/tar is the REAL tar, except for create (a -c... argument): FAKE_TAR=fail cuts
# the archive short and exits 1 (a tar that fails mid-stream); FAKE_TAR=short drops every entry named
# drop-me and exits 0 (an archive holding less than the source)
make_tarbin() {
  mkdir -p "$T/tarbin"
  cat > "$T/tarbin/tar" <<FAKE
#!/bin/sh
# FAKE_TAR_PLAIN=1: a tar that ignores the extraction hardening (drops the four --no-* flags)
if [ "\${FAKE_TAR_PLAIN:-0}" = 1 ]; then
  for a; do shift; case \$a in --no-mac-metadata|--no-xattrs|--no-acls|--no-fflags) ;; *) set -- "\$@" "\$a" ;; esac; done
fi
case " \$* " in
  *" -c"*)
      case \${FAKE_TAR:-} in
        fail) "$(command -v tar)" "\$@" | head -c 100; exit 1 ;;
        short) exec "$(command -v tar)" --exclude '*/drop-me' "\$@" ;;
      esac ;;
esac
exec "$(command -v tar)" "\$@"
FAKE
  # tarbin/stat: FAKE_STAT_FAIL=1 fails every stat; tarbin/rm: FAKE_RM_FAIL=1 refuses to remove an
  # opened-<stamp> extraction (a tree that cannot be removed)
  cat > "$T/tarbin/stat" <<FAKE
#!/bin/sh
[ "\${FAKE_STAT_FAIL:-0}" != 1 ] || exit 1
exec "$(command -v stat)" "\$@"
FAKE
  cat > "$T/tarbin/rm" <<FAKE
#!/bin/sh
if [ "\${FAKE_RM_FAIL:-0}" = 1 ]; then case "\$*" in */opened-*) echo "rm: Operation not permitted (fake)" >&2; exit 1 ;; esac; fi
exec "$(command -v rm)" "\$@"
FAKE
  chmod +x "$T/tarbin/tar" "$T/tarbin/stat" "$T/tarbin/rm"
}
# a tar that fails mid-stream: refused, the source byte-identical, no package
arm_tar_fail() {
  arm_dir tarfail; newsrc tarfail; cp "$T/srcs/src" "$T/src.orig"
  if offline PATH="$T/tarbin:$T/fakebin:$PATH" FAKE_TAR=fail sh "$1" seal "$T/srcs/src"; then echo "    SEALED a tar that failed mid-stream"; fi
  cmp -s "$T/srcs/src" "$T/src.orig" || { echo "    the source CHANGED or was deleted after a failed tar"; return 1; }
  grep -q 'tar FAILED while archiving' "$T/out.log" || { echo "    not refused for the tar failure:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of src-)" ] || { echo "    a package was left behind"; return 1; }
}
# an archive that holds less than the source (tar exit 0): refused, the source kept, no package
arm_tar_short() {
  arm_dir tarshort; rm -rf "$T/srcs/dir"; mkdir -p "$T/srcs/dir"; echo keep > "$T/srcs/dir/keep"; echo drop > "$T/srcs/dir/drop-me"
  if offline PATH="$T/tarbin:$T/fakebin:$PATH" FAKE_TAR=short sh "$1" seal "$T/srcs/dir"; then echo "    SEALED an archive missing an entry"; fi
  [ -f "$T/srcs/dir/keep" ] && [ -f "$T/srcs/dir/drop-me" ] || { echo "    the source directory changed"; return 1; }
  grep -q "does not hold exactly the source's entries" "$T/out.log" || { echo "    not refused for the short listing:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of dir-)" ] || { echo "    a package was left behind"; return 1; }
}
# a DIRECTORY source is sealed and never deleted, and the output says so; a symlink source is refused
arm_dir_source() {
  arm_dir dirsrc; rm -rf "$T/srcs/dir2"; mkdir -p "$T/srcs/dir2/sub"; echo one > "$T/srcs/dir2/one"; echo two > "$T/srcs/dir2/sub/two"
  offline sh "$1" seal "$T/srcs/dir2" || { echo "    the directory seal failed:"; show "$T/out.log"; return 1; }
  [ "$(cat "$T/srcs/dir2/one" "$T/srcs/dir2/sub/two")" = "$(printf 'one\ntwo')" ] || { echo "    the source directory was deleted or changed"; return 1; }
  grep -q 'sealed; source directory left in place — verify the package, then delete it yourself' "$T/out.log" \
    || { echo "    the output does not say the directory was left in place:"; show "$T/out.log"; return 1; }
  [ -n "$(pkg_of dir2-)" ] || { echo "    no package"; return 1; }
  arm_dir symsrc; ln -sf "$T/srcs/dir2/one" "$T/srcs/link"
  if offline sh "$1" seal "$T/srcs/link"; then echo "    a symlink source was SEALED (as a link)"; return 1; fi
  grep -q 'is a symlink' "$T/out.log" && [ -f "$T/srcs/dir2/one" ] || { echo "    symlink source: wrong reason or the target touched"; show "$T/out.log"; return 1; }
}
# a round file that is not a round number is never printed raw by open
arm_round_text() {
  arm_dir roundtext
  printf 'synthetic stdin' | offline sh "$1" seal - || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  printf '12x; echo PWNED\n' > "$(pkg_of '')/round"
  if offline sh "$1" open "$(pkg_of '')"; then echo "    the fake package opened"; return 1; fi
  ! grep -q PWNED "$T/out.log" || { echo "    the round file was printed raw:"; show "$T/out.log"; return 1; }
  grep -q 'drand round (invalid round file)' "$T/out.log" || { echo "    no '(invalid round file)':"; show "$T/out.log"; return 1; }
}
# open_tar_refused SCRIPT TARBALL REASON: a tar+gzip package of TARBALL is refused for REASON
open_tar_refused() {
  tar_pkg "$1" "$2" || return 1
  P=$(pkg_of '')
  if offline FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    $(basename "$2") was EXTRACTED"; return 1; fi
  grep -q -- "$3" "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(find "$P" -type l)" ] && canary_intact || { echo "    something was extracted or the canary changed"; return 1; }
}
arm_open_tar_hard() { arm_dir tarhard; canary; craft_tars; open_tar_refused "$1" "$T/hard.tgz" 'not a regular file or a directory'; }
arm_open_tar_abs() { arm_dir tarabs; canary; craft_tars; open_tar_refused "$1" "$T/abs.tgz" "an absolute path or a '..' component"; }
# ── fix round 2 (Task S1 re-review): symlinked / special sources, the source's identity ─────
# `seal linkdir/` (a symlink to a directory, with the slash tab completion adds) is refused as a
# symlink: before, it sealed just the link and reported the directory "left in place"
arm_src_slash() {
  arm_dir srcslash; rm -rf "$T/srcs/realdir" "$T/srcs/linkdir"; mkdir -p "$T/srcs/realdir"; echo real > "$T/srcs/realdir/f"
  ln -s realdir "$T/srcs/linkdir"
  if offline sh "$1" seal "$T/srcs/linkdir/"; then echo "    SEALED a symlink given with a trailing slash (the package holds only the link)"; return 1; fi
  grep -q 'is a symlink: tar would seal the link' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$FO" 2>/dev/null)" ] && [ "$(cat "$T/srcs/realdir/f")" = real ] || { echo "    a package was written or the target changed"; return 1; }
}
# seal_refuses SCRIPT SOURCE: SOURCE is refused (an entry open could not extract), SOURCE untouched
seal_refuses() {
  if offline sh "$1" seal "$2"; then echo "    SEALED $(basename "$2"), which open could not extract"; return 1; fi
  grep -q 'is not a regular file or a directory (a symlink, FIFO, socket or device), or is a hard-linked file' "$T/out.log" \
    || { echo "    $(basename "$2") refused for another reason:"; show "$T/out.log"; return 1; }
  [ -e "$2" ] || [ -L "$2" ] || { echo "    $(basename "$2") was deleted"; return 1; }
  [ -z "$(ls -A "$FO" 2>/dev/null)" ] || { echo "    a package was left behind"; return 1; }
}
# what open's tar_entries_ok would refuse at unlock time is refused at SEAL time: a directory holding
# a symlink, a hard-linked file or a FIFO; a FIFO source; a hard-linked file source. (Sockets and
# devices fall under the same `! -type f ! -type d` test; a device needs root, a socket a listener.)
arm_src_special() {
  rm -rf "$T/sp"; mkdir -p "$T/sp/withlink" "$T/sp/withhard" "$T/sp/withfifo"
  echo x > "$T/sp/withlink/f"; ln -s f "$T/sp/withlink/l"
  echo x > "$T/sp/withhard/f"; ln "$T/sp/withhard/f" "$T/sp/withhard/g"
  echo x > "$T/sp/withfifo/f"; mkfifo "$T/sp/withfifo/p"; mkfifo "$T/sp/fifo"
  echo x > "$T/sp/hardfile"; ln "$T/sp/hardfile" "$T/sp/hardfile.2"
  for src in withlink withhard withfifo fifo hardfile; do
    arm_dir "special-$src"; seal_refuses "$1" "$T/sp/$src" || return 1
  done
}
# a source FILE replaced between tar and its deletion is NOT deleted; the package is kept
arm_src_replaced() {
  arm_dir replaced; newsrc replaced
  if offline FAKE_TLE_REPLACE="$T/srcs/src" sh "$1" seal "$T/srcs/src"; then echo "    reported success although the source changed"; fi
  [ -f "$T/srcs/src" ] && [ "$(cat "$T/srcs/src")" = replaced ] || { echo "    the replaced source was DELETED"; return 1; }
  grep -q 'source changed during sealing — package kept, source left in place; verify both' "$T/out.log" \
    || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -f "$(pkg_of src-)/README.txt" ] || { echo "    the package was not kept"; return 1; }
}
# tamper_mid FILE: change ONE byte in the middle of FILE (in armor, one base64 character, never a
# line break), so the change lands inside the ciphertext and only age's MAC can notice it
tamper_mid() {
  o=$(( $(wc -c < "$1") / 2 ))
  b=$(dd if="$1" bs=1 skip=$o count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')
  if [ "$b" = 0a ]; then o=$((o - 1)); b=$(dd if="$1" bs=1 skip=$o count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'); fi
  if [ "$b" = 41 ]; then r=B; else r=A; fi
  printf '%s' "$r" | dd of="$1" bs=1 seek=$o count=1 conv=notrunc 2>/dev/null
}

# ── Task S2 §2: the archive carries no metadata of the sealing account ──────────────────────────
# scrub_check TGZ: the payload's gzip header has MTIME 0 and no name; the tar inside holds no
# occurrence of the login name, no xattr pax records, no AppleDouble ._ entry, and every entry is
# owned by 0/0 nobody/nobody (the source's own mtimes and modes stay: it is never modified)
scrub_check() {
  _g=$(head -c 10 "$1" | od -An -tx1 | tr -d ' \n')
  case $_g in 1f8b08??00000000*) ;; *) echo "    gzip header MTIME is not 0 (header $_g)"; return 1 ;; esac
  [ $(( 0x$(printf '%s' "$_g" | cut -c7-8) & 8 )) = 0 ] || { echo "    the gzip header carries a file name"; return 1; }
  gzip -dc < "$1" > "$T/scrubx.tar" 2>/dev/null || [ $? = 2 ] || { echo "    the payload is not gzip"; return 1; }
  _n=$(grep -a -c -F -- "$(id -un)" "$T/scrubx.tar" || true)
  [ "$_n" = 0 ] || { echo "    the login name occurs in $_n line(s) of the archive"; return 1; }
  _n=$(grep -a -c 'LIBARCHIVE\.xattr\|SCHILY\.xattr' "$T/scrubx.tar" || true)
  [ "$_n" = 0 ] || { echo "    xattr records in the archive ($_n line(s))"; return 1; }
  ! tar -tf "$T/scrubx.tar" | grep -q '\(^\|/\)\._' || { echo "    AppleDouble ._ entries in the archive"; return 1; }
  tar --numeric-owner -tvf "$T/scrubx.tar" | awk '$3 != "0" || $4 != "0" { bad = 1 } END { exit bad }' \
    && tar -tvf "$T/scrubx.tar" | awk '$3 != "nobody" || $4 != "nobody" { bad = 1 } END { exit bad }' \
    || { echo "    an entry is not owned by 0/0 nobody/nobody:"; tar -tvf "$T/scrubx.tar" | show; return 1; }
}
# a directory source (kept) with an xattr and a 640 file: sealed offline (the fake tle wraps the
# archive in a 4-line fake header), inspected byte by byte; the source's mtimes, modes and xattrs are
# exactly as before (no touch, no chmod: the source is never modified)
arm_scrub() {
  arm_dir scrub; rm -rf "$T/srcs/sdir"; mkdir -p "$T/srcs/sdir/sub"; echo one > "$T/srcs/sdir/one"; echo two > "$T/srcs/sdir/sub/two"
  xattr -w com.apple.metadata:kMDItemWhereFroms 'https://example.invalid/synthetic-download' "$T/srcs/sdir/one"; chmod 640 "$T/srcs/sdir/one"
  _sb=$(find "$T/srcs/sdir" -exec stat -f '%m %Lp %N' {} +; xattr "$T/srcs/sdir/one")
  offline sh "$1" seal "$T/srcs/sdir" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  [ "$(find "$T/srcs/sdir" -exec stat -f '%m %Lp %N' {} +; xattr "$T/srcs/sdir/one")" = "$_sb" ] \
    || { echo "    the source's mtimes, modes or xattrs CHANGED"; return 1; }
  tail -n +5 "$(pkg_of sdir-)/secret.tar.gz.age" > "$T/scrub.tgz"
  scrub_check "$T/scrub.tgz"
}

# ── S2 safety review: AppleDouble members merge on extraction; the result is checked ON DISK ────
# craft_ad: $T/ad-sym.tgz: an AppleDouble-named "._y" SYMLINK (to $T/adcanary) then a regular "y"
#   (tar -tv lists ONE regular "y"); $T/ad-acl.tgz / $T/ad-root.tgz: AppleDouble members (tar
#   --mac-metadata) carrying an "everyone allow" ACL and an xattr for a file / for "." (the root)
craft_ad() {
  rm -rf "$T/ad"; mkdir -p "$T/ad/s" "$T/ad/a" "$T/ad/r"; echo adcanary > "$T/adcanary"
  ( cd "$T/ad/s" && ln -s "$T/adcanary" ._y && printf 'regular-content\n' > y )
  COPYFILE_DISABLE=1 tar --format ustar -czf "$T/ad-sym.tgz" -C "$T/ad/s" ._y y
  echo synthetic > "$T/ad/a/f"; chmod +a "everyone allow read,write,delete" "$T/ad/a/f"; xattr -w com.example.probe synthetic "$T/ad/a/f"
  tar --mac-metadata -czf "$T/ad-acl.tgz" -C "$T/ad/a" f
  echo synthetic > "$T/ad/r/g"; chmod +a "everyone allow list,add_file,delete_child" "$T/ad/r"
  tar --mac-metadata -czf "$T/ad-root.tgz" -C "$T/ad/r" .
  [ "$(tar -tzf "$T/ad-sym.tgz" | wc -l | tr -d ' ')" = 1 ] && tar -tvzf "$T/ad-sym.tgz" | grep -q '^-' \
    || { echo "    the crafted ._y archive does not list as one regular file (the corpus is not testing the merge)"; return 1; }
}
attrs_under() { find "$1" -exec ls -ld {} + | awk '$1 ~ /[@+]$/'; }
# the "._y" symlink merge: open refuses on the on-disk check, the opened-<stamp>/ dir is removed, the
# canary is untouched (--no-mac-metadata does NOT stop this merge, measured: the on-disk check is the wall)
arm_ad_sym() {
  arm_dir ad-sym; craft_ad || return 1; tar_pkg "$1" "$T/ad-sym.tgz" || return 1
  P=$(pkg_of '')
  if offline FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    an AppleDouble-merged symlink was EXTRACTED and accepted"; return 1; fi
  grep -q 'on disk, an extracted entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -d "$P"/opened-* 2>/dev/null)" ] && [ "$(cat "$T/adcanary")" = adcanary ] || { echo "    opened-<stamp>/ was left behind or the canary changed"; return 1; }
}
# AppleDouble ACL+xattr members, on a file and on "." (the opened dir itself): --no-mac-metadata drops
# them; open succeeds and nothing extracted, the opened dir included, carries an xattr or an ACL
arm_ad_acl() {
  for a in acl root; do
    arm_dir "ad-$a"; craft_ad || return 1; tar_pkg "$1" "$T/ad-$a.tgz" || return 1
    P=$(pkg_of '')
    offline FAKE_TLE_DECRYPT=open sh "$1" open "$P" || { echo "    open refused the AppleDouble $a archive (the extraction applied its ACL/xattrs):"; show "$T/out.log"; return 1; }
    [ -z "$(attrs_under "$(ls -d "$P"/opened-* | head -1)")" ] || { echo "    an xattr or an ACL reached the opened dir ($a)"; return 1; }
  done
}
# a tar that ignores the hardening flags (tarbin/tar, FAKE_TAR_PLAIN) applies the AppleDouble ACL:
# the on-disk attribute check refuses and removes the opened dir
arm_ad_attr() {
  arm_dir ad-attr; craft_ad || return 1; tar_pkg "$1" "$T/ad-acl.tgz" || return 1
  P=$(pkg_of '')
  if offline PATH="$T/tarbin:$T/fakebin:$PATH" FAKE_TAR_PLAIN=1 FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    an extraction carrying an ACL was accepted"; return 1; fi
  grep -q 'carries extended attributes or an ACL' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -d "$P"/opened-* 2>/dev/null)" ] || { echo "    the opened dir was left behind"; return 1; }
}
# a chain info that repeats a key is refused, whichever copy carries the pinned value; a good one is
# stored (and served to tle) as its canonical bytes, jq -cS
arm_pin_dup() {
  for w in dupfirst duplast; do
    arm_dir "dup-$w"
    if printf x | offline FAKE_DRAND_INFO=$w sh "$1" seal -; then echo "    a chain info with a repeated key ($w) was SEALED"; return 1; fi
    grep -q 'is not JSON, or repeats a key' "$T/out.log" || { echo "    $w refused for another reason:"; show "$T/out.log"; return 1; }
  done
  arm_dir canon
  printf x | offline sh "$1" seal - || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  [ "$(cat "$(pkg_of '')/chain-info.json")" = "$INFO_PINNED" ] \
    || { echo "    chain-info.json is not INFO_PINNED"; return 1; }
}

# seal_one SCRIPT INFO-VARIANT / pkg_new: one offline stdin seal with that chain-info variant; its package
seal_one() { printf x | offline FAKE_DRAND_INFO=$2 sh "$1" seal -; }
pkg_new() { pkg_of ''; }
# ── S2 re-review I-1: the chain info is compared EXACTLY; tle is served the pinned constant ──────
# INFO_PINNED is canonical, and its own fields hash to CHAIN (drand's chain-hash preimage)
arm_info_pinned() {
  [ "$(printf '%s' "$INFO_PINNED" | jq -cS .)" = "$INFO_PINNED" ] || { echo "    INFO_PINNED is not canonical (jq -cS)"; return 1; }
  _ph=$(printf '%s' "$INFO_PINNED" | env -i PATH="$PATH" node -e 'const i = JSON.parse(require("fs").readFileSync(0, "utf8")); const b = Buffer.alloc(12); b.writeUInt32BE(i.period, 0); b.writeBigInt64BE(BigInt(i.genesis_time), 4); process.stdout.write(require("crypto").createHash("sha256").update(Buffer.concat([b, Buffer.from(i.public_key, "hex"), Buffer.from(i.groupHash, "hex"), Buffer.from(i.metadata.beaconID)])).digest("hex"))')
  [ "$_ph" = "$CHAIN" ] && [ "$(printf '%s' "$INFO_PINNED" | jq -r .hash)" = "$CHAIN" ] || { echo "    INFO_PINNED's fields do not hash to CHAIN"; return 1; }
}
# a second document, a case-variant key, a case-folding key, an unknown key: refused, nothing sealed;
# the pinned info reordered with whitespace is accepted, and chain-info.json is INFO_PINNED, byte for byte
arm_pin_exact() {
  for w in multidoc casekey longs extrakey; do
    arm_dir "px-$w"
    if seal_one "$1" "$w"; then echo "    a chain info with $w was SEALED"; return 1; fi
    if [ "$w" = multidoc ]; then _pm='is not exactly one JSON value'; else _pm='does not match pinned quicknet exactly'; fi
    grep -q "$_pm" "$T/out.log" || { echo "    $w refused for another reason:"; show "$T/out.log"; return 1; }
  done
  arm_dir px-reorder
  seal_one "$1" reorder || { echo "    the pinned info, reordered, was refused:"; show "$T/out.log"; return 1; }
  [ "$(cat "$(pkg_new)/chain-info.json")" = "$INFO_PINNED" ] || { echo "    chain-info.json is not INFO_PINNED byte for byte"; return 1; }
}
# ── S2 re-review I-2: a mode-000 directory cannot hide entries from the on-disk check ────────────
# craft_m0: $T/m0-sym.tgz: a mode-000 directory "d" holding an AppleDouble "._y" symlink merged into a
#   regular-looking "y"; $T/m0-file.tgz: a mode-000 directory holding a mode-000 regular file (mtree)
craft_m0() {
  rm -rf "$T/m0"; mkdir -p "$T/m0"; echo adcanary > "$T/adcanary"; printf 'regular-content\n' > "$T/m0/ycontent"
  printf '#mtree\n./d type=dir mode=0000\n./d/._y type=link mode=0755 link=%s\n./d/y type=file mode=0644 contents=%s\n' "$T/adcanary" "$T/m0/ycontent" > "$T/m0/sym.mtree"
  printf '#mtree\n./d type=dir mode=0000\n./d/f type=file mode=0000 contents=%s\n' "$T/m0/ycontent" > "$T/m0/file.mtree"
  ( cd "$T/m0" && tar --format ustar -czf "$T/m0-sym.tgz" @sym.mtree && tar --format ustar -czf "$T/m0-file.tgz" @file.mtree )
}
# the mode-000 directory hiding a merged symlink: open refuses on the ON-DISK check and the opened dir
# is gone; a mode-000 directory holding a regular file opens readable
arm_m0() {
  arm_dir m0sym; craft_m0; tar_pkg "$1" "$T/m0-sym.tgz" || return 1
  P=$(pkg_of '')
  if offline FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    a symlink inside a mode-000 directory was accepted"; return 1; fi
  grep -q 'on disk, an extracted entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -d "$P"/opened-* 2>/dev/null)" ] && [ "$(cat "$T/adcanary")" = adcanary ] || { echo "    the opened dir is left, or the canary changed"; return 1; }
  arm_dir m0file; craft_m0; tar_pkg "$1" "$T/m0-file.tgz" || return 1
  P=$(pkg_of '')
  offline FAKE_TLE_DECRYPT=open sh "$1" open "$P" && [ "$(cat "$(ls -d "$P"/opened-* | head -1)/d/f")" = regular-content ] \
    || { echo "    a mode-000 directory with a regular file did not open readable:"; show "$T/out.log"; return 1; }
}
# a refused extraction that cannot be removed (tarbin/rm refuses it) is reported, naming the path
arm_xv_gone() {
  arm_dir xvgone; craft_m0; tar_pkg "$1" "$T/m0-sym.tgz" || return 1
  P=$(pkg_of '')
  if offline PATH="$T/tarbin:$T/fakebin:$PATH" FAKE_RM_FAIL=1 FAKE_TLE_DECRYPT=open sh "$1" open "$P"; then echo "    open succeeded"; return 1; fi
  grep -q "could not remove $P/opened-[0-9TZ]* after refusing it: decrypted content may remain" "$T/out.log" || { echo "    an extraction that could not be removed was not reported:"; show "$T/out.log"; return 1; }
  for O in "$P"/opened-*; do find "$O" -type d -exec chmod u+rwx {} \; ; rm -rf "$O"; done
}
# ── S2 re-review M-5: a source whose identity cannot be read is not sealed (and so never deleted) ─
arm_src_id() {
  arm_dir srcid; newsrc srcid
  if offline PATH="$T/tarbin:$T/fakebin:$PATH" FAKE_STAT_FAIL=1 sh "$1" seal "$T/srcs/src"; then echo "    SEALED a source whose identity could not be read"; fi
  [ -f "$T/srcs/src" ] || { echo "    the source was DELETED"; return 1; }
  grep -q 'cannot identify .* (stat failed): refusing' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_of src-)" ] || { echo "    a package was left behind"; return 1; }
}

# ── Task S2 §5: SEALED.txt at seal time ─────────────────────────────────────────────────────────
# a vt-broadcast that is not runnable refuses the seal BEFORE anything is read; the source is kept
arm_need_vtb() {
  arm_dir needvtb; newsrc needvtb
  if offline VT_BROADCAST="$T/nonexistent-vtb" sh "$1" seal "$T/srcs/src"; then echo "    SEALED without a runnable vt-broadcast"; return 1; fi
  grep -q 'the broadcast tool is not runnable' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -f "$T/srcs/src" ] && [ -z "$(ls -A "$FO")" ] || { echo "    the source was touched or something was written"; return 1; }
}
# fake_vtb: env-names works, seal-text refuses (a SEALED.txt that cannot be written)
fake_vtb() {
  printf '#!/bin/sh\ncase $1 in env-names) echo PATH ;; seal-text) echo "refused sealed.selfcheck: synthetic failure" >&2; exit 2 ;; *) exit 64 ;; esac\n' > "$T/fakevtb"
  chmod +x "$T/fakevtb"
}
# a SEALED.txt that cannot be written: the seal does NOT report success, the package is kept, the
# message says how to write the text, and the SOURCE IS NOT DELETED
arm_sealed_txt_fail() {
  arm_dir sealtxt; newsrc sealtxt; fake_vtb
  if offline VT_BROADCAST="$T/fakevtb" sh "$1" seal "$T/srcs/src"; then echo "    reported success without SEALED.txt"; return 1; fi
  P=$(pkg_of src-)
  grep -q "SEALED.txt could not be written (refused sealed.selfcheck: synthetic failure). The package is complete and kept at" "$T/out.log" \
    && grep -q -- "seal-text $P --write -- until then this seal has NOT finished" "$T/out.log" \
    && [ -f "$P/README.txt" ] && [ ! -e "$P/SEALED.txt" ] && [ -f "$T/srcs/src" ] && ! grep -q '^  package    ' "$T/out.log" \
    || { echo "    not refused as a kept, unfinished package with the source kept:"; show "$T/out.log"; return 1; }
}
# an ordinary seal ends with SEALED.txt: path, bytes and sha256 printed; the file is the one
# seal-text builds (re-running seal-text --write on it changes nothing)
arm_sealed_txt() {
  arm_dir sealok
  printf 'synthetic stdin' | offline sh "$1" seal - || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_of '')
  grep -q "^  SEALED.txt $P/SEALED.txt  $(wc -c < "$P/SEALED.txt" | tr -d ' ') bytes  sha256 $(shasum -a 256 "$P/SEALED.txt" | cut -d' ' -f1)\$" "$T/out.log" \
    && head -1 "$P/SEALED.txt" | grep -q '^== vault-timelock sealed package: self-contained, age + drand timelock ==$' \
    && "$VT_BROADCAST" seal-text "$P" --write > /dev/null 2>&1 \
    || { echo "    no SEALED.txt line, or not seal-text's own text:"; show "$T/out.log"; return 1; }
}

# ── Task S2 §7: no operator PII in the sealed payload (where it applies: the archive of a path
#    seal; timelock-key.sh has no data key file, and `seal -` seals stdin raw, with no metadata)
# a synthetic directory source, sealed offline and unwrapped from the fake tle's 4-line header:
# ZERO occurrences of the operator's login name, full name, short host name, $HOME, UTC offset
# (±HH:MM), today's date (UTC and local) and uid as a word. Counts only, never a value. Strings
# shorter than 3 characters are not searched. (The source's own names, mtimes and modes are its
# content: they are not searched for, and the tar headers store mtimes as octal numbers.)
arm_pii_scan() {
  arm_dir piiscan; rm -rf "$T/srcs/pdir"; mkdir -p "$T/srcs/pdir/sub"; echo "synthetic one" > "$T/srcs/pdir/one"; echo "synthetic two" > "$T/srcs/pdir/sub/two"
  offline sh "$1" seal "$T/srcs/pdir" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  tail -n +5 "$(pkg_of pdir-)/secret.tar.gz.age" | { gzip -dc 2>/dev/null || [ $? = 2 ]; } > "$T/pii.tar" || { echo "    the payload is not gzip"; return 1; }
  _z=$(date +%z); _bad=0
  for kv in "login-name=$(id -un)" "full-name=$(id -F 2>/dev/null || true)" "host-name=$(hostname -s)" "home-dir=$HOME" \
            "tz-offset=${_z%??}:${_z#???}" "date-utc=$(date -u +%Y-%m-%d)" "date-local=$(date +%Y-%m-%d)"; do
    _v=${kv#*=}; [ ${#_v} -ge 3 ] || continue
    _n=$(LC_ALL=C grep -a -o -F -- "$_v" "$T/pii.tar" | wc -l | tr -d ' ')
    [ "$_n" = 0 ] || { echo "    ${kv%%=*}: $_n occurrence(s) in the sealed payload"; _bad=1; }
  done
  _n=$(LC_ALL=C grep -a -c -w -- "$(id -u)" "$T/pii.tar" || true)
  [ "$_n" = 0 ] || { echo "    uid: $_n line(s) with the uid as a word"; _bad=1; }
  return $_bad
}

# ── Task S2 §6: the random offset that unlinks the round from the sealing moment ─────────────────
# le32 N: N's 4 bytes, little-endian (od -tu4 reads the host order; arm64 and x86 are little-endian)
le32() { _l=; for _sh in 0 8 16 24; do _l="$_l\\$(printf %03o $(( ($1 >> _sh) & 255 )))"; done; printf "$_l"; }
# the default maximum is min(24 h, L/10); 120 SEEDED draws through the test seam TL_JITTER_SOURCE
# (values (i * 2654435761 + 12345) mod 2^32, plus 0 and the largest accepted value) give exactly
# value mod (max+1), always within [0, max]; a value at or above the rejection limit is redrawn,
# so a source that only ever gives one is refused
arm_jitter_draws() {
  _bad=0
  for kv in 10=86400 30d=86400 1h=360 10m=60 90s=9; do
    [ "$(sh "$1" jitter-max "${kv%%=*}")" = "${kv#*=}" ] || { echo "    jitter-max ${kv%%=*} is not ${kv#*=}"; _bad=1; }
  done
  for m in 86400 360 60; do
    _n=$(( m + 1 )); _lim=$(( 4294967296 / _n * _n )); i=0
    while [ $i -lt 40 ]; do
      v=$(( (i * 2654435761 + 12345) % 4294967296 )); [ $i != 38 ] || v=0; [ $i != 39 ] || v=$(( _lim - 1 ))
      le32 "$v" > "$T/jsrc"
      j=$(TL_JITTER_SOURCE="$T/jsrc" sh "$1" jitter-draw "$m" 2>/dev/null) || j=REJECTED
      if [ "$v" -lt "$_lim" ]; then
        [ "$j" = $(( v % _n )) ] && [ "$j" -ge 0 ] && [ "$j" -le "$m" ] || { echo "    the draw of $v with max $m gave $j"; _bad=1; }
      else [ "$j" = REJECTED ] || { echo "    the rejected value $v gave $j"; _bad=1; }; fi
      i=$((i + 1))
    done
  done
  le32 4294967295 > "$T/jsrc"
  if TL_JITTER_SOURCE="$T/jsrc" sh "$1" jitter-draw 86400 >/dev/null 2>&1; then echo "    2^32-1 (above the limit for 86401) was not rejected"; _bad=1; fi
  return $_bad
}
# jitter_round_ok R BEFORE AFTER SECONDS: R is the round of a target in [BEFORE+SECONDS, AFTER+SECONDS]
jitter_round_ok() { [ "$1" -ge "$(round_for $(( $2 + $4 )) "$GENESIS" "$PERIOD")" ] && [ "$1" -le "$(round_for $(( $3 + $4 )) "$GENESIS" "$PERIOD")" ]; }
# a 1h seal draws its offset (359 s, from the seam) into the round, prints only the maximum (6m),
# and never the draw; --jitter 0 seals without an offset and warns; --jitter above the duration
# is refused
arm_jitter_seal() {
  arm_dir jit; le32 359 > "$T/jsrc"
  _b=$(date -u +%s); printf x | offline TL_TEST_SECONDS= TL_JITTER_SOURCE="$T/jsrc" sh "$1" seal - 1h || { echo "    the 1h seal failed:"; show "$T/out.log"; return 1; }; _a=$(date -u +%s)
  R=$(cat "$(pkg_of '')/round")
  jitter_round_ok "$R" "$_b" "$_a" 3959 || { echo "    round $R does not include the offset (359 s)"; return 1; }
  grep -q 'requested: 1h (+ random offset up to 6m); offset drawn from TL_JITTER_SOURCE (self-test))' "$T/out.log" \
    && grep -q 'Requested: 1h (+ random offset up to 6m); offset drawn from TL_JITTER_SOURCE (self-test)\.' "$(pkg_of '')/README.txt" \
    || { echo "    the banner or README does not give the maximum:"; show "$T/out.log"; return 1; }
  ! grep -q '359' "$(pkg_of '')/README.txt" || { echo "    the README prints the draw"; return 1; }
  arm_dir jit0
  _b=$(date -u +%s); printf x | offline TL_TEST_SECONDS= sh "$1" seal - 1h --jitter 0 || { echo "    the --jitter 0 seal failed:"; show "$T/out.log"; return 1; }; _a=$(date -u +%s)
  jitter_round_ok "$(cat "$(pkg_of '')/round")" "$_b" "$_a" 3600 || { echo "    --jitter 0 still moved the round"; return 1; }
  grep -q -- '★ --jitter 0: no random offset. The round then gives away the moment of sealing to within 3 s' "$T/out.log" || { echo "    no --jitter 0 warning"; return 1; }
  arm_dir jitbig
  if printf x | offline TL_TEST_SECONDS= sh "$1" seal - 1h --jitter 2h; then echo "    an offset longer than the duration was SEALED"; return 1; fi
  grep -q 'is longer than the duration' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}

# ── Task S2 §5: the LITERAL REHEARSAL. Only SEALED.txt is copied into an empty directory, and the
#    commands are read FROM it: every "     $ " line of the steps asked for, run exactly as printed
#    (sh -c, stdin /dev/null), in order, stopping at the first failure. No command of the text is
#    repeated here, so a wording or command change in sealed.ts is what gets tested.
# literal_steps SEALED FIRST LAST: the printed commands of steps FIRST..LAST ("1b" counts as 1)
literal_steps() {
  awk -v a="$2" -v b="$3" '/^  [0-9]+b?\. / { n = $1; sub(/b?\.$/, "", n); n += 0 } /^     \$ / && n >= a && n <= b { sub(/^     \$ /, ""); print }' "$1"
}
# lit_init DIR TEXT: DIR is a new, empty directory holding only TEXT, as SEALED.txt
lit_init() { rm -rf "$1" "$1.out" "$1.cmds"; mkdir -p "$1" && cp "$2" "$1/SEALED.txt" && [ "$(ls -A "$1")" = SEALED.txt ]; }
# lit_run DIR FIRST LAST [PROFILE]: run the printed commands of steps FIRST..LAST in DIR (under the
#   sandbox PROFILE if given), output in DIR.out. A failing `tle --decrypt` that says "too early" is
#   retried (5 times, 3 s apart: drand may publish a little late) after deleting the empty output file
#   it leaves, as the text tells its reader to.
lit_run() {
  literal_steps "$1/SEALED.txt" "$2" "$3" > "$1.cmds"
  [ -s "$1.cmds" ] || { echo "    SEALED.txt prints no command for steps $2-$3"; return 1; }
  : > "$1.out"
  while IFS= read -r _lc; do
    _ln=0
    until ( cd "$1" && if [ -n "${4:-}" ]; then sandbox-exec -p "$4" sh -c "$_lc"; else sh -c "$_lc"; fi ) < /dev/null >> "$1.out" 2>&1; do
      case $_lc in *"tle --decrypt"*) ;; *) echo "    the printed command failed: $_lc"; show "$1.out"; return 1 ;; esac
      grep -q 'too early' "$1.out" && [ "$_ln" -lt 5 ] || { echo "    the printed tle step failed: $_lc"; show "$1.out"; return 1; }
      rm -f "$1/$(printf '%s\n' "$_lc" | sed -n 's/.*--output=\([^ ]*\).*/\1/p')"; _ln=$((_ln + 1)); sleep 3
    done
  done < "$1.cmds"
}
# lit_early DIR STEP OUT: the printed tle step, before the round, through Tor under TOR_ONLY, must
#   fail with "too early" and leave an EMPTY OUT, exactly what the text warns its reader about
lit_early() {
  literal_steps "$1/SEALED.txt" "$2" "$2" > "$1.cmds"
  if ( cd "$1" && sandbox-exec -p "$TOR_ONLY" sh -c "$(cat "$1.cmds")" ) < /dev/null > "$1.early" 2>&1; then echo "    the printed tle step OPENED before the round"; return 1; fi
  grep -q 'too early' "$1.early" && [ -f "$1/$3" ] && [ ! -s "$1/$3" ] || { echo "    not 'too early' with an empty $3 left behind:"; show "$1.early"; ls -la "$1" | show; return 1; }
  rm -f "$1/$3"
}

# ── self-test: the lock must work in BOTH directions ────────────────────────────────────────
# A script that only demonstrates "it did not open" cannot tell LOCKED from BROKEN. Every REAL drand
# contact below runs under sandbox-exec with B §6.1's profile (TOR_ONLY): the kernel allows exactly
# one outbound destination, Tor's SOCKS port. The plumbing arms run on fakes, offline; their
# mutation arms run the same arm on a one-line mutant that must fail.
cmd_selftest() {
  need
  command -v sandbox-exec >/dev/null 2>&1 || die "sandbox-exec required: the real drand contacts run Tor-only"
  SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  ok=0
  # ★ every seal below inherits this, so the suite can never write into the REAL data dir; and
  #   TMPDIR is the suite's own, checked empty at the end
  export VAULT_TIMELOCK_DIR="$T/out"
  mkdir -p "$T/tmp"; export TMPDIR="$T/tmp"
  # SEALED.txt (Task S2 §5): every seal here writes it with the repo's own vt-broadcast (the arms run
  # MUTANT copies from $T, beside no broadcast/). VT_CONFINED=1: the wrapper then runs node directly
  # (env -i still): many seals here run inside sandbox-exec already, and macOS refuses a second
  # profile; seal-text and env-names are offline. The wrapper's own sandbox is broadcast's test.
  export VT_BROADCAST="$(dirname "$SELF")/broadcast/bin/vt-broadcast" VT_CONFINED=1

  # ── the DURATION grammar (Task S1 §1, §4): offline, and first ──────────────────────────────
  if arm_grammar "$SELF" > "$T/g" 2>&1
  then echo "  OK   DURATION: $(grep -c '^A' "$T/grammar.tsv") accepted forms give their exact seconds; $(grep -c '^R' "$T/grammar.tsv") refused forms are refused for the listed reason"
  else echo "  FAIL DURATION grammar"; sed 's/^/     /' "$T/g"; ok=1; fi
  check "the shared code (die, quicknet constants, the archive scrub flags, iso_of/round_iso/round_of, duration grammar, drand-through-Tor block, tar entry check, verified extraction) is byte-identical in $(basename "$SELF") and 1password-timelock.sh" \
    arm_same_shared "$SELF" "$(dirname "$SELF")/1password-timelock.sh"
  mut_arm zero d arm_grammar "blanking the zero refusal" "'0d' ACCEPTED"
  mut_arm order d arm_grammar "blanking the y-d-h-m-s order check" "'1h1d' ACCEPTED"
  mut_arm cap d arm_grammar "blanking the 100-year cap" "'3155695201s' ACCEPTED"
  echo x > "$T/two-src"
  if ( cd "$T" && sh "$SELF" seal "$T/two-src" 10 20 ) > "$T/two" 2>&1; then echo "  FAIL two durations were accepted"; ok=1
  else grep -q "more than one duration: '10' and '20'" "$T/two" && [ -f "$T/two-src" ] \
       && echo "  OK   two durations are refused before anything runs (the source is untouched)" \
       || { echo "  FAIL two durations refused for the wrong reason"; sed 's/^/     /' "$T/two"; ok=1; }; fi
  make_fakes

  # ── TWO REAL SEALS through Tor, under the Tor-only sandbox (Task S1 §2, §4, §5, §6), 60-second
  #    horizons so the open-after-the-round path is reachable. ★★ THE POSITIVE ARM IS A REAL SEAL
  #    THAT WE WAIT OUT: `tle` refuses to encrypt to a PAST round, so the only way to show the lock
  #    OPENS is to let time pass. A test that only ever shows "did not open" cannot tell LOCKED
  #    from BROKEN.
  #      bin: a path, binary, with a unit duration (its horizon text is checked, Task S1 §1);
  #      arm: stdin (`-`), --armor, with TMPDIR pointed at an EMPTY dir that must stay empty.
  echo "canary-$(date -u +%s)" > "$T/plain"
  mkdir -p "$T/real" "$T/tmp-real"; cp "$T/plain" "$T/real/src"
  if ( cd "$T/real" && TL_TEST_SECONDS=60 sandbox-exec -p "$TOR_LOOP" sh "$SELF" seal "$T/real/src" 40m ) > "$T/log-bin" 2>&1 \
     && [ ! -e "$T/real/src" ] && grep -q 'drand      through Tor' "$T/log-bin"
  then echo "  OK   SEAL (bin), REAL drand through Tor under the Tor+loopback sandbox: sealed, and the source is gone"
  else echo "  FAIL SEAL (bin)"; sed 's/^/       /' "$T/log-bin"; ok=1; fi
  if ( cd "$T/real" && TL_TEST_SECONDS=60 TMPDIR="$T/tmp-real" sandbox-exec -p "$TOR_LOOP" sh "$SELF" seal - --armor < "$T/plain" ) > "$T/log-arm" 2>&1 \
     && grep -q 'drand      through Tor' "$T/log-arm"
  then echo "  OK   SEAL (arm: stdin, --armor), REAL drand through Tor under the Tor+loopback sandbox"
  else echo "  FAIL SEAL (arm)"; sed 's/^/       /' "$T/log-arm"; ok=1; fi
  [ -z "$(ls -A "$T/tmp-real")" ] && [ -z "$(ls -A "$T/real")" ] \
    && echo "  OK   the real stdin seal left its EMPTY TMPDIR empty, and nothing landed in the cwd" \
    || { echo "  FAIL the real seals left files behind:"; ls -A "$T/tmp-real" "$T/real" | sed 's/^/       /'; ok=1; }
  PB=$(ls -d "$T"/out/src-timelock-* 2>/dev/null | head -1); PA=$(ls -d "$T"/out/timelock-* 2>/dev/null | head -1)
  if [ -f "$PB/round" ] && [ -f "$PA/round" ]; then
    if is_binary_age "$PB/secret.tar.gz.age" && [ ! -e "$PB/ARMOR" ]
    then echo "  OK   without --armor the .age is binary (age-encryption.org/v1), no ARMOR file"
    else echo "  FAIL binary format"; ok=1; fi
    if is_armored "$PA/payload.age" && [ "$(cat "$PA/ARMOR" 2>/dev/null)" = pem ] && [ "$(cat "$PA/encoding")" = raw ]
    then echo "  OK   with --armor payload.age is PEM-armored age in 64 columns, ARMOR says pem, encoding says raw"
    else echo "  FAIL armored stdin format"; head -3 "$PA/payload.age" | sed 's/^/       /'; ok=1; fi
    # the horizon: the round's exact UTC time + the round + the duration as typed; no "years"
    HR=$(cat "$PB/round"); HW=$(round_iso "$HR")
    if grep -q "CANNOT BE OPENED UNTIL $HW\$" "$PB/README.txt" \
       && grep -q "^Sealed .*Unlocks $HW (UTC), when drand publishes\$" "$PB/README.txt" \
       && grep -q "^round $HR\. Requested: 40m; overridden by TL_TEST_SECONDS=60 (self-test)\.\$" "$PB/README.txt" \
       && grep -q "opens      $HW  (drand round $HR; requested: 40m;" "$T/log-bin" && ! grep -qi 'year' "$PB/README.txt" \
       && grep -q 'drand contacted     through Tor only' "$PB/README.txt"
    then echo "  OK   a 40m seal: README and banner give $HW (UTC), round $HR, 'requested: 40m', 'through Tor only'; no years"
    else echo "  FAIL the horizon text"; sed -n '1,16p' "$PB/README.txt" | sed 's/^/       /'; ok=1; fi

    for P in "$PB" "$PA"; do
      L=bin; [ "$P" = "$PA" ] && L=arm
      PW=$(round_iso "$(cat "$P/round")")
      if ( cd "$T" && sandbox-exec -p "$TOR_ONLY" sh "$SELF" open "$P" ) > "$T/o1" 2>&1; then echo "  FAIL ($L) opened BEFORE its round — nothing is locked"; ok=1
      elif grep -q "locked until $PW (UTC), drand round $(cat "$P/round")" "$T/o1"
      then echo "  OK   open ($L) refuses before the round (drand through Tor), saying: locked until $PW (UTC)"
      else echo "  FAIL open refused for the wrong reason"; sed 's/^/       /' "$T/o1"; ok=1; fi
    done

    # ── ★ the LITERAL REHEARSAL, part 1 (Task S2 §5): each package's SEALED.txt ALONE in an empty
    #    directory; its printed steps 1-2 (cut, check) run exactly as printed; its printed tle step,
    #    before the round, through Tor, refuses "too early" and leaves the EMPTY file it warns about
    for P in "$PB" "$PA"; do
      if [ "$P" = "$PA" ]; then L=arm; F=payload.age; O=content; else L=bin; F=secret.tar.gz.age; O=secret.tar.gz; fi
      if lit_init "$T/lit-$L" "$P/SEALED.txt" && lit_run "$T/lit-$L" 1 2 > "$T/lit.log" 2>&1 \
         && [ "$(grep -c '^OK ' "$T/lit-$L.out")" = 1 ] && grep -q "^OK $F\$" "$T/lit-$L.out" \
         && lit_early "$T/lit-$L" 3 "$O" >> "$T/lit.log" 2>&1
      then echo "  OK   LITERAL ($L): SEALED.txt alone; its printed steps 1-2 cut out and verify $F; its printed tle step says 'too early' before the round and leaves an empty $O, as it warns"
      else echo "  FAIL LITERAL ($L) before the round"; show "$T/lit.log"; ok=1; fi
    done

    R=$(cat "$PB/round"); [ "$(cat "$PA/round")" -le "$R" ] || R=$(cat "$PA/round")
    echo "  ..   waiting for round $R ($(round_iso "$R"))"; wait_round "$R"
    # ── ★ the LITERAL REHEARSAL, part 2: the printed tle step (through Tor under TOR_ONLY) and, for
    #    the path seal, the printed extraction recover exactly what was sealed
    if lit_run "$T/lit-bin" 3 4 "$TOR_ONLY" > "$T/lit.log" 2>&1 && cmp -s "$T/lit-bin/restored/src" "$T/plain"
    then echo "  OK   LITERAL (bin): after the round, its printed steps 3-4 (tle through Tor, tar) restore the sealed file byte for byte"
    else echo "  FAIL LITERAL (bin) after the round"; show "$T/lit.log"; ok=1; fi
    if lit_run "$T/lit-arm" 3 3 "$TOR_ONLY" > "$T/lit.log" 2>&1 && cmp -s "$T/lit-arm/content" "$T/plain"
    then echo "  OK   LITERAL (arm): after the round, its printed step 3 (tle through Tor) gives back the sealed bytes exactly"
    else echo "  FAIL LITERAL (arm) after the round"; show "$T/lit.log"; ok=1; fi
    # ...and ONE altered printed step makes it fail (the arm runs what the text prints, nothing else)
    for m in "cut|s/{ f = \$2; next }/{ f = \"\"; next }/" "extract|s/tar -xzf secret.tar.gz -C restored/tar -xzf secret.tgz -C restored/"; do
      sed "${m#*|}" "$PB/SEALED.txt" > "$T/lit-mut.txt"
      if cmp -s "$PB/SEALED.txt" "$T/lit-mut.txt"; then echo "  FAIL MUTANT literal/${m%%|*}: the alteration changed nothing"; ok=1
      elif lit_init "$T/lit-mut" "$T/lit-mut.txt" && lit_run "$T/lit-mut" 1 4 "$TOR_ONLY" > "$T/lit.log" 2>&1 && cmp -s "$T/lit-mut/restored/src" "$T/plain"
      then echo "  FAIL MUTANT literal/${m%%|*} SURVIVED: the altered text still restored the file"; ok=1
      else echo "  OK   MUTANT literal/${m%%|*} killed: altering the printed $( [ "${m%%|*}" = cut ] && echo 'step 1 (awk)' || echo 'step 4 (tar)' ) makes the literal rehearsal FAIL (it passes unaltered, above)"; fi
    done

    for P in "$PB" "$PA"; do
      if [ "$P" = "$PA" ]; then L=arm; OUTF=content; IN=payload.age; else L=bin; OUTF=src; IN=secret.tar.gz.age; fi
      n=0   # drand may publish a little late: "locked" is retried, nothing else is
      until ( cd "$T" && sandbox-exec -p "$TOR_ONLY" sh "$SELF" open "$P" ) > "$T/o2" 2>&1 \
            || ! grep -q 'locked until' "$T/o2" || [ $n -ge 5 ]; do n=$((n+1)); sleep 3; done
      O=$(ls -d "$P"/opened-* 2>/dev/null | head -1)
      if [ -n "$O" ] && cmp -s "$O/$OUTF" "$T/plain"
      then echo "  OK   POSITIVE ($L): the round arrived, the package OPENED (drand through Tor) into $(basename "$O")/ and round-tripped the canary"
      else echo "  FAIL POSITIVE ($L): the round arrived and it did NOT open — broken, not locked"; sed 's/^/       /' "$T/o2"; ok=1; fi
      rm -rf "$P"/opened-*
      tamper_mid "$P/$IN"
      if ( cd "$T" && sandbox-exec -p "$TOR_ONLY" sh "$SELF" open "$P" ) > "$T/o3" 2>&1; then echo "  FAIL ($L) a tampered package OPENED"; ok=1
      elif grep -q 'could not open' "$T/o3" && ! grep -q 'locked until' "$T/o3"
      then echo "  OK   ($L) one changed byte in the .age is caught: open refuses"
      else echo "  FAIL ($L) tampering refused for the wrong reason"; sed 's/^/       /' "$T/o3"; ok=1; fi
    done
  else echo "  FAIL no packages to test"; ok=1; fi

  # ── --armor reaches both tle calls: offline seals on this script and on two mutants (Task S1 §4)
  check "--armor (fake tle/curl, offline): the path seal's and the stdin seal's .age are armored, ARMOR says pem" arm_armor "$SELF"
  mut_arm armor-path 's/ \$ARMOR_FLAG//' arm_armor "dropping --armor from the path seal's tle call" "secret.tar.gz.age is not canonical age ASCII armor"
  mut_arm stdin-check/armor 's/ \$ARMOR_FLAG//' arm_armor "dropping --armor from the stdin seal's tle call" "payload.age is not canonical age ASCII armor"

  # ── drand ONLY through Tor (R40, Task S1 §6): fakes log every call, offline ────────────────
  check "every curl and tle call (path seal, stdin seal, open) went to socks5h://drand.<minute>:x@127.0.0.1:9050, NO_PROXY=* and a decoy proxy notwithstanding" arm_routes "$SELF"
  mut_arm curl-proxy 's/ --proxy "\$(drand_proxy)"//' arm_routes "dropping --proxy from curl" "curl DIRECT"
  mut_arm tle-proxy 's/ HTTPS_PROXY="\$_tp" https_proxy="\$_tp"//' arm_routes "dropping HTTPS_PROXY from tle's environment" "tle decrypt DIRECT"
  mut_arm status-proxy 's/ --proxy "\$(drand_proxy)"//' arm_routes "dropping --proxy from the HTTP 425 check" "curl DIRECT"
  mut_arm armor-path/pin 's/ --network="http:\/\/127.0.0.1:\$INFO_PORT"//' arm_routes "letting tle fetch the chain info itself (path seal)" "did NOT use the pinned loopback chain info"
  mut_arm stdin-check/pin 's/ --network="http:\/\/127.0.0.1:\$INFO_PORT"//' arm_routes "letting tle fetch the chain info itself (stdin seal)" "did NOT use the pinned loopback chain info"
  mut_arm tle-proxy/noproxy 's/ -u NO_PROXY -u no_proxy//' arm_routes "leaving NO_PROXY in tle's environment" "TOR-with-NO_PROXY"
  check "--clearnet is the one bypass: every call direct, and the banner and README say so" arm_clearnet "$SELF"
  check "Tor down (its SOCKS port unreachable): refused before any drand call; the source untouched" arm_tor_down "$SELF"
  mut_arm tor-preflight d arm_tor_down "blanking the Tor preflight" "SEALED with Tor unreachable"
  check "quicknet pinned: a wrong hash, genesis_time, period, public_key or schemeID from a mirror is refused" arm_pin "$SELF"
  mut_arm pin 's/|| die /|| true /' arm_pin "disabling the quicknet pin" "SEALED"
  check "the LOCAL negative control refuses a round inside the 5-round margin, before encrypting" arm_local_control "$SELF"
  mut_arm local-control 's/|| die /|| true /' arm_local_control "disabling the local round check" "SEALED"
  check "drand's control: a file that OPENS NOW is refused and removed" arm_drand_control "$SELF"
  mut_arm drand-control 's/then die /then true /' arm_drand_control "disabling the 'opens now' refusal" "refused for another reason"
  check "any drand answer but 'too early' fails closed: refused, no package" arm_drand_reason "$SELF"
  mut_arm drand-reason 's/\*) die /*) true /' arm_drand_reason "accepting a non-'too early' answer" "SEALED although"
  check "the relay must answer HTTP 425 for the round: 200, 500 or no answer (000) refuses, saying which" arm_drand_425 "$SELF"
  mut_arm drand-425 's/|| die /|| true /' arm_drand_425 "accepting any HTTP status" "SEALED although drand answered HTTP 200"
  check "a network error from tle (a slow circuit) is retried, then drand's answer counts" arm_retry "$SELF"
  check "open after the round: tle's 'too early' is reported as a fetch failure, not a lock (F-17)" arm_open_passed "$SELF"
  mut_arm open-passed d arm_open_passed "dropping the passed-round check" "reported as locked"

  # ── plaintext hygiene (Task S1 §5; audit K19, SA-N10) ──────────────────────────────────────
  check "seal - with an EMPTY TMPDIR leaves it empty, as payload.age + encoding=raw (and a spill IS caught)" arm_tmpdir "$SELF"
  check "a tle failure mid-stream (seal - and seal <path>) is refused: no half package, the source kept" arm_stdin_check "$SELF"
  mut_arm stdin-check 's/|| die /|| true /' arm_stdin_check "ignoring tle's exit status on stdin" "SEALED"
  mut_arm stdin-check/tempfile 's/tle_env --encrypt/_x=$(mktemp) \&\& cat > "$_x" \&\& tle_env --encrypt/' arm_tmpdir "spooling stdin through a temp file first (the old K19 leak)" "a temp write is denied here"
  check "the package lands under the data dir (never the cwd), 0700 under umask 022; open finds it by bare name" arm_out_dir "$SELF"
  mut_arm out-dir 's/\$OUT\///g' arm_out_dir "writing the package into the cwd" "landed in the cwd"
  mut_arm pkg-mode 's/mkdir -m 700 "\$PKG"/mkdir "$PKG"/' arm_out_dir "creating the package dir without -m 700" "not 700"
  check "a data dir that is a symlink is refused; nothing is written through it" arm_out_symlink "$SELF"
  mut_arm out-symlink d arm_out_symlink "blanking the symlinked-data-dir refusal" "SEALED through a symlinked data dir"

  # ── open never follows a planted symlink (commit security review of 827e4ed) ───────────────
  check "symlinks planted as content / secret.tar.gz / src: open writes only into a new opened-<stamp>/, the file they point at is untouched" arm_open_symlink "$SELF"
  mut_arm open-target 's/--output="\$OD\/\$PLAIN"/--output="$DIR\/$PLAIN"/' arm_open_symlink "decrypting into the package dir again" "redirected open's write"
  check "a tarball with a symlink entry: refused with the reason, nothing extracted" arm_open_tar_type "$SELF"
  mut_arm tar-type 's/|| die /|| true /' arm_open_tar_type "blanking the listing's entry-type check (the on-disk check then refuses instead)" "refused for another reason"
  check "a tarball with a ../x entry: refused with the reason, nothing written outside" arm_open_tar_path "$SELF"
  mut_arm tar-path 's/|| die /|| true /' arm_open_tar_path "blanking the path check (bsdtar's own default then refuses '..')" "refused for another reason"
  check "a tarball with a HARDLINK entry: refused with the reason, nothing extracted" arm_open_tar_hard "$SELF"
  check "a tarball with an ABSOLUTE-path entry: refused with the reason, nothing extracted" arm_open_tar_abs "$SELF"

  # ── fix round 1 (Task S1 review): tar fails closed, directory sources kept, untrusted text ──
  make_tarbin
  check "seal <path>: a tar that FAILS mid-stream is refused; the source is byte-identical; no package" arm_tar_fail "$SELF"
  mut_arm tar-status 's/|| die /|| true /' arm_tar_fail "ignoring tar's exit status" "the source CHANGED or was deleted"
  check "seal <path>: an archive holding LESS than the source (tar exit 0) is refused; the source is kept" arm_tar_short "$SELF"
  mut_arm tar-listing 's/|| die /|| true /' arm_tar_short "skipping the find-vs-tar listing check" "SEALED an archive missing an entry"
  check "a DIRECTORY source is sealed and left in place, and the output says so; a symlink source is refused" arm_dir_source "$SELF"
  check "a round file that is not a round number is printed as '(invalid round file)', never raw" arm_round_text "$SELF"
  mut_arm round-text d arm_round_text "printing the round file raw" "printed raw"

  # ── fix round 2 (Task S1 re-review): symlinked / special sources, the source's identity ────
  check "seal linkdir/ (a symlink to a directory, trailing slash) is refused as a symlink; nothing written" arm_src_slash "$SELF"
  mut_arm src-symlink 's/|| die /|| true /' arm_src_slash "dropping the symlink-source refusal" "refused for another reason"
  check "a dir with a symlink / hard-linked file / FIFO, a FIFO source, a hard-linked file: refused at SEAL time, source kept" arm_src_special "$SELF"
  mut_arm seal-entries 's/|| die /|| true /' arm_src_special "dropping the seal-time entry check" "which open could not extract"
  check "a source file REPLACED between tar and deletion is kept, and so is the package; the reason is given" arm_src_replaced "$SELF"
  mut_arm src-identity 's/|| die /|| true /' arm_src_replaced "dropping the identity re-check before deletion" "the replaced source was DELETED"

  # ── Task S2 §6: the random offset (seeded draws through the seam; offline seals) ────────────
  check "the random offset: default max min(24h, L/10); 120 seeded draws are exact and within [0, max]; rejected values are redrawn" arm_jitter_draws "$SELF"
  check "a 1h seal's round includes the drawn offset, the outputs print only its maximum; --jitter 0 warns and adds none; --jitter above the duration is refused" arm_jitter_seal "$SELF"
  mut_arm jitter 's/ + J//' arm_jitter_seal "dropping the offset from the target" "does not include the offset"

  # ── Task S2 §2: no metadata of the sealing account in the archive (offline, decrypted) ─────────
  check "the decrypted archive: gzip MTIME 0 and no name; no login name, no xattr records, no ._ entries; owner 0/0 nobody; the source untouched" arm_scrub "$SELF"
  mut_arm scrub/owner 's/ --uid 0 --gid 0 --uname nobody --gname nobody//' arm_scrub "dropping the owner override" "the login name occurs"
  mut_arm scrub/xattr 's/--format ustar --no-mac-metadata --no-xattrs/--no-mac-metadata/' arm_scrub "dropping ustar and --no-xattrs" "xattr records in the archive"
  mut_arm gzip 's/gzip:!timestamp,//' arm_scrub "bsdtar's gzip with its timestamp" "gzip header MTIME is not 0"

  # ── S2 safety review: extraction verified ON DISK; chain info parsed as JSON (offline) ────────
  check "an AppleDouble '._y' symlink that tar -tv lists as a regular file: open refuses on the ON-DISK check, removes the extraction, the canary untouched" arm_ad_sym "$SELF"
  mut_arm disk-type d arm_ad_sym "dropping the on-disk entry-type check" "an AppleDouble-merged symlink was EXTRACTED"
  check "AppleDouble ACL/xattr members (on a file, on the extraction root): --no-mac-metadata drops them; nothing on disk carries an xattr or ACL" arm_ad_acl "$SELF"
  mut_arm xtract 's/ --no-mac-metadata//' arm_ad_acl "extracting without --no-mac-metadata" "open refused the AppleDouble"
  check "a tar that ignores the flags and applies the ACL: the on-disk attribute check refuses and removes the extraction" arm_ad_attr "$SELF"
  mut_arm disk-attr d arm_ad_attr "dropping the on-disk xattr/ACL check" "an extraction carrying an ACL was accepted"
  check "drand chain info with a repeated key is refused (decoy first or last); a good one is stored and served as jq -cS bytes" arm_pin_dup "$SELF"
  mut_arm pin-dup 's/|| die /|| true /' arm_pin_dup "dropping the repeated-key refusal" "with a repeated key (dupfirst) was SEALED"

  # ── S2 re-review, fix round 2 (offline) ──────────────────────────────────────────────────────
  check "INFO_PINNED is canonical and its fields hash to CHAIN" arm_info_pinned "$SELF"
  check "chain info: a 2nd document, a case-variant key, a case-folding key, an unknown key refuse; reordered is fine; chain-info.json is INFO_PINNED" arm_pin_exact "$SELF"
  mut_arm pin-one 's/|| die /|| true /' arm_pin_exact "dropping the one-value check" "a chain info with multidoc was SEALED"
  mut_arm pin/fields 's/\. == \$w/.schemeID == $w.schemeID/' arm_pin_exact "comparing fields instead of the whole value" "a chain info with casekey was SEALED"
  check "a mode-000 directory hiding a merged symlink: refused on disk, the extraction gone; a mode-000 dir with a mode-000 file opens readable" arm_m0 "$SELF"
  mut_arm xv-chmod 's/find "\$2" -type d -exec chmod u+rwx {} \\; \&\& find "\$2" -type f -exec chmod u+rw {} + ||/true ||/' arm_m0 "skipping the owner rwx before the walk (the walk then fails closed)" "refused for another reason"
  check "a refused extraction that cannot be removed is reported, naming the path" arm_xv_gone "$SELF"
  mut_arm xv-gone d arm_xv_gone "dropping the removal check" "an extraction that could not be removed was not reported"
  check "a source whose identity stat cannot read: refused before sealing, the source kept" arm_src_id "$SELF"
  mut_arm src-id-known d arm_src_id "dropping the identity check (the deletion re-check then passes vacuously)" "the source was DELETED"

  # ── Task S2 §5: SEALED.txt at seal time (offline) ──────────────────────────────────────────
  check "every seal ends with SEALED.txt (path, bytes, sha256 printed), exactly seal-text's text" arm_sealed_txt "$SELF"
  check "vt-broadcast not runnable: refused before anything is read, the source kept, with the install hint" arm_need_vtb "$SELF"
  mut_arm need-vtb 's/|| die /|| true /' arm_need_vtb "dropping the up-front vt-broadcast check" "refused for another reason"
  check "SEALED.txt cannot be written: no success reported, the package kept, the source NOT deleted" arm_sealed_txt_fail "$SELF"
  mut_arm sealed-txt 's/if ! _sw=/if _sw=/' arm_sealed_txt_fail "ignoring seal-text's failure" "not refused as a kept, unfinished package"

  # ── Task S2 §7: no operator PII in the sealed archive (offline, decrypted) ───────────────────
  check "PII scan: the decrypted archive holds 0 occurrences of the operator's names, host, home, UTC offset, today's date or uid (counts only)" arm_pii_scan "$SELF"
  mut_arm scrub/owner 's/ --uid 0 --gid 0 --uname nobody --gname nobody//' arm_pii_scan "dropping the owner override" "login-name: [1-9]"

  echo x > "$T/gone"; obliterate "$T/gone"
  if [ -e "$T/gone" ]; then echo "  FAIL obliterate left its target"; ok=1
  else echo "  OK   obliterate removes (unlinks) its target"; fi
  [ -z "$(ls -A "$T/tmp")" ] && echo "  OK   no seal or open in this suite left anything in its TMPDIR" \
    || { echo "  FAIL left in the suite's TMPDIR:"; ls -A "$T/tmp" | sed 's/^/       /'; ok=1; }

  if [ "$ok" -eq 0 ]; then echo "  SELF-TEST PASS"; else echo "  SELF-TEST FAIL"; exit 1; fi
}

case "${1:---help}" in
  seal) shift; cmd_seal "$@" ;;
  open) shift; cmd_open "$@" ;;
  duration) [ $# -eq 2 ] || die "usage: duration <DURATION>"; duration_seconds "$2" ;;
  # test seams for the random offset (Task S2 §6): no network, nothing written
  jitter-max) [ $# -eq 2 ] || die "usage: jitter-max <DURATION>"; jitter_default "$(duration_seconds "$2")" ;;
  jitter-draw) [ $# -eq 2 ] || die "usage: jitter-draw <MAX-SECONDS>"; case $2 in ''|*[!0-9]*) die "jitter-draw: whole seconds" ;; esac; jitter_draw "$2" ;;
  --self-test) cmd_selftest ;;
  *) sed -n '2,20p' "$0" ;;
esac
