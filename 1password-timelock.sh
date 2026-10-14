#!/bin/sh
# 1password-timelock.sh — export ONE 1Password vault, PROVE every item and attachment was captured,
# seal it to a drand round (through its TIME path it stays shut while fewer than t of drand
# quicknet's key shares are combined and BLS12-381 holds; a --recovery-recipient opens it at any
# time), and remove (unlink) the plaintext work copy. Never prints a secret, a title, a URL or an email.
#
#   sh tools/1password-timelock.sh seal <vault-name> [DURATION] [--recovery-recipient age1...] [--armor]
#        [--clearnet] [--jitter DURATION] [--keep-item-metadata] [--keep-item-ids] [--allow-short-operator-strings]
#        [--list [--pad]]   # --list: every captured file its own age block (SEALED.txt format /2); --pad: size buckets
#   sh tools/1password-timelock.sh open <package-dir> [--clearnet]  # after the round: the TIME path
#   sh tools/1password-timelock.sh open <package-dir> --identity recovery.key   # the KEY path
#   sh tools/1password-timelock.sh open <package-dir> [...] --plaintext [--force]   # after the unlock time only:
#        a fully verified open also writes SEALED-plaintext.txt (every entry decrypted; mode 600; LOCAL ONLY)
#   sh tools/1password-timelock.sh duration <DURATION>           # print its seconds; no network
#   sh tools/1password-timelock.sh --self-test                   # synthetic fixture, no vault
#   DURATION: a bare number of YEARS (default 10), or N<unit> terms in the order y d h m s:
#   30d, 1h, 40m, 365d, 1y30d, 1d12h, 90s (m = minutes, no month unit; at most 100y)
#   --armor: every .age file is written ASCII-armored (PEM); `open` reads either form
#   drand is reached ONLY through Tor (127.0.0.1:9050); --clearnet is the explicit opt-out (R40)
#   --jitter: the maximum random offset added to the round (default min(24h, DURATION/10); 0 = none)
#   --keep-item-metadata / --keep-item-ids: keep account metadata / 1Password ids inside the seal
#   every seal ends by writing SEALED.txt (the self-contained text to publish) with vt-broadcast,
#   and STRUCTURE.txt (the vault's shape, every value removed; LOCAL ONLY); open re-checks it
#   packages land in ${VAULT_TIMELOCK_DIR:-${XDG_DATA_HOME:-~/.local/share}/vault-timelock}/;
#   `open` accepts a bare package name from there
#
# ─────────────────────────────────────────────────────────────────────────────────────────────
# ★★★ THE ONE FACT THAT DECIDES WHETHER THIS IS A BACKUP OR A DECORATION
#
#   `op item get --help`  →  --reveal   Don't conceal sensitive fields.
#
# **So `op item get` CONCEALS BY DEFAULT.** An export written without `--reveal` is a file full of
# concealed values that is the right size, has the right item count, passes every structural check
# a careless script would run — and restores nothing. It is a classic failure shape: the right
# command on the right artefact, measuring the wrong quantity, with no error and no empty result.
#
# This script therefore uses `--reveal`, and everything else in it follows from that decision:
# the stream now carries every secret you own, so it is never printed and never summarised by
# anything but a count or a hash. ★ It IS written to disk unencrypted, briefly: each revealed item
# lands in a private 0700 temp dir ($WORK; the round-trip check extracts into $WORK/rt) for the
# seconds the capture, seal and round-trip take, and that dir is removed on success, on failure and
# on Ctrl-C/HUP/TERM (traps; exit 130 on a signal). Removal is an UNLINK, not a wipe: on APFS and on
# SSDs no overwrite reaches the old blocks, so FileVault is what keeps those blocks ciphertext.
#
# ★★ PII DISCIPLINE — what this script is allowed to emit, exhaustively:
#     · counts            (how many items, how many fields, how many files)
#     · item UUIDs        (opaque; 1Password's own identifiers, not user data)
#     · SHA-256 digests   (of each sanitised item's JSON exactly as jq wrote it: not
#                          canonicalised, unsalted; never published)
#     · a vault NAME, only because you typed it
#   It never emits: titles, usernames, passwords, URLs, emails, notes, TOTP seeds, filenames.
#   ★ TITLES ARE PII. "Chase — joint account" names a bank and a relationship. Progress output is
#     "42/57", never a name, and the manifest keys on UUID for the same reason.
#
# ★ COMPLETENESS IS PROVED BY INDEPENDENT CHECKS, not by "the command exited 0":
#     1. what 1Password SAYS the vault holds        (op item list)
#     2. what we actually CAPTURED                  (rows in the manifest; the id SETS compared too)
#     3. every attachment each item lists           (fetched, on disk, at the JSON's size, digested
#                                                    into ATTACHMENTS.csv; any failed fetch refuses)
#     4. what survived the round-trip               (every sealed item JSON and attachment matches its
#                                                    digest after decrypting the real ciphertext)
#   All must agree. Any two agreeing is the failure mode: a truncated capture that is internally
#   consistent. Not proved here: that the TIME and KEY wraps open (see the round-trip comment).
# ─────────────────────────────────────────────────────────────────────────────────────────────
set -eu
unset CDPATH   # every `cd` below must go exactly where it says, silently

CHAIN=52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971   # drand quicknet
GENESIS=1692803367; PERIOD=3   # quicknet's genesis_time and period: what turns a round into a UTC time
MIRRORS="https://api.drand.sh https://api2.drand.sh https://api3.drand.sh"
# the archive scrub (Task S2 §2), IDENTICAL in both tools: ustar (no pax records, so no xattrs), no
# mac metadata / xattrs / ACLs / file flags, every entry owned by 0/0 nobody/nobody. Unquoted on use.
TAR_SCRUB='--format ustar --no-mac-metadata --no-xattrs --no-acls --no-fflags --uid 0 --gid 0 --uname nobody --gname nobody'   # @mut:scrub
OP=${OP:-op}      # overridable so --self-test can substitute a fixture
TLE=${TLE:-tle}   # ★ tle v1.2.0 accepts ONLY long flags with `=`; short forms fail misleadingly
# Where packages go. The XDG data dir, not the cwd: a package written wherever the shell happened to
# be standing is a package nobody can find in ten years.
OUT=${VAULT_TIMELOCK_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/vault-timelock}
# vt-broadcast writes SEALED.txt at the end of every seal (Task S2 §5): the repo's own broadcast/
# tool beside this script, or VT_BROADCAST (the self-test points it at the repo's copy)
VTB=${VT_BROADCAST:-$(cd "$(dirname "$0")" && pwd)/broadcast/bin/vt-broadcast}

die() { printf '%s\n' "$*" >&2; exit 1; }

need() {
  command -v "$OP"  >/dev/null 2>&1 || die "op is not installed — brew install 1password-cli"
  command -v "$TLE" >/dev/null 2>&1 || die "tle is not installed — go install github.com/drand/tlock/cmd/tle@v1.2.0"
  command -v jq     >/dev/null 2>&1 || die "jq is not installed — brew install jq"
  command -v node   >/dev/null 2>&1 || die "node is not installed (v24, https://nodejs.org): the seal serves the pinned drand chain info to tle on loopback"
  command -v shasum >/dev/null 2>&1 || die "shasum is missing: every digest (manifest, attachments, round trip) needs it"
  tar --version 2>/dev/null | grep -q bsdtar || die "tar is not bsdtar (macOS /usr/bin/tar): the archive scrub uses bsdtar's flags"
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

# obliterate: REMOVE plaintext, and say honestly what that is (audit SA-N7): an UNLINK. On APFS and
# on SSDs no overwrite reaches the old blocks (copy-on-write, wear levelling); `rm -P` has no effect
# on current macOS and there is no `shred`. FileVault protects the stale blocks; keeping plaintext
# off disk protects the rest. Refuses to report success while anything is still there.
obliterate() {
  for f in "$@"; do
    [ -e "$f" ] || continue
    rm -rf "$f" 2>/dev/null || true
    if [ -e "$f" ]; then die "could not remove $f — refusing to report success"; fi
  done
}
# is_sha256 STR: 64 lowercase hex characters
is_sha256() { case $1 in *[!0-9a-f]*) return 1 ;; esac; [ ${#1} = 64 ]; }
# sha256_of FILE: its SHA-256, or refuse. A missing or broken shasum gave "" for EVERY digest, and
# "" = "" compares equal: the round trip and open would have checked nothing (S2 re-review I-3).
# Callers: h=$(sha256_of F) || exit 1
sha256_of() {
  _s256=$(shasum -a 256 "$1" 2>/dev/null) || die "★ shasum failed on $(basename "$1"): REFUSING (no digest check may compare nothing)"
  _s256=${_s256%% *}
  is_sha256 "$_s256" || die "★ shasum gave no SHA-256 for $(basename "$1"): REFUSING (no digest check may compare nothing)"   # @mut:sha-format
  echo "$_s256"
}
# seal_cleanup: the EXIT and INT/TERM traps of `seal`. The plaintext dir goes; so does a package dir
# this run created but did not finish (ciphertext, but nobody vouched for it: no README, maybe no
# proof that it is shut). PKG_PARTIAL is set only after OUR mkdir of a NEW dir succeeded.
seal_cleanup() {
  info_stop
  obliterate "${WORK:-}"
  if [ -n "${PKG_PARTIAL:-}" ]; then rm -rf "$PKG_PARTIAL"; fi
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

# pii_audit: ★★ THE BUILT-IN, FAIL-CLOSED AUDIT OF WHAT WILL BE ENCRYPTED (Task S2 §7). The
#   operator's guarantee on a real vault, which no one else may inspect: run on the EXACT bytes,
#   after the archive is written and the data key drawn, before anything is encrypted.
#     S = every 1Password identifier in the RAW item JSONs, by category: item-id (incl. a REFERENCE
#         field's value), file-id, content-path, section-id, field-id (not a built-in name),
#         reference, url-id, vault-id, member-id (last_edited_by), item-time (created_at,
#         updated_at), item-version. Categories that --keep-item-ids / --keep-item-metadata keep
#         are not searched (vault-id with either: content_path and reference embed it).
#     P = the operator: login-name (id -un), full-name (id -F), host-name (hostname -s),
#         computer-name (scutil --get ComputerName), home-dir ($HOME), tz-offset (date +%z as
#         ±HH:MM), seal-date-utc and seal-date-local (YYYY-MM-DD), vault-name (as typed, and
#         vault.name; not with --keep-item-metadata).
#   Exact, case-sensitive byte matches (LC_ALL=C grep -F). S strings of 6+ characters (ids, times,
#   paths; an item version is a short number and is not searched). P strings of 6+ characters (and
#   tz-offset) as substrings, of 3-5 characters as WHOLE WORDS (grep -w): a short login name must not
#   match inside a hex digest or a JSON key. An operator identity string (login, full name, host,
#   computer name, home) of 1-2 characters cannot be searched: the seal refuses, naming its category,
#   unless --allow-short-operator-strings (which says the risk). A 1-2-char vault name is not searched.
#   Floors, fail closed: P must hold a login-name and a home-dir; S must hold at least one item-id
#   per declared item (unless --keep-item-ids): an empty S (a jq or op JSON shape change) refuses.
#   A grep that fails (exit > 1: an unreadable file, memory) refuses: "0 hits" is never inferred.
#     · S is searched EVERYWHERE: the whole uncompressed tar stream (headers, every item JSON,
#       every attachment, both CSVs) and the data key bytes tle will encrypt.
#     · P is searched only where nothing of the user's belongs: the data key bytes; the tar stream
#       MINUS the archived content files (hits in vault.tar − hits in the item JSONs and
#       attachments: the headers, padding, MANIFEST.csv and ATTACHMENTS.csv); and each sanitised
#       JSON's structure (every key, and the values of id, category, type, purpose, state). A
#       secret may legitimately contain the login name (a username field) or the vault name (a
#       note): user content is not an operator leak, and values are never scanned for P.
#   Any hit refuses: "★ PII/ID audit: N hit(s) (categories: ...)", counts and category names
#   only, never a value; the traps then remove the plaintext and the half package. The pattern
#   files live in $WORK/audit (0700) and go with it.
pii_audit() {
  _A="$WORK/audit"; mkdir -m 700 "$_A"
  jq -r --argjson km "$KEEP_META" --argjson ki "$KEEP_IDS" '
    def bi: test("^[A-Za-z][A-Za-z_ ]{0,19}$");
    def out($c): strings | "\($c)\t\(.)";
    (if $ki == 1 then empty else
      (.id | out("item-id")),
      ((.files // [])[] | (.id | out("file-id")), (.content_path | out("content-path")), (.section.id? | strings | select(bi | not) | out("section-id"))),
      ((.sections // [])[] | .id | strings | select(bi | not) | out("section-id")),
      ((.fields // [])[] | (.id | strings | select(bi | not) | out("field-id")), (.section.id? | strings | select(bi | not) | out("section-id")),
                           (.reference | out("reference")), (select((.type // "") == "REFERENCE") | .value | out("item-id"))),
      ((.urls // [])[] | .id? | out("url-id"))
    end),
    (if $km == 1 then empty else
      (if $ki == 1 then empty else .vault.id? | out("vault-id") end), (.last_edited_by | out("member-id")), (.created_at, .updated_at | out("item-time")),
      (.version | select(. != null) | tostring | out("item-version"))
    end)' "$WORK"/items/*.json > "$_A/S.tsv" || die "★ PII/ID audit: could not read the item JSON: REFUSING"
  _z=$(date +%z)
  { printf 'login-name\t%s\n' "$(id -un)"
    printf 'full-name\t%s\n' "$(id -F 2>/dev/null || true)"
    printf 'host-name\t%s\n' "$(hostname -s 2>/dev/null || true)"
    printf 'computer-name\t%s\n' "$(scutil --get ComputerName 2>/dev/null || true)"
    printf 'home-dir\t%s\n' "$HOME"
    printf 'tz-offset\t%s\n' "${_z%??}:${_z#???}"
    printf 'seal-date-utc\t%s\n' "$(date -u +%Y-%m-%d)"
    printf 'seal-date-local\t%s\n' "$(date +%Y-%m-%d)"
    if [ "$KEEP_META" = 0 ]; then printf 'vault-name\t%s\n' "$VAULT"; jq -r '.vault.name? | strings | "vault-name\t\(.)"' "$WORK"/items/*.json; fi
  } > "$_A/P.tsv" || die "★ PII/ID audit: could not collect the operator strings: REFUSING"
  for f in "$WORK"/s/items/*.json; do cat "$f"; echo; done > "$_A/content"
  find "$WORK/s/files" -type f -exec sh -c 'for f; do cat "$f"; echo; done' sh {} + >> "$_A/content"
  for f in "$WORK"/s/items/*.json; do jq -r '(paths | .[-1] | strings), (.. | objects | (.id?, .category?, .type?, .purpose?, .state?) | strings)' "$f"; done > "$_A/struct" \
    || die "★ PII/ID audit: could not read a sanitised item: REFUSING"
  audit_floors
  # (the vault name is not an identity string, and vault.name is dropped: 1-2 chars of it go unsearched)
  _short=$(awk -F '\t' '$1 != "tz-offset" && $1 != "vault-name" && length($2) > 0 && length($2) < 3 { print $1 }' "$_A/P.tsv" | LC_ALL=C sort -u | tr '\n' ' ')
  if [ -n "$_short" ]; then
    [ "$ALLOW_SHORT" = 1 ] || die "★ PII/ID audit: operator string(s) too short to search (categories: ${_short% }): REFUSING. --allow-short-operator-strings seals anyway, without searching for them."   # @mut:audit-short
    echo "  ★ --allow-short-operator-strings: NOT searched for (1-2 characters): ${_short% }. If they leak into the archive metadata or the key file, nothing here notices."
  fi
  # with the account metadata dropped, no sanitised item may keep a vault key (the vault name's only
  # carrier; it is the shape that is asserted, whatever the name's length; S2 re-review)
  [ "$KEEP_META" = 1 ] || for f in "$WORK"/s/items/*.json; do jq -e 'has("vault") | not' "$f" >/dev/null 2>&1 || die "★ PII/ID audit: a sanitised item still carries a vault key: REFUSING"; done   # @mut:audit-vaultkey
  _vs=$(awk -F '\t' '$1 == "vault-name" && length($2) > 0 && length($2) < 3' "$_A/P.tsv" | LC_ALL=C sort -u | wc -l | tr -d ' ')
  _hits=0; _cats=; _sl=; _pl=
  for c in $(cut -f1 "$_A/S.tsv" "$_A/P.tsv" | LC_ALL=C sort -u); do
    for t in S P; do
      _np1=$(audit_pats "$c" "$t")
      [ "$_np1" -gt 0 ] || continue
      _k=$(audit_count "$_A/identity.key.c" "$WORK/identity.key") || exit 1
      _t=$(audit_count "$_A/vault.tar.c" "$WORK/vault.tar") || exit 1
      if [ "$t" = S ]; then _n=$(( _k + _t )); _sl="$_sl $c=$_np1"
      else
        _u=$(audit_count "$_A/content.c" "$_A/content") || exit 1
        _v=$(audit_count "$_A/struct.c" "$_A/struct") || exit 1
        _d=$(( _t - _u )); [ "$_d" -ge 0 ] || _d=$(( - _d ))
        _n=$(( _k + _d + _v )); _pl="$_pl $c=$_np1"
      fi
      if [ "$_n" -gt 0 ]; then _hits=$(( _hits + _n )); _cats="${_cats:+$_cats, }$c"; fi
    done
  done
  [ "$_hits" = 0 ] || die "★ PII/ID audit: $_hits hit(s) (categories: $_cats) in what would be sealed — REFUSING. Counts and category names only; no value is printed. Nothing was encrypted; the plaintext work dir is removed."   # @mut:pii-audit
  echo "  audit      0 operator identifiers, 0 1Password identifiers in the sealed payload (searched: S$_sl; P$_pl)$( [ "$_vs" = 0 ] || echo "; vault-name: $_vs string(s) of 1-2 chars not searched" )"
}
# audit_floors: the floors (fail closed): a shape change that empties S, or a missing operator string,
# refuses. Run by pii_audit and again by audit_structure, on the same pattern files.
audit_floors() {
  _sid=$(awk -F '\t' '$1 == "item-id"' "$_A/S.tsv" | cut -f2 | LC_ALL=C sort -u | wc -l | tr -d ' ')
  [ "$KEEP_IDS" = 1 ] || [ "$_sid" -ge "$DECLARED" ] || die "★ PII/ID audit: the item JSON yields $_sid item id(s) for $DECLARED declared item(s) (did op's JSON shape change?): REFUSING"   # @mut:audit-floor
  for c in login-name home-dir; do
    awk -F '\t' -v c="$c" '$1 == c && $2 != ""' "$_A/P.tsv" | grep -q . || die "★ PII/ID audit: no $c to search for: REFUSING"
  done
}
# audit_pats CATEGORY S|P: that category's strings into $_A/pat (substrings: S 6+ chars; P 6+, and
# tz-offset) and $_A/patw (whole words: P 3-5 chars); prints how many there are
audit_pats() {
  awk -F '\t' -v c="$1" -v t="$2" '$1 == c && (length($2) >= 6 || (t == "P" && c == "tz-offset" && length($2) > 0)) { print $2 }' "$_A/$2.tsv" | LC_ALL=C sort -u > "$_A/pat"
  awk -F '\t' -v c="$1" -v t="$2" 't == "P" && $1 == c && c != "tz-offset" && length($2) >= 3 && length($2) < 6 { print $2 }' "$_A/$2.tsv" | LC_ALL=C sort -u > "$_A/patw"
  echo $(( $(wc -l < "$_A/pat") + $(wc -l < "$_A/patw") ))
}
# audit_count TAG FILE: the matches of $_A/pat (substrings) and $_A/patw (whole words) in FILE.
# grep's own failure (exit > 1) refuses; it is never read as "no match" (S2 review).
audit_count() {
  _ac=0
  for _af in pat patw; do
    [ -s "$_A/$_af" ] || continue
    _gst=0
    if [ "$_af" = pat ]; then LC_ALL=C grep -a -o -F -f "$_A/$_af" "$2" > "$1" 2>/dev/null || _gst=$?
    else LC_ALL=C grep -a -o -w -F -f "$_A/$_af" "$2" > "$1" 2>/dev/null || _gst=$?; fi
    [ "$_gst" -le 1 ] || die "★ PII/ID audit: grep failed (exit $_gst) on $(basename "$2"): REFUSING"   # @mut:audit-grep
    _ac=$(( _ac + $(wc -l < "$1") ))
  done
  echo "$_ac"
}

# ── ★ STRUCTURE.txt: THE SEALED VAULT'S SHAPE, EVERY VALUE REMOVED (Task S3; operator R63, 2026-10-09:
#    "also generate plaintext version indicative of structure, not of actual values"; where: "Local
#    only") ───────────────────────────────────────────────────────────────────────────────────────
#    `seal` writes it into the package beside SEALED.txt (mode 600), built from the SANITISED work
#    copies ($WORK/s, exactly what the archive holds) after the round-trip proof; `open` rebuilds it
#    from restored/ and compares. It is LOCAL ONLY (R44 class): never in SEALED.txt, never published.
#    ★ BUILT FROM AN ALLOWLIST, NEVER BY REDACTION. The jq program below can emit only:
#      · CATEGORY: one of the documented item categories, else OTHER; TYPE: one of the documented
#        field types, else OTHER; purpose=<PURPOSE> only for USERNAME, PASSWORD or NOTES; a field's id
#        only when it is username, password or notesPlain, else "custom"; <set>/<empty>: whether a
#        title or a value exists at all;
#      · counts: fields, sections (numbered, never labelled), urls and how many are primary, tags;
#      · per file: document|attachment and files/<item>/<file>, built from the archive's OWN ids: the
#        item from its file name items/<id>.json (checked [a-z0-9]+ before use), the file id only if
#        [a-z0-9]+ (else "(invalid id)"); those are the seal's pseudonyms, or 1Password's own with
#        --keep-item-ids. "(not on disk)" marks a listed file that files/ does not hold.
#    Never: titles, labels, values, hrefs, file names, sizes, lengths, section labels, tag text, any
#    other id (vault, account, field, section), times, versions, last_edited_by. An unknown shape (a
#    missing array, a non-string type, an entry that is not an object) gives OTHER or <empty> and is
#    counted, never echoed. jq's own error text is never shown: it can quote a value.
#    The documented lists, from the 1Password developer docs only (this tool never ran op to find
#    them; read 2026-10-09; developer.1password.com answers 301 to www.1password.dev):
#      · categories: the Item "category" enum of the Connect API reference,
#        https://developer.1password.com/docs/connect/api-reference/
#        (= https://www.1password.dev/connect/api-reference/get-vault-item-by-id);
#      · field types: the Field "type" enum there (STRING EMAIL CONCEALED URL OTP DATE MONTH_YEAR MENU),
#        plus PHONE, the JSON type of the `phone` field in the table of
#        https://developer.1password.com/docs/cli/item-fields/ (= https://www.1password.dev/cli/item-fields/);
#      · purposes: the Field "purpose" enum of the Connect reference ("" = none, USERNAME, PASSWORD, NOTES).
#      (item-fields also names a "Crypto Wallet" category, with no documented JSON value: it is OTHER.)
#    binds-to: the SHA-256 of vault.tar.gz.age's BINARY form (de-armored after --armor), the digest
#    SEALED.txt's [file vault.tar.gz.age ...] line carries: the text describes that archive only.
#    A failure to build, check or audit it does not undo the package (it is complete and verified):
#    as for SEALED.txt, the seal then does NOT report success, keeps the package and says what to do.
#    The lines marked "@mut:" are disabled one at a time by the self-test's mutation arms.
STRUCT_JQ='
def cats: ["LOGIN","PASSWORD","API_CREDENTIAL","SERVER","DATABASE","CREDIT_CARD","MEMBERSHIP","PASSPORT","SOFTWARE_LICENSE","OUTDOOR_LICENSE","SECURE_NOTE","WIRELESS_ROUTER","BANK_ACCOUNT","DRIVER_LICENSE","IDENTITY","REWARD_PROGRAM","DOCUMENT","EMAIL_ACCOUNT","SOCIAL_SECURITY_NUMBER","MEDICAL_RECORD","SSH_KEY","CUSTOM"];
def types: ["STRING","EMAIL","CONCEALED","URL","OTP","DATE","MONTH_YEAR","MENU","PHONE"];
def purposes: ["USERNAME","PASSWORD","NOTES"];
def builtins: ["username","password","notesPlain"];
def allow(l): if type == "string" and (. as $s | any(l[]; . == $s)) then . else null end;
def o: if type == "object" then . else {} end;
def each($k): [(o | .[$k]) // [] | .[]?];
def state: if . == null or . == "" or . == [] or . == {} then "<empty>" else "<set>" end;
def pad($n): . + ((" " * ($n - length)) // "");
def strid: if type == "string" then . else null end;
def category: (o | .category | allow(cats)) // "OTHER";
def fname: o as $f | ($f.id | allow(builtins)) // "custom";   # @mut:struct-label
def frow($ind): o as $f | "\($ind)field \($f | fname | pad(12)) \((($f.type | allow(types)) // "OTHER") | pad(10)) \((($f.purpose | allow(purposes)) as $p | if $p then "purpose=" + $p else "" end) | pad(17)) \($f.value | state)";
def structure_rows($n; $id; $pres):
  o as $i | each("fields") as $fs | each("sections") as $ss
  | [$ss[] | o | .id | strid] as $sids
  | [$fs[] | (o | .section | o | .id | strid) as $s | if $s == null then null else ([range(0; $sids | length) | select($sids[.] == $s)] | first) end] as $at
  | "item \($n)  \($i | category)  items/\($id).json",
    "  title          \($i.title | state)",
    (range(0; $fs | length) | select($at[.] == null) | $fs[.] | frow("  ")),
    (range(0; $ss | length) as $k | "  section \($k + 1)", (range(0; $fs | length) | select($at[.] == $k) | $fs[.] | frow("    "))),
    "  urls           \(each("urls") | length) (\([each("urls")[] | select((o | .primary) == true)] | length) primary)",
    "  tags           \(each("tags") | length)",
    (each("files")[] | (o | .id | if type == "string" and test("^[a-z0-9]+$") then . else null end) as $fid
      | "  file           \((if $i.category == "DOCUMENT" then "document" else "attachment" end) | pad(10)) files/\($id)/\($fid // "(invalid id)")\(if $fid != null and $pres["\($id)/\($fid)"] == true then "" else "  (not on disk)" end)"),
    "";
($pres | split("\n") | map(select(length > 0) | {(.): true}) | add // {}) as $p
| [inputs | {id: (input_filename | split("/") | last | rtrimstr(".json")), j: .}] as $items
| "totals: \($items | length) items, \([$items[].j | each("fields") | length] | add // 0) fields, \([$items[].j | each("sections") | length] | add // 0) sections, \([$items[].j | each("urls") | length] | add // 0) urls, \([$items[].j | each("files") | length] | add // 0) files   by category: \([$items[].j | category] | group_by(.) | map("\(.[0]) \(length)") | join(", "))",
  "",
  (range(0; $items | length) as $k | $items[$k] as $it | $it.j | structure_rows($k + 1; $it.id; $p)),
  "== end =="'
# bin_sha256 FILE: the SHA-256 of an .age file's BINARY form: as written, or de-armored when it starts
# with age's armor header (scratch in $WORK/st)
bin_sha256() {
  if [ "$(head -n 1 "$1" 2>/dev/null)" = '-----BEGIN AGE ENCRYPTED FILE-----' ]; then
    sed '1d;$d' "$1" > "$WORK/st/armor.b64" && base64 -d < "$WORK/st/armor.b64" > "$WORK/st/armor.bin" 2>/dev/null \
      || die "★ structure: $(basename "$1") is ASCII-armored but does not decode"
    sha256_of "$WORK/st/armor.bin"
  else sha256_of "$1"; fi
}
# structure_text DIR ARCHIVE OUT [NAME]: the shape of DIR/items + DIR/files, bound to ARCHIVE, into OUT. DIR
# may be untrusted (a restored/ tree): every name is checked before use and nothing of it is printed. NAME (lane B):
# vault.tar.gz.age (the default) or index (a seal --list package: it binds to the index, which lists every block).
structure_text() {
  _sd=$1; _sa=$2; _so=$3; _sn=${4:-vault.tar.gz.age}; _sw="$WORK/st"
  rm -rf "$_sw"; mkdir -m 700 "$_sw" || die "★ structure: could not create its scratch dir"
  [ -d "$_sd/items" ] && [ ! -L "$_sd/items" ] || die "★ structure: there is no items/ directory to describe"
  : > "$_sw/ids"
  for _f in "$_sd"/items/*.json; do
    [ -e "$_f" ] || [ -L "$_f" ] || continue
    [ -f "$_f" ] && [ ! -L "$_f" ] || die "★ structure: an items/ entry is not a regular file (not printed)"
    _i=$(basename "$_f" .json)
    case $_i in ''|*[!a-z0-9]*) die "★ structure: an item file name is not [a-z0-9]+.json (not printed)" ;; esac
    echo "$_i" >> "$_sw/ids"
  done
  [ -s "$_sw/ids" ] || die "★ structure: items/ holds no item"
  LC_ALL=C sort "$_sw/ids" > "$_sw/ids.sorted" || die "★ structure: could not sort the item ids"
  set --
  while IFS= read -r _i; do set -- "$@" "$_sd/items/$_i.json"; done < "$_sw/ids.sorted"
  # the files on disk (relative to files/), only to mark a listed file that is missing
  : > "$_sw/present"
  if [ -d "$_sd/files" ]; then
    ( cd "$_sd/files" && find . -type f > "$_sw/present.raw" ) || die "★ structure: files/ could not be listed"
    sed 's|^\./||' "$_sw/present.raw" > "$_sw/present" || die "★ structure: files/ could not be listed"
  fi
  _bh=$(bin_sha256 "$_sa") || exit 1
  if [ "$_sn" = index ]; then
    _swh='what-this-is: the layout of what the per-file blocks hold. No titles, labels, values, URLs, tags,'
    _sbi="binds-to: index sha256=$_bh   (valid for this seal only: the index lists every block)"
  else
    _swh='what-this-is: the layout of what vault.tar.gz.age holds. No titles, labels, values, URLs, tags,'
    _sbi="binds-to: vault.tar.gz.age sha256=$_bh   (valid for this archive only)"
  fi
  printf '%s\n' '== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==' \
    'format: vault-timelock-structure/1' \
    "$_swh" \
    '  file names, sizes or lengths. <set>/<empty> says only whether a value exists. Item and file ids' \
    "  are the archive's own (items/<id>.json, files/<id>/<file>); MANIFEST.csv maps item ids to 1Password's." \
    "$_sbi" > "$_so" || die "★ structure: could not write it"
  jq -n -r --rawfile pres "$_sw/present" "$STRUCT_JQ" "$@" >> "$_so" 2>/dev/null \
    || die "★ structure: an item could not be read as JSON (jq's message is not shown: it can quote a value)"
}
# structure_counts_ok STRUCTURE MANIFEST: item by item, the field, section and file rows equal the
# manifest's field_count, section_count and file_count, and both list the same items
structure_counts_ok() {
  awk '/^item [0-9]+  [A-Z_]+  items\/[a-z0-9]+\.json$/ { c = $NF; sub(/^items\//, "", c); sub(/\.json$/, "", c); n[c] = 1; next }
       c == "" { next }
       /^ +field / { f[c]++ } /^  section [0-9]+$/ { s[c]++ } /^  file / { l[c]++ }
       END { for (i in n) printf "%s,%d,%d,%d\n", i, f[i], s[i], l[i] }' "$1" > "$WORK/st/counts.s" || return 1
  LC_ALL=C sort -o "$WORK/st/counts.s" "$WORK/st/counts.s" || return 1
  tail -n +2 "$2" | cut -d, -f1,3,4,5 | LC_ALL=C sort > "$WORK/st/counts.m" || return 1
  [ -s "$WORK/st/counts.m" ] && cmp -s "$WORK/st/counts.s" "$WORK/st/counts.m"
}
# audit_structure FILE: pii_audit's own pattern files ($WORK/audit, with its floors re-checked) over
# FILE: S (1Password identifiers) and P (the operator) are BOTH searched in all of it, since nothing in
# STRUCTURE.txt is the user's. Any hit refuses, counts and category names only.
audit_structure() {
  _A="$WORK/audit"
  [ -f "$_A/S.tsv" ] && [ -f "$_A/P.tsv" ] || die "★ PII/ID audit: the payload audit's patterns are missing: REFUSING to write STRUCTURE.txt unaudited"
  audit_floors
  _hits=0; _cats=
  for c in $(cut -f1 "$_A/S.tsv" "$_A/P.tsv" | LC_ALL=C sort -u); do
    for t in S P; do
      _np1=$(audit_pats "$c" "$t")
      [ "$_np1" -gt 0 ] || continue
      _n=$(audit_count "$_A/structure.c" "$1") || exit 1
      if [ "$_n" -gt 0 ]; then _hits=$(( _hits + _n )); _cats="${_cats:+$_cats, }$c"; fi
    done
  done
  [ "$_hits" = 0 ] || die "★ PII/ID audit: $_hits hit(s) (categories: $_cats) in STRUCTURE.txt: REFUSING to write it. Counts and category names only; no value is printed."
  echo "  audit      STRUCTURE.txt: 0 operator identifiers, 0 1Password identifiers (the payload audit's patterns)"
}
# structure_prepare: (seal, in a subshell) build STRUCTURE.txt from $WORK/s, check it, audit it, and
# copy it into the package, mode 600. Any failure exits the subshell with its reason on stderr.
structure_prepare() {
  structure_text "$WORK/s" "$PKG/$ARCH" "$WORK/STRUCTURE.txt" "$ARCH"
  structure_counts_ok "$WORK/STRUCTURE.txt" "$WORK/s/MANIFEST.csv" || die "★ STRUCTURE.txt does not match MANIFEST.csv (per item: fields, sections, files): REFUSING to write it. Counts only; no value is printed."   # @mut:struct-count
  audit_structure "$WORK/STRUCTURE.txt"   # @mut:struct-audit
  { ( umask 077 && cp "$WORK/STRUCTURE.txt" "$PKG/STRUCTURE.txt" ) && chmod 600 "$PKG/STRUCTURE.txt"; } \
    || { rm -f "$PKG/STRUCTURE.txt"; die "★ STRUCTURE.txt could not be copied into the package"; }
  echo "  structure  STRUCTURE.txt: $(grep -c '^item ' "$PKG/STRUCTURE.txt" | tr -d ' ') item(s), shape only, every value removed; counts = MANIFEST.csv (local only, mode 600)"
}
# first_diff_line A B: the first line number at which B differs from A (one being shorter counts)
first_diff_line() {
  LC_ALL=C awk 'NR == FNR { a[FNR] = $0; na = FNR; next }
       !d && (FNR > na || a[FNR] != $0) { d = FNR }
       { nb = FNR }
       END { if (!d && na != nb) d = (na < nb ? na : nb) + 1; if (!d) d = (nb > 0 ? nb : 1); print d }' "$1" "$2"
}
# structure_check DIR: (open, after extract_verified) rebuild the structure of DIR/restored and compare
# it, byte for byte (binds-to and body), with DIR/STRUCTURE.txt. Never refuses: open has verified every
# digest already; this prints "structure ✓" or a warning naming only the first differing line number.
# STRUCT_STATE records the outcome for --plaintext (Task SP): ok, absent, or anything else (not verified).
structure_check() {
  STRUCT_STATE=unchecked
  if [ ! -e "$1/STRUCTURE.txt" ] && [ ! -L "$1/STRUCTURE.txt" ]; then STRUCT_STATE=absent; echo "  structure  no STRUCTURE.txt beside the package: not compared"; return 0; fi
  if [ -L "$1/STRUCTURE.txt" ] || [ ! -f "$1/STRUCTURE.txt" ]; then echo "  ⚠ structure: STRUCTURE.txt is not a regular file: not compared"; return 0; fi
  set +e
  ( set -e; structure_text "$1/restored" "$1/$ARCH" "$WORK/STRUCTURE.txt" "$ARCH" ) > /dev/null 2> "$WORK/structure.err"
  _cst=$?
  set -e
  if [ "$_cst" != 0 ]; then echo "  ⚠ structure: restored/ could not be described ($(tr '\n' ' ' < "$WORK/structure.err" | sed 's/ $//')): STRUCTURE.txt not compared"; return 0; fi
  if cmp -s "$WORK/STRUCTURE.txt" "$1/STRUCTURE.txt"; then   # @mut:open-structure
    STRUCT_STATE=ok
    echo "  structure ✓ STRUCTURE.txt matches restored/ (items and files) and binds to this $ARCH"
  else
    _cl=$(first_diff_line "$WORK/STRUCTURE.txt" "$1/STRUCTURE.txt") || _cl='?'
    echo "  ⚠ structure: STRUCTURE.txt differs from the structure of restored/ at line $_cl (its content is not shown). The items and attachments are verified by their digests above; STRUCTURE.txt is only a local description."
  fi
}

# ── ★ SEALED-plaintext.txt: EVERY ENTRY, DECRYPTED, AS TEXT (Task SP; R74: an opt-in
#    flag writes a plaintext view of what SEALED.txt seals, as SEALED-plaintext.txt, and only at open
#    time) ─────────────────────────────────────────────────────────────────────────────
#    `open <package> --plaintext [--force]` writes SEALED-plaintext.txt into the package dir, beside
#    restored/: the decrypted view of every item (the opposite of STRUCTURE.txt). It holds EVERY SECRET.
#    · ONLY AFTER THE UNLOCK TIME AND A FULLY VERIFIED OPEN, fail closed. Before anything is decrypted
#      (plaintext_precheck): no temp file of an interrupted --plaintext is left in the package dir (it may
#      hold every secret: the operator deletes it; SP review m3); SEALED.txt is beside the package, its one
#      unlock-after line agrees with the round file and with quicknet's pinned clock, and that round has
#      been reached (on the KEY path too: a recovery key opens early, the plaintext file does not); the
#      output name is free (or --force and a regular file). After open's own checks (plaintext_gate):
#      every item verified against a manifest (none: refused), every attachment against ATTACHMENTS.csv
#      (open itself refuses otherwise), "structure ✓" when STRUCTURE.txt exists, restored/items holds
#      exactly the manifest's items, and SEALED.txt's [file vault.tar.gz.age ...] digest is this
#      archive's. Any failure: no file.
#    · WRITTEN SAFELY, by PLAIN_JS itself (SP review m1, m2): the temp file .SEALED-plaintext.txt.<pid>.tmp
#      is opened O_CREAT|O_EXCL|O_NOFOLLOW with mode 0600 (never through a symlink, a FIFO or anything
#      already there), fchmod 0600; its inherited ACL is stripped (chmod -N: the kernel copies a
#      file_inherit ACE of the package dir into a new file) and `ls -ld` must then say exactly
#      -rw-------, all BEFORE a byte is written; Time Machine is told to skip it (tmutil addexclusion,
#      no -p: best effort, SP review m7); the whole text is written and fsynced, then put in place:
#      link(2) without --force (EEXIST for ANY existing name: a file, a directory, a symlink, a FIFO; never
#      into or through it), rename(2) with --force (only over a regular file); the placed name must be the
#      inode just written; the dir is fsynced. On any failure the temp file it created is removed; the
#      shell's traps remove it if the open is interrupted. The tool prints the path, bytes, lines and
#      SHA-256, and warnings; never a byte of the content.
#    · THE FORMAT (vault-timelock-plaintext/1), deterministic, built from restored/ only:
#        == vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==
#        format: vault-timelock-plaintext/1
#        source: SEALED.txt sha256=<hex>   archive: vault.tar.gz.age sha256=<hex>   structure: ✓|not present
#          (lane B: a seal --list package's "archive: index sha256=<hex>", the index's digest; the body is the same)
#        opened-after: <SEALED.txt's unlock-after>   (drand round R)
#        escapes: (the rule below, verbatim)
#        delete: (read it, then delete it and restored/ promptly)
#        (blank), then per item, in the seal's item-id order (LC_ALL=C, as STRUCTURE.txt):
#        [item N] <category>  <title>
#          <label> : <value>                      fields outside a section, in JSON order
#          section "<label>"                      each section, in JSON order, with its fields indented
#          url <label> : <href>   (primary)        "   (primary)" only when primary is true
#          tags : <t1>, <t2>                      (no line without tags)
#          notes :                                each field with purpose NOTES outside a section; its
#            <line>                               lines at 4 spaces ("notes : (empty)" when empty)
#          file <name> : files/<id>/<fid>  (<bytes> B, sha256 <hex>)  [document|attachment]
#          other values :                         every other value-bearing key (SP review m5), by path:
#            <path> : <value>                     e.g. fields[3].ssh_formats.openssh.value (an SSH key's
#                                                 OpenSSH form); ids, types, purposes, section refs, entropy,
#                                                 strength and totp (derived) and account metadata are not
#        (blank line after each item), then: == end (<n> items, <m> files) ==
#      Values in full, concealed ones too. A value's continuation lines are indented 4 spaces more than
#      its row. An empty or null value is (empty); a number, boolean, object or array is its compact JSON.
#    · ESCAPING, INJECTIVE (SP review I1). A row (the item line, a field, a section, a url, the tags, a
#      notes block, a file, an other value) is printed VERBATIM, a backslash as itself, unless one of its
#      texts needs escaping: an invalid UTF-8 byte; a control character (C0, DEL, C1; a newline too, except
#      as a line break of a value); a lone surrogate; an invisible or space-like character (Unicode Cf, Zl,
#      Zp, Co, Cn, Default_Ignorable_Code_Point, and every Zs but U+0020: NBSP, U+200B, U+202E, U+FEFF ...);
#      a space at the start or end of a line; the exact text (empty); its row's separator (" : " in a
#      label, file name or path; ", " in a tag; a space in the category; a trailing "(primary)" in a href);
#      a slot whose END forms that separator with it ("Mot de passe :" before " : "); a label, section label
#      or title ending in ":"; a value, href or tag starting with ":" or a space (SP re-review N1): every row
#      then decodes, by its first separator, to exactly one (label, value).
#      Then the WHOLE row is escaped, with "\" in column 1 of each of its lines: a backslash is \\, and each
#      such character, separator character, edge space and the "(" of a literal (empty) is \xNN per byte
#      of its UTF-8 (a lone surrogate: its 3 bytes; an invalid byte: itself). (empty) is always an empty
#      value. So p\x07w (6 characters) prints "  lit : p\x07w" and p<BEL>w prints "\ bel : p\x07w".
#    · PARSED FROM BYTES. jq, and Node's own UTF-8 decoding, replace an invalid byte with U+FFFD; PLAIN_JS
#      therefore reads each JSON file as bytes with its own parser, keeping every invalid byte. Its
#      errors are fixed texts naming at most an item or file id ([a-z0-9]+); it never echoes a value.
#    · LOCAL ONLY (R44 class): never in SEALED.txt (seal-text reads only the .age files, chain-info.json,
#      round and encoding), never in a publication; the README lists it as local only. `seal --plaintext`
#      (the flag anywhere, first included) is refused: the plaintext exists only after the unlock time.
#    The lines marked "@mut:" are disabled one at a time by the self-test's mutation arms.
PLAIN_JS='
const fs = require("fs"), crypto = require("crypto"), cp = require("child_process"), path = require("path")
const a = process.argv.slice(1)
class Bad extends Error {}
class Taken extends Error {}
const bad = (m) => { throw new Bad(m) }
const NONE = { t: "n" }
const cs = (s) => [...s].map((x) => x.codePointAt(0))
const EMPTY = cs("(empty)")
const key = (c) => c.map((x) => (x < 0 ? "\u0000" + x : String.fromCodePoint(x))).join("")
// one JSON value parsed from BYTES: s (code points; an invalid UTF-8 byte b is -1 - b), r (a number,
// true or false, as written), n (null), a, o (a map for lookups, and the keys in order)
function parse(b, id) {
  let i = 0
  const n = b.length
  const no = (w) => bad("item " + id + ": " + w)
  const ws = () => { while (i < n && (b[i] === 32 || b[i] === 9 || b[i] === 10 || b[i] === 13)) i++ }
  const hex4 = () => { const h = b.toString("latin1", i, i + 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) no("not JSON"); i += 4; return parseInt(h, 16) }
  function str() {
    i++
    const c = []
    for (;;) {
      if (i >= n) no("not JSON")
      const x = b[i]
      if (x === 34) { i++; return c }
      if (x === 92) {
        const e = b[i + 1]; i += 2
        if (e === 117) {
          let u = hex4()
          if (u >= 0xd800 && u <= 0xdbff && b[i] === 92 && b[i + 1] === 117) {
            const j = i; i += 2
            const l = hex4()
            if (l >= 0xdc00 && l <= 0xdfff) u = 0x10000 + (u - 0xd800) * 1024 + (l - 0xdc00); else i = j
          }
          c.push(u)
        } else {
          const k = { 34: 34, 92: 92, 47: 47, 98: 8, 102: 12, 110: 10, 114: 13, 116: 9 }[e]
          if (k === undefined) no("not JSON")
          c.push(k)
        }
        continue
      }
      if (x < 0x80) { c.push(x); i++; continue }
      let m = 0, cp = 0, lo = 0
      if (x >= 0xc2 && x <= 0xdf) { m = 1; cp = x & 0x1f; lo = 0x80 }
      else if (x >= 0xe0 && x <= 0xef) { m = 2; cp = x & 0x0f; lo = 0x800 }
      else if (x >= 0xf0 && x <= 0xf4) { m = 3; cp = x & 0x07; lo = 0x10000 }
      let ok = m > 0 && i + m < n
      for (let k = 1; ok && k <= m; k++) { if ((b[i + k] & 0xc0) !== 0x80) ok = false; else cp = cp * 64 + (b[i + k] & 0x3f) }
      if (ok && (cp < lo || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))) ok = false
      if (ok) { c.push(cp); i += m + 1 } else { c.push(-1 - x); i++ }
    }
  }
  function val(d) {
    if (d > 512) no("nested too deeply")
    ws()
    if (i >= n) no("not JSON")
    const x = b[i]
    if (x === 123 || x === 91) {
      const obj = x === 123, close = obj ? 125 : 93
      const v = obj ? { t: "o", m: new Map(), k: [] } : { t: "a", v: [] }
      i++; ws()
      if (b[i] === close) { i++; return v }
      for (;;) {
        ws()
        if (obj) {
          if (b[i] !== 34) no("not JSON")
          const kc = str(), ks = key(kc)
          ws()
          if (b[i] !== 58) no("not JSON")
          i++
          if (v.m.has(ks)) no("a key is repeated")
          const e = val(d + 1)
          v.m.set(ks, e); v.k.push([kc, e])
        } else v.v.push(val(d + 1))
        ws()
        if (b[i] === 44) { i++; continue }
        if (b[i] === close) { i++; return v }
        no("not JSON")
      }
    }
    if (x === 34) return { t: "s", v: str() }
    const w = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?)/.exec(b.toString("latin1", i, Math.min(n, i + 1024)))
    if (!w) no("not JSON")
    i += w[0].length
    return w[0] === "null" ? NONE : { t: "r", v: w[0] }
  }
  const v = val(0)
  ws()
  if (i !== n) no("not JSON")
  return v
}
const get = (o, k) => (o.t === "o" && o.m.has(k) ? o.m.get(k) : NONE)
const isStr = (v, s) => v.t === "s" && key(v.v) === s
const list = (o, k, id) => { const v = get(o, k); if (v === NONE) return []; if (v.t !== "a") bad("item " + id + ": " + k + " is not a list"); return v.v }
const objs = (o, k, id) => list(o, k, id).map((e) => (e.t === "o" ? e : bad("item " + id + ": an entry of " + k + " is not an object")))
const u8 = (c) => c < 0x80 ? [c] : c < 0x800 ? [0xc0 | (c >> 6), 0x80 | (c & 63)] : c < 0x10000 ? [0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)] : [0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)]
const hx = (y) => "\\x" + y.toString(16).padStart(2, "0")
function compact(v) {
  if (v.t === "n") return cs("null")
  if (v.t === "r") return cs(v.v)
  if (v.t === "s") return [34, ...v.v.flatMap((c) => (c === 34 || c === 92 ? [92, c] : [c])), 34]
  if (v.t === "a") return [91, ...v.v.flatMap((e, k) => [...(k ? [44] : []), ...compact(e)]), 93]
  return [123, ...v.k.flatMap(([kc, e], k) => [...(k ? [44] : []), ...compact({ t: "s", v: kc }), 58, ...compact(e)]), 125]
}
// a value: a string as it is; null or "" is (empty); anything else its compact JSON
const cps = (v) => (v.t === "n" || (v.t === "s" && v.v.length === 0) ? EMPTY : v.t === "s" ? v.v : compact(v))
// ---- escaping (SP review I1) ------------------------------------------------------------------------
// a slot: its code points, whether it is an empty value, its kind: v a value (it may span lines), l a
// label, file name or path (its row separator is " : "), t a tag (", "), c the category (a space), h a
// url href (a trailing "(primary)"), s a title or section label
const sl = (v, k) => { const c = cps(v); return { c, e: c === EMPTY, k } }
const SPECIAL = /^(?:[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]|(?! )\p{Zs})$/u
const special = (c, nl) => (c < 0 || (c >= 0xd800 && c < 0xe000) ? true : c === 10 ? !nl : SPECIAL.test(String.fromCodePoint(c)))
const SEP = { l: 58, t: 44, c: 32, h: 40 }
const txt = (c) => c.map((x) => String.fromCodePoint(x)).join("")
// a row is decoded by its FIRST separator (" : " after a label, ", " between tags, "  " after the category),
// so a slot is escaped unless "<slot><separator>" holds that separator first at the end of the slot: a slot that
// contains it, or whose end joins the start of the separator into an earlier one (a label "Mot de passe :" before
// " : "). Labels (and section labels, titles) ending in ":" and values (hrefs, tags) starting with ":" or " "
// are escaped too, whatever the row: the text of a row then decodes to one (label, value) pair only (SP re-review N1)
const SEPS = { l: " : ", t: ", ", c: "  " }
const edges = (k, t) => (Object.prototype.hasOwnProperty.call(SEPS, k) && (t + SEPS[k]).indexOf(SEPS[k]) !== t.length) ||
  ((k === "l" || k === "s") && t.endsWith(":")) || ((k === "v" || k === "h" || k === "t") && (t.startsWith(":") || t.startsWith(" ")))
function needs(s) {
  if (s.e) return false
  if (s.c.some((x) => special(x, s.k === "v"))) return true
  const t = txt(s.c)
  if (t === "(empty)" || t.split("\n").some((l) => l.startsWith(" ") || l.endsWith(" ")) || (s.k === "l" && t.includes(" : ")) ||
    (s.k === "t" && t.includes(", ")) || (s.k === "c" && t.includes(" ")) || (s.k === "h" && t.endsWith("(primary)"))) return true
  return edges(s.k, t)   // # @mut:pt-sepedge
}
const BS = String.fromCharCode(92, 92)   // # @mut:pt-escape
// the escaped text of a slot: \\ for a backslash; \xNN per byte for an invalid byte, a special character,
// a space at a line edge, the row separator character of its kind, the "(" of a literal (empty), and a ":"
// that starts a value, href or tag
function esc(s) {
  if (s.e) return "(empty)"
  const c = s.c, nl = s.k === "v", edge = new Set()
  for (let i = 0, b = 0; i <= c.length; i++) {
    if (i < c.length && !(nl && c[i] === 10)) continue
    for (let j = b; j < i && c[j] === 32; j++) edge.add(j)
    for (let j = i - 1; j >= b && c[j] === 32; j--) edge.add(j)
    b = i + 1
  }
  const lit = key(c) === "(empty)"
  return c.map((x, i) => (x < 0 ? hx(-1 - x) : x === 92 ? BS : x === 10 && nl ? "\n" :
    special(x, nl) || edge.has(i) || x === SEP[s.k] || (lit && i === 0) || (i === 0 && x === 58 && (s.k === "v" || s.k === "h" || s.k === "t")) ? u8(x).map(hx).join("") : String.fromCodePoint(x))).join("")
}
const plain = (s) => (s.e ? "(empty)" : txt(s.c))
let out = []
const MK = (l) => (l[0] === " " ? "\\" + l.slice(1) : "\\" + l)   // # @mut:pt-marker
const put = (x, l) => out.push(x ? MK(l) : l)
// one row: fixed texts and slots; ESCAPED (every slot, and "\" in column 1 of each line) when a slot needs it
function row(ind, segs, tail) {
  const x = segs.some((g) => typeof g !== "string" && needs(g))
  const l = segs.map((g) => (typeof g === "string" ? g : x ? esc(g) : plain(g))).join("").split("\n")
  l.forEach((s, k) => put(x, (k ? " ".repeat(ind.length + 4) : ind) + s + (k === l.length - 1 ? tail : "")))
}
function notes(v) {
  const s = sl(v, "v")
  if (s.e) { put(false, "  notes : (empty)"); return }
  const x = needs(s)
  put(x, "  notes :")
  for (const l of (x ? esc(s) : plain(s)).split("\n")) put(x, "    " + l)
}
// every value-bearing leaf the rows do not show, as [path, value], in document order (SP review m5)
const LISTS = ["fields", "sections", "urls", "files"]
const SKIP = { item: ["id", "title", "category", "fields", "sections", "urls", "tags", "files", "version", "vault", "last_edited_by", "created_at", "updated_at"],
  fields: ["id", "type", "purpose", "label", "value", "section", "reference", "entropy", "totp"],
  sections: ["id", "label"], urls: ["id", "label", "href", "primary"], files: ["id", "name", "size", "section", "content_path"] }
function others(it) {
  const o = []
  const leaf = (p, v) => {
    if (v.t === "o") { for (const [kc, e] of v.k) leaf([...p, 46, ...kc], e) }
    else if (v.t === "a") v.v.forEach((e, i) => leaf([...p, ...cs("[" + i + "]")], e))
    else if (v.t !== "n") o.push([p, v])
  }
  for (const [kc, e] of it.k) {
    const k = key(kc)
    if (LISTS.includes(k) && e.t === "a") {
      e.v.forEach((x, i) => {
        for (const [fc, fe] of x.k) {
          const fk = key(fc), p = [...cs(k + "[" + i + "]."), ...fc]
          if (SKIP[k].includes(fk)) continue
          if (k === "fields" && fk === "password_details" && fe.t === "o") { for (const [pc, pe] of fe.k) if (key(pc) !== "strength") leaf([...p, 46, ...pc], pe) }
          else leaf(p, fe)
        }
      })
    } else if (!SKIP.item.includes(k)) leaf(kc, e)
  }
  return o
}
const lst = (p) => { try { return fs.lstatSync(p) } catch { return null } }
function body(dir) {
  out = []
  const ids = fs.readdirSync(dir + "/items").map((f) => {
    const s = lst(dir + "/items/" + f)
    if (!/^[a-z0-9]+[.]json$/.test(f) || s === null || !s.isFile()) bad("an items/ entry is not a regular [a-z0-9]+.json file (not printed)")
    return f.slice(0, -5)
  }).sort()
  if (ids.length === 0) bad("items/ holds no item")
  const att = new Map()
  const as = lst(dir + "/ATTACHMENTS.csv")
  if (as !== null) {
    if (!as.isFile()) bad("ATTACHMENTS.csv is not a regular file")
    const rows = fs.readFileSync(dir + "/ATTACHMENTS.csv", "latin1").split("\n")
    if (rows[rows.length - 1] === "") rows.pop()
    if (rows[0] !== "item_id,file_id,bytes,sha256") bad("ATTACHMENTS.csv has no header")
    for (const r of rows.slice(1)) {
      const m = /^([a-z0-9]+),([a-z0-9]+),(0|[1-9][0-9]{0,14}),([0-9a-f]{64})$/.exec(r)
      if (!m || att.has(m[1] + "/" + m[2])) bad("ATTACHMENTS.csv has a malformed or repeated row (not printed)")
      att.set(m[1] + "/" + m[2], { bytes: Number(m[3]), sha: m[4], used: false })
    }
  }
  let nf = 0
  ids.forEach((id, n) => {
    const it = parse(fs.readFileSync(dir + "/items/" + id + ".json"), id)
    if (it.t !== "o") bad("item " + id + ": not a JSON object")
    const fields = objs(it, "fields", id), sections = objs(it, "sections", id), urls = objs(it, "urls", id)
    const files = objs(it, "files", id), tags = list(it, "tags", id)
    row("", ["[item " + (n + 1) + "] ", sl(get(it, "category"), "c"), "  ", sl(get(it, "title"), "s")], "")
    // a field belongs to the first section whose id (a string) equals its section.id; else to the item
    const sid = sections.map((s) => { const x = get(s, "id"); return x.t === "s" ? key(x.v) : null })
    const at = fields.map((f) => { const x = get(get(f, "section"), "id"); return x.t === "s" ? sid.indexOf(key(x.v)) : -1 })
    const val = (f) => get(f, "value")   // # @mut:pt-concealed
    const isNotes = (k) => at[k] === -1 && isStr(get(fields[k], "purpose"), "NOTES")
    fields.forEach((f, k) => { if (at[k] === -1 && !isNotes(k)) row("  ", [sl(get(f, "label"), "l"), " : ", sl(val(f), "v")], "") })
    sections.forEach((s, j) => {
      row("  ", ["section \"", sl(get(s, "label"), "s"), "\""], "")
      fields.forEach((f, k) => { if (at[k] === j) row("    ", [sl(get(f, "label"), "l"), " : ", sl(val(f), "v")], "") })
    })
    urls.forEach((u) => { const p = get(u, "primary"); row("  ", ["url ", sl(get(u, "label"), "l"), " : ", sl(get(u, "href"), "h")], p.t === "r" && p.v === "true" ? "   (primary)" : "") })
    if (tags.length > 0) row("  ", ["tags : ", ...tags.flatMap((t, k) => (k ? [", ", sl(t, "t")] : [sl(t, "t")]))], "")
    fields.forEach((f, k) => { if (isNotes(k)) notes(val(f)) })
    const kind = isStr(get(it, "category"), "DOCUMENT") ? "document" : "attachment"
    for (const f of files) {
      const x = get(f, "id"), fid = x.t === "s" ? key(x.v) : ""
      if (!/^[a-z0-9]+$/.test(fid)) bad("item " + id + ": a file id is not [a-z0-9]+ (not printed)")
      const r = att.get(id + "/" + fid)
      if (r === undefined || r.used) bad("item " + id + ": file " + fid + " has no ATTACHMENTS.csv row of its own")
      r.used = true
      const p = dir + "/files/" + id + "/" + fid, st = lst(p)
      if (st === null || !st.isFile()) bad("files/" + id + "/" + fid + " is missing or not a regular file")
      const data = fs.readFileSync(p), h = crypto.createHash("sha256").update(data).digest("hex")
      if (data.length !== r.bytes || h !== r.sha) bad("files/" + id + "/" + fid + " does not match ATTACHMENTS.csv")
      const fixed = " : files/" + id + "/" + fid + "  (" + data.length + " B, sha256 " + h + ")  [" + kind + "]"
      row("  ", ["file ", sl(get(f, "name"), "l"), fixed], "")   // # @mut:pt-attach
      nf++
    }
    const ov = others(it)   // # @mut:pt-other
    if (ov.length > 0) {
      put(false, "  other values :")
      for (const [p, v] of ov) row("    ", [{ c: p, e: false, k: "l" }, " : ", sl(v, "v")], "")
    }
    out.push("")
  })
  for (const [k, r] of att) if (!r.used) bad("ATTACHMENTS.csv lists " + k + ", which no item lists")
  out.push("== end (" + ids.length + " items, " + nf + " files) ==")
  return out.join("\n") + "\n"
}
// write: the whole file into a NEW temp file (O_EXCL, O_NOFOLLOW, 0600, no ACL), fsync, then link (no
// --force) or rename (--force) into place; prints "<bytes> <lines> <sha256> <tm>" (tm: yes|no, the Time
// Machine exclusion). The temp file is removed on any failure; a temp NAME already taken exits 4.
function write(dir, outp, tmp, force, sealed, archive, struct, iso, round, aname) {
  if (!/^[0-9a-f]{64}$/.test(sealed) || !/^[0-9a-f]{64}$/.test(archive) || !(struct === "✓" || struct === "not present") || !(force === "0" || force === "1") ||
      !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(iso) || !/^[1-9][0-9]{0,15}$/.test(round) || !(aname === "vault.tar.gz.age" || aname === "index")) bad("the header values are malformed")
  const text = Buffer.from([
    "== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==",
    "format: vault-timelock-plaintext/1",
    "source: SEALED.txt sha256=" + sealed + "   archive: " + aname + " sha256=" + archive + "   structure: " + struct,
    "opened-after: " + iso + "   (drand round " + round + ")",
    "escapes: a row with \"\\\" in column 1 is escaped (\\\\ = one backslash, \\xNN = one byte of UTF-8); every other row is verbatim; (empty) = an empty value",
    "delete: this file and restored/ hold every secret: read them, then delete both promptly (Spotlight may index them, and backups may copy them, while they exist)",
    "", body(dir)].join("\n"), "utf8")
  const C = fs.constants
  let fd
  try { fd = fs.openSync(tmp, C.O_WRONLY | C.O_CREAT | C.O_EXCL | C.O_NOFOLLOW, 0o600) }   // # @mut:pt-mode
  catch (e) {
    if (e && (e.code === "EEXIST" || e.code === "ELOOP")) throw new Taken("the temp file name " + path.basename(tmp) + " is taken (something this open did not create: left alone)")
    bad("the temp file could not be created (" + String(e && e.code).replace(/[^A-Z]/g, "") + ")")
  }
  const st = fs.fstatSync(fd)
  let placed = false, tm = "no"
  try {
    fs.fchmodSync(fd, 0o600)
    cp.execFileSync("/bin/chmod", ["-N", tmp], { stdio: "ignore" })   // # @mut:pt-acl
    const ls = cp.execFileSync("/bin/ls", ["-ld", tmp]).toString("latin1").split(" ")[0], sp = lst(tmp)
    if (ls !== "-rw-------" || sp === null || !sp.isFile() || sp.ino !== st.ino || sp.nlink !== 1) bad("the new temp file carries an ACL or extended attributes, or is not the file just created (" + ls.replace(/[^-a-z@+]/g, "?") + ")")
    try { cp.execFileSync("tmutil", ["addexclusion", tmp], { stdio: "ignore", timeout: 30000 }); tm = "yes" } catch { tm = "no" }
    for (let off = 0; off < text.length; ) off += fs.writeSync(fd, text, off, text.length - off)
    fs.fsyncSync(fd)
    if (force === "1") {
      const o = lst(outp)
      if (o !== null && !o.isFile()) bad("SEALED-plaintext.txt is not a regular file (a directory, symlink or FIFO is there): not replaced")
      fs.renameSync(tmp, outp)
    } else {
      try { fs.linkSync(tmp, outp) }   // # @mut:pt-link
      catch (e) { if (e && e.code === "EEXIST") bad("SEALED-plaintext.txt appeared during this open (a file, directory, symlink or FIFO): not overwritten; --force replaces only a regular file"); throw e }
      fs.unlinkSync(tmp)
    }
    placed = true
    const f = lst(outp)
    if (f === null || !f.isFile() || f.ino !== st.ino) bad("SEALED-plaintext.txt is not the file this open wrote")
    try { const d = fs.openSync(path.dirname(outp), "r"); try { fs.fsyncSync(d) } finally { fs.closeSync(d) } } catch {}
  } finally {
    fs.closeSync(fd)
    if (!placed) { const t = lst(tmp); if (t !== null && t.ino === st.ino) fs.unlinkSync(tmp) }
  }
  let nl = 0
  for (const b of text) if (b === 10) nl++
  process.stdout.write(text.length + " " + nl + " " + crypto.createHash("sha256").update(text).digest("hex") + " " + tm + "\n")
}
try {
  if (a[0] === "body" && a.length === 2) process.stdout.write(body(a[1]))
  else if (a[0] === "write" && a.length === 11) write(...a.slice(1))
  else bad("usage: body <dir> | write <dir> <out> <tmp> <force> <sealed> <archive> <structure> <iso> <round> <archive-name>")
} catch (e) {
  process.stderr.write(e instanceof Bad || e instanceof Taken ? e.message : "restored/ could not be read, or the file could not be written (not printed)")
  process.exitCode = e instanceof Taken ? 4 : 3
}'
# plaintext_body DIR: the items of DIR (a restored/ tree) in the format above, on stdout (the test seam); a
# failure dies with PLAIN_JS's fixed text (never a value)
plaintext_body() {
  env -i PATH="$PATH" node -e "$PLAIN_JS" body "$1" 2> "$WORK/pt.err" \
    || die "★ the plaintext could not be built: $(head -c 400 "$WORK/pt.err" | tr '\n' ' ')$( [ -s "$WORK/pt.err" ] || echo 'the renderer (node) failed') (no value is shown)"
}
# plaintext_precheck DIR: (open --plaintext, after WORK exists, BEFORE anything is decrypted) no leftover
# temp file; SEALED.txt (copied into WORK: every later use reads that copy), its unlock-after = the round
# file = quicknet's pinned clock, that round reached; the output name free, or --force and a regular file
plaintext_precheck() {
  command -v node >/dev/null 2>&1 || die "node is not installed (v24, https://nodejs.org): --plaintext renders the restored items with it. Nothing was opened."
  # a temp file left by an interrupted --plaintext (SIGKILL, power loss) may hold every secret (SP review m3)
  find "$1" -mindepth 1 -maxdepth 1 -name '.SEALED-plaintext.txt.*' > "$WORK/pt.left" || die "★ --plaintext: $1 could not be listed. Nothing was opened."
  _plo=$(head -n 1 "$WORK/pt.left"); _plo=${_plo##*/}; case $_plo in *[!A-Za-z0-9._-]*) _plo='a .SEALED-plaintext.txt.* entry (its name has unusual characters)' ;; esac
  [ ! -s "$WORK/pt.left" ] || die "★ --plaintext: $1 holds $_plo, a temp file left by an interrupted open --plaintext: it may hold every secret in plain text. Delete it yourself (its content is not shown), then open again. Nothing was opened."   # @mut:pt-leftover
  [ -f "$1/SEALED.txt" ] && [ ! -L "$1/SEALED.txt" ] && cp "$1/SEALED.txt" "$WORK/SEALED.txt" || die "★ --plaintext needs SEALED.txt beside the package (its unlock time and digest head SEALED-plaintext.txt): write it with vt-broadcast seal-text $1 --write. Nothing was opened."   # @mut:pt-sealed
  _pa=$(sed -n 's/^unlock-after: \([0-9]\{4\}-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z\)  (drand round \([1-9][0-9]\{0,15\}\))$/\1 \2/p' "$WORK/SEALED.txt")
  PT_ISO=${_pa% *}; PT_ROUND=${_pa#* }
  [ -n "$_pa" ] && [ "$(printf '%s\n' "$_pa" | wc -l | tr -d ' ')" = 1 ] && [ "$(round_of "$1")" = "$PT_ROUND" ] && [ "$(round_iso "$PT_ROUND")" = "$PT_ISO" ] || die "★ --plaintext: SEALED.txt has no single unlock-after line that agrees with the package's round file and quicknet's pinned clock: refusing. Nothing was opened."   # @mut:pt-agree
  _pc=$(( ($(date -u +%s) - GENESIS) / PERIOD + 1 ))
  [ "$PT_ROUND" -le "$_pc" ] || die "★ --plaintext: the unlock time has not passed ($PT_ISO UTC, drand round $PT_ROUND): SEALED-plaintext.txt exists only after the unlock time. Nothing was opened."   # @mut:pt-round
  if [ -e "$1/SEALED-plaintext.txt" ] || [ -L "$1/SEALED-plaintext.txt" ]; then
    [ "$PT_FORCE" = 1 ] || die "★ $1/SEALED-plaintext.txt already exists: not overwritten (pass --force to replace it). Nothing was opened."
    [ -f "$1/SEALED-plaintext.txt" ] && [ ! -L "$1/SEALED-plaintext.txt" ] || die "★ $1/SEALED-plaintext.txt is not a regular file (a directory, a symlink or a FIFO): --force replaces only a regular file. Nothing was opened."
  fi
}
# plaintext_gate DIR: (after open's own checks) the open was FULLY verified; any doubt refuses, and says
# that restored/ (written by the open) holds what the archive had
plaintext_gate() {
  _pg="SEALED-plaintext.txt is written only after a fully verified open: not written. restored/ holds what the archive had."
  [ "$PT_ITEMS" = 1 ] || die "★ --plaintext: the items were not verified against a manifest (see above). $_pg"
  case $STRUCT_STATE in ok|absent) ;; *) die "★ --plaintext: STRUCTURE.txt does not match restored/, or was not compared (see above). $_pg" ;; esac
  # restored/items holds exactly the items the manifest listed and open verified (nothing unverified)
  cut -d' ' -f1 "$WORK/fcounts" | LC_ALL=C sort > "$WORK/pt.mf" && find "$1/restored/items" -mindepth 1 -maxdepth 1 > "$WORK/pt.ls" \
    || die "★ --plaintext: restored/items could not be listed. $_pg"
  : > "$WORK/pt.rs"
  while IFS= read -r _pp; do
    _pn=${_pp##*/}; _pi=
    case $_pn in *.json) _pi=${_pn%.json} ;; esac
    case $_pi in ''|*[!a-z0-9]*) die "★ --plaintext: restored/items holds an entry that is not an item file (not printed). $_pg" ;; esac
    [ -f "$_pp" ] && [ ! -L "$_pp" ] || die "★ --plaintext: restored/items/$_pi.json is not a regular file. $_pg"
    echo "$_pi" >> "$WORK/pt.rs"
  done < "$WORK/pt.ls"
  LC_ALL=C sort -o "$WORK/pt.rs" "$WORK/pt.rs"
  cmp -s "$WORK/pt.mf" "$WORK/pt.rs" || die "★ --plaintext: restored/items does not hold exactly the items the manifest lists and open verified ($(wc -l < "$WORK/pt.rs" | tr -d ' ') on disk, $(wc -l < "$WORK/pt.mf" | tr -d ' ') verified). $_pg"
  # SEALED.txt (the copy read before decrypting) describes THIS archive (lane B: a per-file package's SEALED.txt is format
  # /2, layout per-file, and its [file index ...] line carries this index's SHA-256)
  _ps=$(sed -n 's/^\[file vault\.tar\.gz\.age bytes=[0-9]* sha256=\([0-9a-f]\{64\}\)\]$/\1/p' "$WORK/SEALED.txt")
  if [ "$ARCH" = index ]; then
    _ps=$(sed -n 's/^\[file index bytes=[0-9]* sha256=\([0-9a-f]\{64\}\) gzip=[0-9]*\]$/\1/p' "$WORK/SEALED.txt")
    grep -qx 'format: vault-timelock-sealed/2' "$WORK/SEALED.txt" && grep -qx 'layout: per-file' "$WORK/SEALED.txt" || _ps=
  fi
  mkdir -p -m 700 "$WORK/st"
  _pb=$(bin_sha256 "$1/$ARCH") || exit 1
  [ -n "$_ps" ] && [ "$_ps" = "$_pb" ] || die "★ --plaintext: SEALED.txt does not carry this $ARCH's SHA-256 (it describes another package). $_pg"
}
# plaintext_write DIR: restored/ excluded from Time Machine (best effort), then PLAIN_JS writes the file
# (see the banner); prints the path, bytes, lines, SHA-256 and the warnings
plaintext_write() {
  PT_OUT="$1/SEALED-plaintext.txt"
  _pse=$(sha256_of "$WORK/SEALED.txt") || exit 1
  _par=$(bin_sha256 "$1/$ARCH") || exit 1
  if [ "$STRUCT_STATE" = ok ]; then _pst='✓'; else _pst='not present'; fi
  if tmutil addexclusion "$1/restored" >/dev/null 2>&1; then _ptr=yes; else _ptr=no; fi   # (SP review m7; no -p)
  PT_TMP="$1/.SEALED-plaintext.txt.$$.tmp"   # from here the traps remove it if this open is interrupted
  set +e
  env -i PATH="$PATH" node -e "$PLAIN_JS" write "$1/restored" "$PT_OUT" "$PT_TMP" "$PT_FORCE" "$_pse" "$_par" "$_pst" "$PT_ISO" "$PT_ROUND" "$ARCH" > "$WORK/pt.out" 2> "$WORK/pt.err"
  _pw=$?
  set -e
  [ "$_pw" != 4 ] || PT_TMP=   # the temp NAME was taken by something this open did not create: never remove it
  [ "$_pw" = 0 ] || die "★ SEALED-plaintext.txt was not written: $(head -c 400 "$WORK/pt.err" | tr '\n' ' ')$( [ -s "$WORK/pt.err" ] || echo 'the writer (node) failed') (no value is shown)"
  PT_TMP=
  read -r _pb _pn _ph _ptf < "$WORK/pt.out" || _pb=
  case "$_pb $_pn $_ptf" in *[!0-9\ yesno]*|' '*) die "★ SEALED-plaintext.txt was written, but its writer's report is malformed: check $PT_OUT yourself" ;; esac
  is_sha256 "$_ph" || die "★ SEALED-plaintext.txt was written, but its writer's report is malformed: check $PT_OUT yourself"
  echo "  plaintext  $PT_OUT  $_pb bytes  $_pn lines  sha256 $_ph"
  echo "  ★ SEALED-plaintext.txt contains every secret in plain text; delete it (and restored/) when done"
  echo "  ★ Time Machine exclusion (tmutil addexclusion): SEALED-plaintext.txt $_ptf, restored/ $_ptr. Spotlight may index both while they exist: read the file, then delete both promptly"
}

# ── ★ seal --list: EVERY CAPTURED FILE ITS OWN AGE BLOCK (SEALED.txt format /2, layout per-file; lane B 2026-10-14;
#    the contract: .superpowers/sdd/2026-10-14-vt-decrypt/v2-format.md) ──────────────────────────────────────────────
#    The capture, the completeness proofs, the sanitiser, the payload audit, the one-time X25519 identity and its TIME and
#    KEY wraps are v1's. Instead of ONE vault.tar.gz.age, each file v1 tars (items/<id>.json, files/<id>/<fid>, MANIFEST.csv,
#    ATTACHMENTS.csv) is gzip -n -9'd, zero-padded up to its size bucket with --pad (pad_bucket), and age-encrypted to the
#    identity's recipient as its own block b0001, b0002, ... (zero-padded to max(4, digits of N)), the numbers a random
#    permutation (8 bytes of /dev/urandom per file, sorted): a block number says nothing about a path. Which block is which
#    file is ONLY in the index, a vault-timelock-index/1 text (one TAB-separated line per block: block, path, bytes,
#    sha256, gzip bytes), audited like STRUCTURE.txt (S and P in all of it) before anything is encrypted, then gzipped,
#    padded and encrypted the same way as `index`. The package's `layout` file says per-file, the padding and where the
#    index's gzip stream ends (SEALED.txt prints it as gzip=): readers cut every decrypted block at its gzip length before
#    gunzip. The round trip decrypts the index and EVERY block from the package, cuts, gunzips and matches every digest
#    (the index's, the manifest's, ATTACHMENTS.csv's) before the plaintext work copy is removed. Without --list nothing
#    here runs: the default seal is format /1, unchanged.
#    TL_ORDER_SOURCE (self-test seam, like TL_JITTER_SOURCE) replaces /dev/urandom for the block order.
#    The lines marked "@mut:" are disabled one at a time by the self-test's mutation arms.
TAB=$(printf '\t')
V2_INDEX_HEADER=vault-timelock-index/1
# a sealed file's path: what v1's tar holds, and nothing else (ids are pseudonyms, or 1Password's own with --keep-item-ids)
V2_PATH='^(items/[a-z0-9]+[.]json|files/[a-z0-9]+/[a-z0-9]+|MANIFEST[.]csv|ATTACHMENTS[.]csv)$'
# pad_bucket N: --pad's bucket for a gzip stream of N bytes: 1, 2, 4, 8, 16, 32, 64, 128 KiB, then multiples of 128 KiB
pad_bucket() {
  if [ "$1" -gt 131072 ]; then echo $(( ($1 + 131071) / 131072 * 131072 )); return 0; fi
  _pk=1024; while [ "$_pk" -lt "$1" ]; do _pk=$((_pk * 2)); done; echo "$_pk"
}
# v2_pad FILE GZIP-BYTES: with --pad, zero bytes after the gzip stream up to its bucket
v2_pad() {
  [ "$PAD" = 1 ] || return 0
  _pz=$(( $(pad_bucket "$2") - $2 ))
  [ "$_pz" = 0 ] || head -c "$_pz" /dev/zero >> "$1" || die "could not pad a block"   # @mut:v2-pad
}
# v2_unpad IN GZIP-BYTES PADDING OUT: OUT = the gzip stream of a decrypted block or index; fails unless IN is exactly
# GZIP-BYTES long (padding none), or exactly its bucket with nothing but zero bytes after the stream (padding buckets)
v2_unpad() {
  _us=$(wc -c < "$1" | tr -d ' ') || return 1
  if [ "$3" = buckets ]; then [ "$_us" = "$(pad_bucket "$2")" ] || return 1; else [ "$_us" = "$2" ] || return 1; fi
  head -c "$2" "$1" > "$4" || return 1
  [ "$(tail -c +$(( $2 + 1 )) "$1" | tr -d '\000' | wc -c | tr -d ' ')" = 0 ]
}
# audit_index FILE: pii_audit's own pattern files over the index (floors re-checked): S and P are BOTH searched in all of
# it, since nothing in the index is the user's. Any hit refuses, counts and category names only, before encryption.
audit_index() {
  _A="$WORK/audit"
  [ -f "$_A/S.tsv" ] && [ -f "$_A/P.tsv" ] || die "★ PII/ID audit: the payload audit's patterns are missing: REFUSING to seal the index unaudited"
  audit_floors
  _hits=0; _cats=
  for c in $(cut -f1 "$_A/S.tsv" "$_A/P.tsv" | LC_ALL=C sort -u); do
    for t in S P; do
      _np1=$(audit_pats "$c" "$t")
      [ "$_np1" -gt 0 ] || continue
      _n=$(audit_count "$_A/index.c" "$1") || exit 1
      if [ "$_n" -gt 0 ]; then _hits=$(( _hits + _n )); _cats="${_cats:+$_cats, }$c"; fi
    done
  done
  [ "$_hits" = 0 ] || die "★ PII/ID audit: $_hits hit(s) (categories: $_cats) in the index (block, path, bytes, sha256, gzip bytes) — REFUSING. Counts and category names only; no value is printed. Nothing was encrypted; the plaintext work dir is removed."   # @mut:v2-audit
  echo "  audit      the index: 0 operator identifiers, 0 1Password identifiers (the payload audit's patterns)"
}
# seal_v2_prepare: (seal --list, after pii_audit, before anything is encrypted) every file of $WORK/s gzipped (and padded)
# into $WORK/v2/gz/<block>, in a random block order; the index written, audited, gzipped (and padded). Sets NB and IGZ.
seal_v2_prepare() {
  _V="$WORK/v2"; mkdir -m 700 "$_V" "$_V/gz" || die "could not create the per-file work dir"
  ( cd "$WORK/s" && find items files -type f ) > "$_V/paths.raw" || die "★ --list: the capture could not be listed"
  { LC_ALL=C sort "$_V/paths.raw" && echo MANIFEST.csv && echo ATTACHMENTS.csv; } > "$_V/paths" || die "★ --list: the capture could not be listed"
  _bp=$(grep -cvE "$V2_PATH" "$_V/paths" || true)
  [ "$_bp" = 0 ] || die "★ --list: $_bp captured path(s) are not items/<id>.json, files/<id>/<file>, MANIFEST.csv or ATTACHMENTS.csv: REFUSING (not printed)"
  NB=$(wc -l < "$_V/paths" | tr -d ' ')
  [ "$NB" -eq $(( CAPTURED + NATT + 2 )) ] || die "★ --list: $NB file(s) to seal, but $CAPTURED item(s), $NATT attachment(s) and 2 manifests were captured: REFUSING"
  # the block order: 8 random bytes per file, sorted (a uniform permutation; never printed)
  # (od -v: never "*" for a repeated line; a repeated key is then the check below's to refuse)
  od -v -An -tx1 -N $(( 8 * NB + 8 )) < "${TL_ORDER_SOURCE:-/dev/urandom}" | tr -d ' \n' | fold -w 16 | head -n "$NB" > "$_V/keys"
  [ "$(wc -l < "$_V/keys" | tr -d ' ')" = "$NB" ] && ! grep -qv '^[0-9a-f]\{16\}$' "$_V/keys" || die "★ --list: could not draw the block order"
  # (fix round 1, minor c) the keys must be distinct: a repeated key would leave that pair's order to the paths
  [ "$(LC_ALL=C sort -u "$_V/keys" | wc -l | tr -d ' ')" = "$NB" ] || die "★ --list: the block order's random keys repeat (TL_ORDER_SOURCE?): REFUSING"   # @mut:v2-order-distinct
  paste -d ' ' "$_V/keys" "$_V/paths" | LC_ALL=C sort | cut -d ' ' -f 2- > "$_V/order"   # @mut:v2-order
  _w=${#NB}; [ "$_w" -ge 4 ] || _w=4
  printf '%s\n' "$V2_INDEX_HEADER" > "$_V/index.tsv"
  _k=0
  while IFS= read -r _p; do
    _k=$((_k + 1)); _b=$(printf "b%0${_w}d" "$_k")
    _n=$(wc -c < "$WORK/s/$_p" | tr -d ' ') && _h=$(sha256_of "$WORK/s/$_p") || exit 1
    gzip -n -9 -c "$WORK/s/$_p" > "$_V/gz/$_b" || die "★ gzip FAILED on a block: refusing"   # @mut:v2-gzip
    _g=$(wc -c < "$_V/gz/$_b" | tr -d ' ')
    v2_pad "$_V/gz/$_b" "$_g"
    printf '%s\t%s\t%s\t%s\t%s\n' "$_b" "$_p" "$_n" "$_h" "$_g" >> "$_V/index.tsv"
  done < "$_V/order"
  [ "$_k" = "$NB" ] || die "★ --list: $_k block(s) prepared for $NB file(s): REFUSING"
  audit_index "$_V/index.tsv"   # @mut:v2-audit-call
  gzip -n -9 -c "$_V/index.tsv" > "$_V/index.gz" || die "★ gzip FAILED on the index: refusing"
  IGZ=$(wc -c < "$_V/index.gz" | tr -d ' ')
  v2_pad "$_V/index.gz" "$IGZ"
  echo "  blocks     $NB file(s) as $NB block(s) + the index: each gzip -n -9'd$( [ "$PAD" = 0 ] || echo ', zero-padded to its size bucket (--pad)'), numbered in a random order$( [ -z "${TL_ORDER_SOURCE:-}" ] || echo ' (drawn from TL_ORDER_SOURCE, a self-test seam: NOT random)')"
}
# seal_v2_encrypt: every prepared block, then the index, age-encrypted to the data key's recipient into the package; the
# layout file last
seal_v2_encrypt() {
  tail -n +2 "$WORK/v2/index.tsv" > "$WORK/v2/lines"
  while IFS="$TAB" read -r _b _p _n _h _g; do
    age -r "$DATA_RECIP" $ARMOR_FLAG -o "$PKG/$_b" "$WORK/v2/gz/$_b" || die "block encryption failed ($_b)"   # @mut:v2-armor
    [ -s "$PKG/$_b" ] || die "sealed block $_b is empty — refusing"
  done < "$WORK/v2/lines"
  age -r "$DATA_RECIP" $ARMOR_FLAG -o "$PKG/index" "$WORK/v2/index.gz" || die "index encryption failed"   # @mut:v2-armor-index
  [ -s "$PKG/index" ] || die "sealed index is empty — refusing"
  printf 'layout: per-file\npadding: %s\nindex-gzip: %s\n' "$V2_PADDING" "$IGZ" > "$PKG/layout" || die "could not write the layout file"
}
# v2_restore INDEX PKG KEY DEST PADDING: every block INDEX lists, decrypted from PKG with KEY into DEST/<path> (DEST: a
#   new directory the caller made). Refuses (die, block names only, never a path or a value) unless INDEX is a
#   vault-timelock-index/1 text whose every line is <bN> TAB <a sealed path> TAB <bytes> TAB <sha256> TAB <gzip bytes>, no
#   block and no path twice; the b-files in PKG are EXACTLY its blocks (none missing, none extra); and every block opens
#   with KEY, is its gzip stream (+ zero padding to its bucket with PADDING buckets), gunzips, and gives exactly the
#   bytes and SHA-256 of its line. Prints the number of blocks. Scratch in $WORK. The caller runs it in a subshell
#   (umask 077: files 600, directories 700) and removes DEST when it refuses.
v2_restore() {
  _ri=$1; _rp=$2; _rk=$3; _rd=$4; _rpad=$5
  [ "$(head -n 1 "$_ri")" = "$V2_INDEX_HEADER" ] || die "★ the index is not a $V2_INDEX_HEADER text"
  tail -n +2 "$_ri" > "$WORK/v2.lines" && [ -s "$WORK/v2.lines" ] || die "★ the index lists no block"
  LC_ALL=C awk -F '\t' -v re="$V2_PATH" 'NF != 5 || $1 !~ /^b[0-9][0-9][0-9][0-9]+$/ || $2 !~ re || $3 !~ /^[0-9]+$/ || length($3) > 12 || $4 !~ /^[0-9a-f]+$/ || length($4) != 64 || $5 !~ /^[0-9]+$/ || length($5) > 12 || b[$1]++ || p[$2]++ { bad = 1 } END { exit bad }' "$WORK/v2.lines" \
    || die "★ the index has a malformed or repeated line (not printed)"   # @mut:v2-index
  cut -f1 "$WORK/v2.lines" | LC_ALL=C sort > "$WORK/v2.want"
  find "$_rp" -mindepth 1 -maxdepth 1 -name 'b[0-9]*' > "$WORK/v2.found" || die "★ the package dir could not be listed"
  sed 's|.*/||' "$WORK/v2.found" | LC_ALL=C sort > "$WORK/v2.have"
  cmp -s "$WORK/v2.want" "$WORK/v2.have" || die "★ the package's blocks are not exactly the index's: $(wc -l < "$WORK/v2.want" | tr -d ' ') listed, $(wc -l < "$WORK/v2.have" | tr -d ' ') present (a block is missing, or one is not the index's)"   # @mut:v2-blockset
  _rn=0
  # (fix round 1, minor b) `|| [ -n "$_b" ]`: a last line with no trailing newline is restored too, never skipped
  while IFS="$TAB" read -r _b _p _n _h _g || [ -n "$_b" ]; do
    [ -f "$_rp/$_b" ] && [ ! -L "$_rp/$_b" ] || die "★ block $_b is not a regular file"
    age -d -i "$_rk" -o "$WORK/v2.blk" "$_rp/$_b" 2>/dev/null || die "★ block $_b did not open with the data key: damaged or tampered"
    v2_unpad "$WORK/v2.blk" "$_g" "$_rpad" "$WORK/v2.gz" || die "★ block $_b is not its gzip stream of $_g bytes$( [ "$_rpad" = none ] || echo ' + zero padding to its bucket')"
    mkdir -p "$_rd/$(dirname "$_p")" || die "★ block $_b: its directory could not be created"
    gzip -dc "$WORK/v2.gz" > "$_rd/$_p" 2>/dev/null || die "★ block $_b does not gunzip"
    _rh=$(sha256_of "$_rd/$_p") || exit 1
    [ "$(wc -c < "$_rd/$_p" | tr -d ' ') $_rh" = "$_n $_h" ] || die "★ block $_b: its file does not match the index (bytes or SHA-256): damaged, tampered or swapped"   # @mut:v2-digest
    _rn=$((_rn + 1))
  done < "$WORK/v2.lines"
  rm -f "$WORK/v2.blk" "$WORK/v2.gz"
  # (fix round 2, N-1) verified, then listed (the index's lines, a last one without a newline counted)
  echo "$_rn $(awk 'END { print NR }' "$WORK/v2.lines")"
}
# v2_layout DIR: (open) DIR/layout is exactly "layout: per-file", "padding: none|buckets", "index-gzip: <n>"; no
# vault.tar.gz.age beside it; an index. Sets V2_PADDING and IGZ.
v2_layout() {
  [ -f "$1/layout" ] && [ ! -L "$1/layout" ] || die "★ $1/layout is not a regular file: refusing"
  _lp=$(sed -n '2s/^padding: \([a-z]*\)$/\1/p' "$1/layout"); _lg=$(sed -n '3s/^index-gzip: \([1-9][0-9]*\)$/\1/p' "$1/layout")
  case $_lp in none|buckets) ;; *) _lp= ;; esac
  [ -n "$_lp" ] && [ -n "$_lg" ] && [ ${#_lg} -le 15 ] && printf 'layout: per-file\npadding: %s\nindex-gzip: %s\n' "$_lp" "$_lg" | cmp -s - "$1/layout" \
    || die "★ $1/layout is not exactly 'layout: per-file', 'padding: none|buckets', 'index-gzip: <n>': refusing"
  [ ! -e "$1/vault.tar.gz.age" ] && [ ! -L "$1/vault.tar.gz.age" ] || die "★ $1 holds both a per-file layout and vault.tar.gz.age: refusing an ambiguous package"
  [ -f "$1/index" ] && [ ! -L "$1/index" ] || die "no index (a regular file) in $1: a per-file package cannot be opened without it"
  V2_PADDING=$_lp; IGZ=$_lg
}
# open_v2 DIR: (open, after identity.key) the index opened, cut at its gzip length, gunzipped; restored/ created NEW (as
# v1: never an existing path) and every block decrypted into it by v2_restore; any refusal removes restored/ (it may hold
# what the blocks before decrypted to); then the on-disk check v1's extraction gets: regular files and directories only,
# no xattr, no ACL.
open_v2() {
  age -d -i "$WORK/identity.key" -o "$WORK/index.bin" "$1/index" 2>/dev/null || die "★ the data key did not open the index: damaged or tampered (or the package is inconsistent)"
  v2_unpad "$WORK/index.bin" "$IGZ" "$V2_PADDING" "$WORK/index.gz" || die "★ the index is not its gzip stream of $IGZ bytes$( [ "$V2_PADDING" = none ] || echo ' + zero padding to its bucket') (the layout file says so): refusing"
  gzip -dc "$WORK/index.gz" > "$WORK/index.tsv" 2>/dev/null || die "★ the index does not gunzip: refusing"
  mkdir -m 700 "$1/restored" || die "★ $1/restored already exists (a directory, a file or a symlink): move it away first. open writes plaintext only into a NEW restored/ it creates itself."
  set +e
  ( set -e; umask 077; v2_restore "$WORK/index.tsv" "$1" "$WORK/identity.key" "$1/restored" "$V2_PADDING" ) > "$WORK/v2.out" 2> "$WORK/v2.err"
  _vo=$?
  set -e
  if [ "$_vo" != 0 ]; then
    xv_remove "$1/restored"
    die "$(head -c 400 "$WORK/v2.err" | tr '\n' ' ')$( [ -s "$WORK/v2.err" ] || echo "★ the blocks could not be restored (exit $_vo)") — refused; restored/ removed (it held what the blocks before decrypted to)."
  fi
  _xb=$(find "$1/restored" -mindepth 1 ! -type f ! -type d) && _xa=$(find "$1/restored" -exec ls -ld {} +) || { xv_remove "$1/restored"; die "★ restored/ could not be walked: refused, removed"; }
  _xa=$(printf '%s\n' "$_xa" | awk '$1 ~ /[@+]$/')
  [ -z "$_xb" ] && [ -z "$_xa" ] || { xv_remove "$1/restored"; die "★ on disk, restored/ holds something other than regular files and directories, or carries extended attributes or an ACL: refused, removed"; }
  read -r _vr _vl < "$WORK/v2.out" && [ "$_vr" = "$_vl" ] || { xv_remove "$1/restored"; die "★ $_vr of $_vl block(s) of the index were restored: refused, restored/ removed"; }
  echo "  blocks     $_vr/$_vl block(s) opened with the data key (verified / listed in the index); every file's bytes and SHA-256 match the index"
}
# seal_v2_roundtrip: (seal --list, before the data key and the plaintext go) the index and EVERY block decrypted from the
# package with the real data key, cut, gunzipped, and every digest matched: the index's (v2_restore), and as v1's round
# trip, every item against MANIFEST.csv, every attachment against ATTACHMENTS.csv, both CSVs byte-identical
seal_v2_roundtrip() {
  RT="$WORK/rt"; mkdir -m 700 "$RT" "$RT/x"
  age -d -i "$WORK/identity.key" -o "$RT/index.bin" "$PKG/index" || die "★ the sealed index did NOT open with its own data key"
  v2_unpad "$RT/index.bin" "$IGZ" "$V2_PADDING" "$RT/index.gz" && gzip -dc "$RT/index.gz" > "$RT/index.tsv" 2>/dev/null \
    && cmp -s "$RT/index.tsv" "$WORK/v2/index.tsv" || die "★ round-trip FAILED: the sealed index does not come back as the index written. Refusing to ship a package that does not reopen."
  set +e
  ( set -e; umask 077; v2_restore "$RT/index.tsv" "$PKG" "$WORK/identity.key" "$RT/x" "$V2_PADDING" ) > "$RT/out" 2> "$RT/err"
  _vo=$?
  set -e
  [ "$_vo" = 0 ] || die "★ round-trip FAILED: $(head -c 400 "$RT/err" | tr '\n' ' ')Refusing to ship a package that does not reopen."   # @mut:v2-rt
  rtbad=0; rtn=0
  while IFS=, read -r id sha _f _s _l; do
    [ "$id" = "item_id" ] && continue
    rtn=$((rtn+1))
    if [ ! -f "$RT/x/items/$id.json" ]; then rtbad=$((rtbad+1)); continue; fi
    h=$(sha256_of "$RT/x/items/$id.json") || exit 1
    [ "$h" = "$sha" ] || rtbad=$((rtbad+1))
  done < "$WORK/s/MANIFEST.csv"
  rabad=0; ran=0
  cmp -s "$RT/x/ATTACHMENTS.csv" "$WORK/s/ATTACHMENTS.csv" && cmp -s "$RT/x/MANIFEST.csv" "$WORK/s/MANIFEST.csv" || rabad=1
  while IFS=, read -r id fid _b sha; do
    [ "$id" = "item_id" ] && continue
    ran=$((ran+1))
    h=; [ ! -f "$RT/x/files/$id/$fid" ] || { h=$(sha256_of "$RT/x/files/$id/$fid") || exit 1; }
    [ "$h" = "$sha" ] || rabad=$((rabad+1))
  done < "$WORK/s/ATTACHMENTS.csv"
  read -r _rb _rl < "$RT/out" || _rb=; [ "$_rl" = "$NB" ] || _rb=
  obliterate "$RT"
  [ "$rtbad" -eq 0 ] && [ "$rabad" -eq 0 ] && [ "$_rb" = "$NB" ] || die "★ round-trip FAILED for $rtbad of $rtn item(s) and $rabad of $ran attachment(s) ($_rb of $NB blocks). Refusing to ship a package that does not reopen."
  echo "  unsealed   round-tripped $rtn/$rtn items and $ran/$ran attachments through the real ciphertext (the index and all $NB blocks, each its own age file), digests match"
}
# readme_v2: (seal --list) README.txt of a per-file package: v1's sections, its files and steps for the blocks and the
# index (uses the seal's variables; the format /1 README is the heredoc in cmd_seal, unchanged)
readme_v2() {
  _lb=$(cd "$PKG" && ls -d b[0-9]* | LC_ALL=C sort | tail -n 1)
  _v2s=; [ -n "$STRUCT_ERR" ] || _v2s="  STRUCTURE.txt      the vault's shape with every value removed: categories, field
                     types, set/empty, counts and the archive's own ids, bound to
                     the index by SHA-256. Never publish this file.
"
  if [ "$V2_PADDING" = buckets ]; then _v2p="gzip-compressed, zero-padded up to a size bucket (--pad: 1, 2, 4 ...
                     128 KiB, then a multiple of 128 KiB),"
  else _v2p="gzip-compressed (no padding: its size is the compressed file's),"; fi
  _v2o=; [ -z "${TL_ORDER_SOURCE:-}" ] || _v2o=" -- here drawn from TL_ORDER_SOURCE,
                     a SELF-TEST seam: NOT random (never seal a real vault so)"
  cat > "$PKG/README.txt" <<EOF
================================================================================
 1PASSWORD VAULT "$VAULT" — SEALED UNTIL $WHEN
================================================================================
Sealed $(date -u +%Y-%m-%dT%H:%M:%SZ) · $DECLARED items · drand round $ROUND
Unlocks $WHEN (UTC), when drand publishes round $ROUND. Requested: $REQ.
Layout: per-file (seal --list; SEALED.txt format vault-timelock-sealed/2): every
file of the vault is its own age block, so one file can be opened alone.

  b0001 ... $_lb   $NB blocks: each file of the vault (an item's JSON, an attachment,
                     MANIFEST.csv, ATTACHMENTS.csv) on its own, $_v2p
                     then age-encrypted to a one-time X25519 key; numbered in a
                     random order${_v2o}
  index              which block is which file (block, path, bytes, SHA-256, gzip
                     bytes), gzip-compressed, padded the same way, age-encrypted to
                     the same key
  layout             per-file, the padding, and where the index's gzip stream ends
  unlock-TIME.age    that key's age identity, tlock-encrypted to drand round $ROUND
${KEYLINE}  SEALED.txt         the self-contained text to publish: unlock-TIME.age, the index
                     and every block as text, the drand parameters and the literal
                     commands that open them
  MANIFEST.csv       item ids + SHA-256 of each item's sealed JSON + field/section/
                     file counts + 1Password's own item id. No values, but the digests
                     are unsalted: anyone holding a candidate item can confirm it.
                     Never publish this file.
${_v2s}${BLANKLINE}  chain-info.json    drand quicknet's parameters, as pinned at sealing
  round              $ROUND
  README.txt         this file (it names the vault: never publish it)
  local only         $LOCALS: never published
                     SEALED-plaintext.txt: local only, created by open --plaintext after
                     the unlock time (every entry decrypted, in plain text, mode 600);
                     never publish it; delete it and restored/ promptly (Spotlight may
                     index them, and backups may copy them, while they exist)
  ASCII armor        $ARMORED
  drand contacted    $VIA

 1. WHAT KEEPS IT SHUT UNTIL $WHEN -- AND WHAT THAT ASSUMES
    Every block and the index are age-encrypted to one one-time key; that key is
    encrypted to drand round $ROUND (tlock: identity-based encryption on BLS12-381).
    The decryption key for the TIME path is drand quicknet's threshold BLS signature
    for round $ROUND, which the network is designed to publish at $WHEN. It can exist
    earlier if: (a) t or more quicknet key shares are combined -- by colluding
    operators, or by whoever steals or compels them; shares from before a reshare
    count -- which yields the signature at any time, without trace; (b) BLS12-381's
    pairing assumptions fail -- a large quantum computer would break them, and every
    copy kept or published now stays exposed until then; (c) recovery.key is used, if
    unlock-KEY.age exists (section 2). Short of these, fewer than t shares cannot
    produce the signature. Public until then: how many files ($NB) and, from each
    block's size, $( [ "$V2_PADDING" = buckets ] && echo "the size bucket of that file's gzip-compressed size
    (--pad)" || echo "that file's exact gzip-compressed size (no --pad)"), and the index's exact compressed size
    (SEALED.txt's gzip=); never a path, a name or a digest.

 2. HOW TO OPEN IT — TWO PATHS, either one is enough
    The blocks are encrypted to one fresh age key. That key is sealed twice, so
    recovering it EITHER way opens everything.

    PATH A -- TIME. Works once drand has published round $ROUND (due $WHEN), with no
    key and no secret:
        go install github.com/drand/tlock/cmd/tle@v1.2.0
        sh 1password-timelock.sh open .
        sh 1password-timelock.sh open . --plaintext   (also writes SEALED-plaintext.txt)
      or by hand (through Tor, as at sealing): SEALED.txt's steps 1-4. Step 1 is
        env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=identity.key unlock-TIME.age
      then identity.key opens the index (age -d -i identity.key), cut at its gzip
      length and gunzipped, and every block the same way, each cut at its own gzip
      length (the index's last column) and gunzipped into restored/<path>.

    PATH B -- KEY. Works at ANY time, including today, if unlock-KEY.age is present:
        sh 1password-timelock.sh open . --identity recovery.key
      or by hand:
        age -d -i recovery.key -o identity.key unlock-KEY.age
      then SEALED.txt's steps 2-4 with that identity.key.

    ★★ WHAT PATH B COSTS, STATED PLAINLY: a recovery key DEFEATS THE TIMELOCK. Anyone
    holding recovery.key can open this today. The timelock then binds only people who do
    NOT hold it. That is the right trade if your worry is "drand disappears and this is
    lost forever"; it is the wrong trade if your worry is "somebody opens this early".
    Sealing without --recovery-recipient produces no unlock-KEY.age and leaves TIME as
    the only way in.

 3. HOW TO VERIFY IT IS COMPLETE, once open (open does this itself; by hand, here,
    after restored/ exists):
        tail -n +2 MANIFEST.csv | while IFS=, read -r id h _; do
          [ "\$(shasum -a 256 "restored/items/\$id.json" 2>/dev/null | cut -d' ' -f1)" = "\$h" ] \\
            || echo "MISSING OR MISMATCH \$id"
        done
    It must print nothing, and MANIFEST.csv must have $DECLARED rows. Attachments: each
    row of restored/ATTACHMENTS.csv (item,file,bytes,sha256) must match the file
    restored/files/<item>/<file>; SEALED.txt's last step checks both with shasum -c.
    The ids inside the blocks are this seal's pseudonyms; MANIFEST.csv's last column
    (op_item_id, here only) maps each one to 1Password's own item id.

 4. IF THE TOOLING IS GONE
    SEALED.txt, beside this file, is self-contained: it carries unlock-TIME.age, the
    index and every block as text and the literal commands to open them.
    unlock-TIME.age is a standard age file with one tlock stanza; its plaintext is the
    age identity (AGE-SECRET-KEY-1...) that opens the index and every block, age files
    with one X25519 stanza each. For unlock-TIME.age you need the drand signature for
    round $ROUND on chain $CHAIN:
        curl --noproxy '' --proxy socks5h://127.0.0.1:9050 https://api.drand.sh/$CHAIN/public/$ROUND
    (through Tor, as at sealing). Scheme: bls-unchained-g1-rfc9380. Public key:
    chain-info.json, beside this file. Mirrors: api2.drand.sh, api3.drand.sh.

 5. IF DRAND IS GONE
    Then this is not openable, and that was the risk accepted. A timelock stops early
    opening (under the assumptions in section 1); it does not stop PERMANENT loss. Store
    a Shamir split with trustees as a second, human path -- the two fail in opposite
    directions.

 6. WHAT THE CAPTURE DID AND DID NOT GUARANTEE
    Items were read with \`op item get --reveal\`, because op CONCEALS sensitive fields
    by default and an export without it restores nothing. Archived items were included.
    Every attachment was fetched (op read / op document get), checked against the size
    the item reports, and is sealed as its own block with its digest (ATTACHMENTS.csv).
    Inside the seal, each item keeps every value, title, label, URL, tag and file, but
    not the account metadata around it (vault id and name, who last edited it and
    when, versions, content paths, op:// references) unless --keep-item-metadata was
    given, and 1Password's ids are replaced by this seal's pseudonyms unless
    --keep-item-ids was given. Every block is gzip -n (no name, no time) and the
    time-locked key is one line, with no creation time.
    NOT captured: vault-level settings, sharing/ACLs, item history (prior versions), and
    anything a Business policy blocked from export.
================================================================================
EOF
}
# unrelated_check FILE: an UNRELATED key must be told "no identity matched" by FILE (claims review F-14; see the seal)
unrelated_check() {
  if _ui=$(age -d -i "$WORK/unrelated.key" -o /dev/null "$1" 2>&1); then die "★ REFUSING: the payload decrypted with an UNRELATED identity. Nothing is protecting it."; fi   # @mut:no-identity
  case $_ui in *"no identity matched"*) ;; *) die "★ REFUSING: the payload is not an age file encrypted to a recipient (an unrelated key got: $_ui)" ;; esac   # @mut:no-identity-reason
}

cmd_seal() {
  # the vault name comes first: an option there would become the vault's name and reach Tor, drand and op
  # (SP review m4); --plaintext anywhere gets its own reason (Task SP)
  case ${1:-} in --plaintext) die "plaintext exists only after the unlock time — use open --plaintext" ;; -*) die "seal <vault-name> [DURATION] [options]: '$1' is an option, not a vault name: the vault name comes first" ;; esac   # @mut:pt-dash
  VAULT=${1:?usage: seal <vault-name> [DURATION] [--recovery-recipient age1...] [--armor] [--clearnet]}
  shift
  # Options may come before or after the one DURATION. Anything not starting with -- is the
  # duration, so `-1d` reaches the grammar and is refused there, with the grammar in the message.
  DUR=10; HAVE_DUR=0; RECOVERY=""; ARMOR_FLAG=""; KEEP_META=0; KEEP_IDS=0; JIT_ARG=""; ALLOW_SHORT=0; LIST=0; PAD=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --recovery-recipient) RECOVERY=${2:?--recovery-recipient needs an age1... public key}; shift 2 ;;
      # Task S2 §7: both put account metadata INSIDE the seal (public at the round); both warn
      --keep-item-metadata) KEEP_META=1; shift ;;
      --keep-item-ids) KEEP_IDS=1; shift ;;
      --allow-short-operator-strings) ALLOW_SHORT=1; shift ;;   # S2 review: 1-2 char operator strings
      # --armor (Task S1 §2): EVERY .age this writes is PEM-armored age, names unchanged. Unquoted
      # $ARMOR_FLAG below is empty or exactly --armor; age and tle both spell it that way.
      --armor) ARMOR_FLAG=--armor; shift ;;
      --jitter) JIT_ARG=${2:?--jitter needs a DURATION (0 disables the random offset)}; shift 2 ;;   # Task S2 §6
      --clearnet) CLEARNET=1; shift ;;   # the ONLY way past Tor (R40); named in the banner
      # lane B: each captured file its own age block (SEALED.txt format /2); --pad rounds each block up to a size bucket
      --list) LIST=1; shift ;;
      --pad) PAD=1; shift ;;
      # Task SP: the plaintext is written by `open`, after the unlock time; a seal never writes one
      --plaintext) die "plaintext exists only after the unlock time — use open --plaintext" ;;
      --*) die "unexpected option: $1" ;;
      *) [ "$HAVE_DUR" = 0 ] || die "more than one duration: '$DUR' and '$1' — give at most one"
         DUR=$1; HAVE_DUR=1; shift ;;
    esac
  done
  [ "$PAD" = 0 ] || [ "$LIST" = 1 ] || die "--pad goes with --list only: it pads each per-file block up to a size bucket"
  SECS=$(duration_seconds "$DUR") || exit 1
  # the duration exactly as typed; a bare number is the only form that means years
  if [ "$HAVE_DUR" = 0 ]; then REQ="10 (years, the default)"
  else case $DUR in *[!0-9]*) REQ=$DUR ;; *) REQ="$DUR (years)" ;; esac; fi
  # TL_TEST_SECONDS exists ONLY so --self-test can reach the TIME path. A 10-year seal cannot be
  # opened inside a test, and a test that never opens one cannot tell LOCKED from BROKEN.
  if [ -n "${TL_TEST_SECONDS:-}" ]; then
    case $TL_TEST_SECONDS in *[!0-9]*) die "TL_TEST_SECONDS must be whole seconds" ;; esac
    SECS=$TL_TEST_SECONDS; REQ="$REQ; overridden by TL_TEST_SECONDS=$TL_TEST_SECONDS (self-test)"
  fi
  jitter_setup
  echo "  horizon    requested: $REQ = $SECS s$( [ "$JMAX" = 0 ] || echo " + a random 0..$JMAX s") from the moment of sealing"
  # (lane B) ARCH: the file STRUCTURE.txt binds to and open's SEALED.txt checks name: the archive, or the per-file index
  ARCH=vault.tar.gz.age; V2_PADDING=none
  if [ "$LIST" = 1 ]; then ARCH=index; [ "$PAD" = 0 ] || V2_PADDING=buckets
    echo "  layout     per-file (--list): every captured file its own age block, paths only in an encrypted index; SEALED.txt format /2$( [ "$PAD" = 0 ] || echo '; --pad: block sizes rounded up to buckets')"
  fi
  need
  need_vtb
  command -v age >/dev/null 2>&1 || die "age is not installed — brew install age"
  case "$RECOVERY" in ""|age1*) : ;; *) die "--recovery-recipient must be an age1... PUBLIC key,
   never a secret. Generate one with: age-keygen -o recovery.key   (keep recovery.key OFFLINE;
   the age1... line it prints on stderr is the public half and is what goes here)" ;; esac

  # Tor and drand FIRST, before a single item is exported: a seal that cannot reach drand through
  # Tor must fail while the plaintext is still only in 1Password. Chain info is fetched and PINNED.
  tor_preflight
  INFO=$(chain_info) || exit 1

  # Work in a private directory. `mktemp -d` is 0700; the plaintext lives here for seconds. The
  # traps remove it on ANY exit; a signal also exits 130 instead of letting the seal run on.
  # An explicit template: measured 2026-10-09 (macOS 26.2), a bare `mktemp -d` IGNORES $TMPDIR and
  # uses the per-user temp dir, so the place the plaintext lives would not be the one you chose.
  _tmpd=${TMPDIR:-/tmp}
  WORK=$(mktemp -d "${_tmpd%/}/1password-timelock.XXXXXXXX") || die "mktemp failed"   # @mut:work-tmpdir
  trap 'seal_cleanup' EXIT   # @mut:trap-exit
  trap 'seal_cleanup; exit 130' HUP INT TERM   # @mut:trap-signal
  chmod 700 "$WORK"

  # ── 1. what 1Password SAYS is there ────────────────────────────────────────────────────────
  #    --include-archive is deliberate: archived items are still your data, and their absence
  #    from a backup is silent.
  "$OP" item list --vault "$VAULT" --include-archive --format json > "$WORK/list.json" \
    || die "could not list vault '$VAULT' — check the name with: op vault list"
  DECLARED=$(jq 'length' "$WORK/list.json")
  [ "$DECLARED" -gt 0 ] || die "vault '$VAULT' reports 0 items — refusing to seal an empty archive"
  echo "  declared   $DECLARED item(s)"

  # ── 2. capture, with --reveal, straight to disk inside 0700 and never to stdout ────────────
  #    ★ ATTACHMENTS (Task S2 §1; claims review F-2). Files are REFERENCES in the item JSON
  #      (`.files[]`: id, name, size; shape per https://www.1password.dev/cli/item-template-json and
  #      https://www.1password.dev/connect/api-reference/get-vault-item-by-id); the bytes need a second
  #      call, with the DOCUMENTED syntax of op CLI 2.x (docs only: this tool never ran op to find out):
  #        · a file attached to ANY item:  op read --out-file <path> "op://<vaultID>/<itemID>/<fileID>"
  #          (https://www.1password.dev/cli/reference/commands/read; the reference syntax
  #          https://www.1password.dev/cli/secret-reference-syntax: "To reference a file attachment, use
  #          the file name in place of a field name", and any part "must be referred to by its unique
  #          identifier (ID)" when needed: IDs only, so no title or file NAME is ever in argv or a log;
  #          the optional [section/] part is omitted)
  #        · a Document item's one file:   op document get <itemID> --vault <vaultID> --include-archive
  #                                          --out-file <path>
  #          (https://www.1password.dev/cli/reference/management-commands/document: it takes an ITEM
  #          name or ID, never a file ID; the flag is --out-file, which "won't overwrite an existing file";
  #          --include-archive: "Include document items in the Archive")
  #      ★ ARCHIVED items (S2 review): `op read` documents no --include-archive
  #        (https://www.1password.dev/cli/reference/commands/read lists --file-mode, --force,
  #        --no-newline, --out-file only), so for an attachment of an archived non-Document item
  #        (.state ARCHIVED) the docs give no way to address it: if op read fails there, the refusal
  #        says so, naming the item and file ids. Unarchive the item, or seal without it.
  #      Each lands in files/<itemID>/<fileID>. op's stdin is /dev/null: it must not eat the id list
  #      this loop reads, and a prompt fails instead of hanging. The checks after the loop FAIL CLOSED:
  #      any failed fetch, any item whose fetched-file count differs from its .files count, any file
  #      whose size differs from the JSON's .size. Then every file's bytes and SHA-256 go into
  #      ATTACHMENTS.csv, sealed INSIDE the archive and re-checked by the round trip and by open.
  #    --include-archive on item get: archived items are in the list (step 1) and are fetched too.
  mkdir -p "$WORK/items" "$WORK/files"
  # every item id becomes a path, an argv word and a pattern: only 1Password's documented id shape,
  # 26 characters [a-z0-9] (the Item id pattern ^[\da-z]{26}$,
  # https://www.1password.dev/connect/api-reference/get-vault-item-by-id); else refuse (S2 re-review M-6)
  _bid=$(jq -r '.[].id' "$WORK/list.json" | grep -cvE '^[a-z0-9]{26}$' || true)
  [ "$_bid" = 0 ] || die "★ op item list returned $_bid item id(s) that are not 26 [a-z0-9] characters: REFUSING (they would become paths and patterns; not printed)"   # @mut:item-id
  n=0
  jq -r '.[].id' "$WORK/list.json" | while IFS= read -r id; do
    # ★ --reveal is what makes this a backup rather than a picture of one.
    "$OP" item get "$id" --format json --reveal --include-archive > "$WORK/items/$id.json" 2>/dev/null </dev/null \
      || { echo "$id" >> "$WORK/failed"; continue; }
    vid=$(jq -r '.vault.id // ""' "$WORK/items/$id.json" 2>/dev/null) || vid=
    ic=$(jq -r '.category // "" | ascii_downcase' "$WORK/items/$id.json" 2>/dev/null) || ic=
    ia=$(jq -r 'if (.state // "") == "ARCHIVED" then " (an ARCHIVED item: op read documents no --include-archive; unarchive it, or seal without it)" else "" end' "$WORK/items/$id.json" 2>/dev/null) || ia=
    nfl=$(jq '[.files // [] | .[]] | length' "$WORK/items/$id.json" 2>/dev/null) || nfl=0
    jq -r '(.files // [])[] | .id // ""' "$WORK/items/$id.json" 2>/dev/null | while IFS= read -r fid; do
      # ids become an op:// reference and a PATH: 1Password's own charset only, else it is a failure
      case "$vid" in ''|*[!a-z0-9]*) echo "$id/(vault id not [a-z0-9]+)" >> "$WORK/failed-files"; continue ;; esac
      case "$fid" in ''|*[!a-z0-9]*) echo "$id/(file id not [a-z0-9]+)" >> "$WORK/failed-files"; continue ;; esac
      mkdir -p "$WORK/files/$id"
      if [ "$ic" = document ] && [ "$nfl" = 1 ]; then
        "$OP" document get "$id" --vault "$vid" --include-archive --out-file "$WORK/files/$id/$fid" </dev/null >/dev/null 2>&1 \
          || echo "$id/$fid" >> "$WORK/failed-files"
      else
        "$OP" read --out-file "$WORK/files/$id/$fid" "op://$vid/$id/$fid" </dev/null >/dev/null 2>&1 \
          || echo "$id/$fid$ia" >> "$WORK/failed-files"
      fi
    done
    n=$((n+1)); printf '\r  captured   %s/%s' "$n" "$DECLARED"
  done
  echo

  if [ -f "$WORK/failed" ]; then
    die "★ $(wc -l < "$WORK/failed" | tr -d ' ') item(s) could not be read. REFUSING to seal a
   partial vault — a backup missing items it does not name is worse than none."
  fi
  # ★ a failed attachment fetch used to land here and be read by nothing (F-2). Item/file ids only.
  [ ! -s "$WORK/failed-files" ] || die "★ $(wc -l < "$WORK/failed-files" | tr -d ' ') attachment(s) could not be fetched (item/file ids): $(tr '\n' ' ' < "$WORK/failed-files")— REFUSING to seal a vault whose attachments are missing."   # @mut:failed-files

  # ── 3. the manifest: UUID, digest, shape. NO VALUES. ──────────────────────────────────────
  #    This is what makes completeness checkable in ten years without opening the archive.
  {
    echo "item_id,sha256,field_count,section_count,file_count"
    for f in "$WORK"/items/*.json; do
      id=$(basename "$f" .json)
      h=$(sha256_of "$f") || exit 1
      fc=$(jq '[.fields // [] | .[]] | length' "$f")
      sc=$(jq '[.sections // [] | .[]] | length' "$f")
      lc=$(jq '[.files // [] | .[]] | length' "$f")
      echo "$id,$h,$fc,$sc,$lc"
    done
  } > "$WORK/MANIFEST.csv"
  CAPTURED=$(( $(wc -l < "$WORK/MANIFEST.csv") - 1 ))

  # ── 4. ★ THE COMPLETENESS PROOF — three counts, and they must all agree ───────────────────
  echo "  manifest   $CAPTURED row(s)"
  [ "$CAPTURED" -eq "$DECLARED" ] \
    || die "★ COUNT MISMATCH: 1Password declared $DECLARED, captured $CAPTURED. Refusing."

  # every declared id must appear in the manifest — a count can match while the SET differs
  MISSING=$(jq -r '.[].id' "$WORK/list.json" | while IFS= read -r id; do
              grep -q "^$id," "$WORK/MANIFEST.csv" || echo "$id"; done | wc -l | tr -d ' ')
  [ "$MISSING" -eq 0 ] || die "★ $MISSING declared id(s) absent from the manifest. Refusing."

  # ── ★★★ PAYLOAD COMPLETENESS: does each entry carry an ACTUAL VALUE, not just a shape? ────
  #    This is the arm that catches a concealed export. `--reveal` should make every field carry
  #    its value; without it op emits the field with the value blanked, which has the right
  #    field_count and the wrong contents. Counted by STRUCTURE — a value is checked for being
  #    non-empty, and its bytes are never read, printed, or compared to anything.
  # ── ★★★ POPULATION, NOT PER ITEM. Requirement: some entries may legitimately
  #    have blanks. `--reveal` is a PER-INVOCATION flag — it takes effect for every item
  #    or for none — so a concealed export fails UNIFORMLY. A FEW blank items beside a populated
  #    majority is therefore positive evidence that --reveal WORKED, and the earlier per-item rule
  #    read it as proof of the opposite and refused to back up a correct vault.
  #
  #    100 % blank is a MODE. A few % blank is a VAULT.
  WITHFIELDS=0; NOVALUE=0; WITHCONCEAL=0; NOCONCEAL=0; NOPASS=0; LOGINS=0
  : > "$WORK/blank-items.txt"
  for f in "$WORK"/items/*.json; do
    id=$(basename "$f" .json)
    nf=$(jq '[.fields // [] | .[]] | length' "$f")
    v=$(jq '[.fields // [] | .[] | select((.value // "") != "")] | length' "$f")
    if [ "$nf" -gt 0 ]; then
      WITHFIELDS=$((WITHFIELDS+1))
      if [ "$v" -eq 0 ]; then NOVALUE=$((NOVALUE+1)); echo "$id" >> "$WORK/blank-items.txt"; fi
    fi
    # `concealed` is the type `--reveal` un-masks — `op item get --help`, `--fields type=concealed`
    nc=$(jq '[.fields // [] | .[] | select((.type // "" | ascii_downcase) == "concealed")] | length' "$f")
    ncv=$(jq '[.fields // [] | .[] | select((.type // "" | ascii_downcase) == "concealed" and ((.value // "") != ""))] | length' "$f")
    if [ "$nc" -gt 0 ]; then
      WITHCONCEAL=$((WITHCONCEAL+1))
      if [ "$ncv" -eq 0 ]; then NOCONCEAL=$((NOCONCEAL+1)); fi
    fi
    needs=$(jq -r 'if ((.category // "" | ascii_downcase) == "login" or (.category // "" | ascii_downcase) == "password") then "y" else "n" end' "$f")
    if [ "$needs" = "y" ]; then
      LOGINS=$((LOGINS+1))
      hp=$(jq '[.fields // [] | .[] | select(((.purpose // "" | ascii_downcase) == "password") and ((.value // "") != ""))] | length' "$f")
      if [ "$hp" -eq 0 ]; then NOPASS=$((NOPASS+1)); echo "$id" >> "$WORK/blank-items.txt"; fi
    fi
  done

  # ★ REFUSE only on the UNIFORM case — that is the only shape a per-invocation flag can produce.
  if [ "$WITHFIELDS" -gt 0 ] && [ "$NOVALUE" -eq "$WITHFIELDS" ]; then
    die "★ ALL $WITHFIELDS item(s) with fields are blank. That IS the concealed-export signature:
   --reveal is per-invocation, so it fails for every item or none, and every one is empty. Either
   --reveal did not take effect or this vault holds nothing. Refusing."
  fi
  if [ "$WITHCONCEAL" -gt 0 ] && [ "$NOCONCEAL" -eq "$WITHCONCEAL" ]; then
    die "★ ALL $WITHCONCEAL item(s) with CONCEALED-type fields are empty. Per \`op item get --help\`,
   concealed is exactly the type --reveal un-masks. Refusing."
  fi

  # ★ PARTIAL is DATA, not a defect. Report it — by UUID, never by title — and continue.
  if [ "$NOVALUE" -gt 0 ]; then
    echo "  note       $NOVALUE of $WITHFIELDS item(s) have fields but no value — sealed anyway."
    echo "             These are entries that are genuinely empty (a login with no password saved,"
    echo "             unfilled optional fields). --reveal demonstrably worked: the other"
    echo "             $(( WITHFIELDS - NOVALUE )) carry values, and it cannot work for some and not others."
  fi
  if [ "$NOPASS" -gt 0 ]; then
    echo "  note       $NOPASS of $LOGINS login item(s) carry no password — sealed anyway (a login"
    echo "             saved with only a username is ordinary; there is no rule that every login"
    echo "             has a stored password)."
  fi
  if [ "$NOVALUE" -eq 0 ] && [ "$NOPASS" -eq 0 ]; then
    echo "  payload    every item carries a value; every login carries a password"
  else
    echo "  payload    populated items verified; blanks reported above, not treated as failures"
  fi

  # an item with zero fields AND zero files captured nothing but a name
  EMPTY=$(awk -F, 'NR>1 && $3==0 && $5==0' "$WORK/MANIFEST.csv" | wc -l | tr -d ' ')
  [ "$EMPTY" -eq 0 ] \
    || die "★ $EMPTY item(s) captured with no fields and no files — that is the --reveal
   failure mode (concealed values look like absent ones). Refusing."
  echo "  verified   counts agree, id sets agree, no item is hollow"

  # ── 4b. ★ ATTACHMENTS: every file the JSON lists is on disk, at its size, and digested ─────
  #    Per item: the regular files in files/<id>/ AND the listed ids found there must both number
  #    exactly the item's .files count (a missing file, or a stray one, refuses); per file: its
  #    bytes must equal the JSON's .size (a truncated or converted download refuses). The rows are
  #    item_id,file_id,bytes,sha256: sealed inside the archive (ATTACHMENTS.csv), never beside it.
  echo "item_id,file_id,bytes,sha256" > "$WORK/ATTACHMENTS.csv"
  for f in "$WORK"/items/*.json; do
    id=$(basename "$f" .json)
    jq -r '(.files // [])[] | "\(.id // "")|\(.size // "")"' "$f" | while IFS='|' read -r fid fsz; do
      [ -f "$WORK/files/$id/$fid" ] || continue
      fb=$(wc -c < "$WORK/files/$id/$fid" | tr -d ' ')
      [ "$fb" = "$fsz" ] || die "★ attachment $id/$fid is $fb bytes, but the item JSON says $fsz: a truncated or converted download. REFUSING."   # @mut:att-size
      fh=$(sha256_of "$WORK/files/$id/$fid") || exit 1
      echo "$id,$fid,$fb,$fh"
    done >> "$WORK/ATTACHMENTS.csv" || exit 1
  done
  while IFS=, read -r id _h _f _s lc; do
    [ "$id" = item_id ] && continue
    nd=0; [ ! -d "$WORK/files/$id" ] || nd=$(find "$WORK/files/$id" -type f | wc -l | tr -d ' ')
    nr=$(grep -c "^$id," "$WORK/ATTACHMENTS.csv" || true)
    [ "$nd" = "$lc" ] && [ "$nr" = "$lc" ] || die "★ item $id lists $lc attachment(s); $nr of them were fetched and $nd file(s) are on disk. REFUSING to seal an incomplete capture."   # @mut:att-count
  done < "$WORK/MANIFEST.csv"
  NATT=$(( $(wc -l < "$WORK/ATTACHMENTS.csv") - 1 ))
  echo "  attachments $NATT file(s): every listed file fetched, sizes match the item JSON (ATTACHMENTS.csv, sealed inside)"

  # ── 4c. ★★ NO PII OF THE OPERATOR, NO 1PASSWORD IDENTIFIER IN THE SEALED PAYLOAD (Task S2 §7) ──
  #    The vault's VALUES are the payload: titles, labels, field values, URLs, tags, file names and
  #    bytes stay exactly as op revealed them. What `op item get --format json` adds AROUND them
  #    (https://www.1password.dev/cli/item-template-json; files[] as
  #    https://www.1password.dev/connect/api-reference/get-vault-item-by-id; fields[].reference per
  #    https://www.1password.dev/cli/secret-reference-syntax) names the account, not the secrets,
  #    and is public at the round. The capture and the completeness proof above used the REAL ids;
  #    from here on the sealed copy is built in $WORK/s from SANITISED JSON:
  #      · DROPPED: vault {id, name}, last_edited_by (an account member's UUID), version,
  #        created_at, updated_at (activity times); content_path (embeds vault/item/file ids) and
  #        reference (op://vault/item/... ) everywhere.
  #      · PSEUDONYMISED, with fresh random values for this seal (32 hex chars, /dev/urandom),
  #        consistently (one real id, one pseudonym, wherever it occurs as a string value: a field's
  #        section.id is its section's pseudonym): every `id` except vault.id, plus the value of a
  #        REFERENCE field. Built-in names are kept: an id of 1-20 letters, '_' or ' ' starting with
  #        a letter (username, password, notesPlain, database_type, "add more") is a field or
  #        section NAME, not an identifier; 1Password's generated ids are 26 characters.
  #      · archive paths use the pseudonyms: items/<item>.json, files/<item>/<file>; the SEALED
  #        MANIFEST.csv and ATTACHMENTS.csv carry pseudonyms and the sanitised digests. The LOCAL
  #        MANIFEST.csv beside the package adds the real op item id per row (local only, R44).
  #    --keep-item-metadata keeps the dropped metadata (vault, last_edited_by, version, the two
  #    times); --keep-item-ids keeps every id, content_path and reference. Each says so, loudly.
  #    The data key file is ONE line (AGE-SECRET-KEY-1...): age-keygen's "# created: <local time
  #    with UTC offset>" and "# public key:" comments would be inside unlock-TIME.age and public
  #    at the round (measured: the seal time and the timezone).
  [ "$KEEP_META" = 0 ] || echo "  ★ --keep-item-metadata: the vault id and name, the member UUID who last edited each item, item versions and created/updated times go INSIDE the seal, readable by anyone after the unlock round."
  [ "$KEEP_IDS" = 0 ] || echo "  ★ --keep-item-ids: 1Password's item, file, section and field ids, content paths and op:// references (both embed the vault id) go INSIDE the seal, readable by anyone after the unlock round; they are stable account-scoped identifiers."
  mkdir -m 700 "$WORK/s" "$WORK/s/items" "$WORK/s/files"
  if [ "$KEEP_IDS" = 1 ]; then echo '[]' > "$WORK/ids.json"
  else
    jq -s '[.[] | ([paths(type == "string") as $p | select($p[-1] == "id" and $p[0] != "vault") | getpath($p)]
                   + [(.fields // [])[] | select((.type // "") == "REFERENCE") | .value | strings])[]]
           | map(select(test("^[A-Za-z][A-Za-z_ ]{0,19}$") | not)) | unique' "$WORK"/items/*.json > "$WORK/ids.json" || die "could not read the item ids"
  fi
  _ni=$(jq length "$WORK/ids.json")
  if [ "$_ni" = 0 ]; then echo '[]' > "$WORK/pseudo.json"
  else od -An -tx1 -N $(( 16 * _ni + 16 )) /dev/urandom | tr -d ' \n' | fold -w 32 | head -n "$_ni" | jq -R . | jq -s . > "$WORK/pseudo.json"; fi
  jq -n --slurpfile i "$WORK/ids.json" --slurpfile p "$WORK/pseudo.json" \
    'if ($p[0] | length) == ($i[0] | length) and ($p[0] | unique | length) == ($i[0] | length) then [range(0; $i[0] | length) as $k | {($i[0][$k]): $p[0][$k]}] | add // {} else error("pseudonyms") end' \
    > "$WORK/map.json" || die "could not draw pseudonyms"
  # pseudo ID: its pseudonym; with --keep-item-ids the id itself. An id the map does not hold refuses
  # (S2 review: mapping it to itself would put a real 1Password id into the archive's paths)
  pseudo() {
    if [ "$KEEP_IDS" = 1 ]; then echo "$1"; return 0; fi
    jq -er --arg k "$1" '.[$k] // error("unmapped")' "$WORK/map.json" 2>/dev/null || die "★ no pseudonym for 1Password id $1 (it is not an id the item JSON carries: did op's JSON shape change?): REFUSING"   # @mut:pseudo-strict
  }
  echo "item_id,sha256,field_count,section_count,file_count" > "$WORK/s/MANIFEST.csv"
  echo "item_id,sha256,field_count,section_count,file_count,op_item_id" > "$WORK/MANIFEST.local.csv"
  for f in "$WORK"/items/*.json; do
    id=$(basename "$f" .json); pid=$(pseudo "$id") || exit 1
    jq --slurpfile m "$WORK/map.json" --argjson km "$KEEP_META" --argjson ki "$KEEP_IDS" '
      $m[0] as $map
      | (if $km == 1 then . else del(.vault, .last_edited_by, .version, .created_at, .updated_at) end)   # @mut:sanitize-meta
      | walk(if type == "object" then
               (if $ki == 1 then . else del(.content_path, .reference) end)   # @mut:sanitize-paths
               | with_entries(if (.value | type) == "string" and $map[.value] != null then .value = $map[.value] else . end)
             else . end)' "$f" > "$WORK/s/items/$pid.json" || die "could not sanitise item $id"
    sf="$WORK/s/items/$pid.json"
    sh2=$(sha256_of "$sf") || exit 1
    row="$sh2,$(jq '[.fields // [] | .[]] | length' "$sf"),$(jq '[.sections // [] | .[]] | length' "$sf"),$(jq '[.files // [] | .[]] | length' "$sf")"
    echo "$pid,$row" >> "$WORK/s/MANIFEST.csv"
    echo "$pid,$row,$id" >> "$WORK/MANIFEST.local.csv"
  done
  echo "item_id,file_id,bytes,sha256" > "$WORK/s/ATTACHMENTS.csv"
  while IFS=, read -r id fid fb fh; do
    [ "$id" = item_id ] && continue
    pid=$(pseudo "$id") || exit 1; pfid=$(pseudo "$fid") || exit 1
    mkdir -p -m 700 "$WORK/s/files/$pid"
    mv "$WORK/files/$id/$fid" "$WORK/s/files/$pid/$pfid" || die "could not move attachment $id/$fid"
    echo "$pid,$pfid,$fb,$fh" >> "$WORK/s/ATTACHMENTS.csv"
  done < "$WORK/ATTACHMENTS.csv"
  if [ "$KEEP_META" = 0 ]; then _sm="account metadata dropped"; else _sm="account metadata KEPT (--keep-item-metadata)"; fi
  if [ "$KEEP_IDS" = 0 ]; then _si="$_ni 1Password id(s) pseudonymised"; else _si="1Password ids KEPT (--keep-item-ids)"; fi
  echo "  sanitised  $DECLARED item(s): $_sm, $_si; values untouched"

  # ── 5. seal ────────────────────────────────────────────────────────────────────────────────
  #    GENESIS and PERIOD are the pinned quicknet values chain_info just matched.
  NOW=$(date -u +%s)
  J=0; [ "$JMAX" = 0 ] || J=$(jitter_draw "$JMAX")   # drawn once, never printed
  TARGET=$(( NOW + SECS + J ))   # @mut:jitter
  ROUND=$(round_for "$TARGET" "$GENESIS" "$PERIOD")
  # the round's own time (the round of TARGET's period, at most PERIOD-1 s before TARGET), not
  # TARGET: that is when it opens
  WHEN=$(round_iso "$ROUND")
  echo "  unlock     $WHEN  (drand round $ROUND; requested: $REQ)"
  assert_future "$ROUND"   # before encrypting anything: a horizon inside the margin is refused here

  # -m applies to the leaf only, and only if mkdir creates it: an existing dir keeps its mode. The
  # package dir is NEW (no -p: an existing one is refused) and 0700 whatever the umask (SA-N10).
  # A data dir that is itself a symlink is refused: packages are never written through one.
  [ ! -L "$OUT" ] || die "★ $OUT is a symlink: refusing to write packages through it"   # @mut:out-symlink
  mkdir -p -m 700 "$OUT" || die "could not create $OUT"
  PKG="$OUT/1password-$VAULT-timelock-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -m 700 "$PKG" || die "could not create a new package dir $PKG"   # @mut:pkg-mode
  PKG_PARTIAL=$PKG
  printf '%s' "$INFO" > "$PKG/chain-info.json"   # the pinned, checked info: tle encrypts with exactly this

  # ── TWO LAYERS, because `tle` accepts ROUNDS ONLY and cannot carry a second recipient. ──────
  #    The payload is encrypted ONCE to a fresh age key. That key is then sealed by each unlock
  #    path independently, so recovering it by EITHER path opens the payload. This is ordinary
  #    hybrid encryption; the only design choice is that the paths are ORs, not ANDs.
  # The data key is ONE line, the secret: age-keygen's comment lines (creation time in local time
  # with the UTC offset, the public key) never touch the disk, so tle and age encrypt only this.
  age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-1' > "$WORK/identity.key" || die "age-keygen failed"   # @mut:key-strip
  DATA_RECIP=$(age-keygen -y "$WORK/identity.key") && [ -n "$DATA_RECIP" ] || die "could not derive the data key's recipient"

  # ── ★ THE ARCHIVE CARRIES NO METADATA OF THE SEALING ACCOUNT (Task S2 §2; claims review F-11) ──
  #    Everything inside becomes public at the round. A plain `tar czf` (measured 2026-10-09 on a
  #    synthetic tree, bsdtar 3.5.3) wrote the login name as every entry's owner, uid 501, seal-time
  #    mtimes and modes, the files' xattrs as pax records (Spotlight's kMDItemWhereFroms = download
  #    URLs), and the gzip header's MTIME. So, on the WORK copies (never anything of the user's):
  #      · dirs 700, files 600, every mtime 2000-01-01T00:00:00Z. TZ=UTC0 matters: `touch -t` reads
  #        LOCAL time, so without it the epoch stored would encode this machine's UTC offset;
  #      · tar $TAR_SCRUB (ustar: no pax records at all, so no xattrs, plus --no-xattrs and
  #        --no-mac-metadata; owner 0/0 nobody/nobody; COPYFILE_DISABLE=1: no AppleDouble ._ files);
  #      · gzip -n -9 (no name, MTIME 0), then zero-padded to a multiple of 10,240 B, the size
  #        granularity bsdtar's own piped output had: the payload's length reveals the compressed
  #        vault size to within 10 KiB, not to the byte. bsdtar and gzip -d read the padding.
  #    The archive is written to $WORK (the same 0700 dir as the plaintext items), its exit status
  #    checked, then encrypted.
  find "$WORK/s" -mindepth 1 -type d -exec chmod 700 {} + && find "$WORK/s" -type f -exec chmod 600 {} + \
    && find "$WORK/s" -mindepth 1 -exec env TZ=UTC0 touch -h -t 200001010000 {} + || die "could not normalise the work copies"   # @mut:normalize
  COPYFILE_DISABLE=1 tar $TAR_SCRUB -cf "$WORK/vault.tar" -C "$WORK/s" items files MANIFEST.csv ATTACHMENTS.csv || die "★ tar FAILED while archiving the capture: refusing"
  pii_audit
  # --list (lane B): the per-file blocks and the index instead of ONE archive (the tar above was the audit's input only)
  if [ "$LIST" = 1 ]; then seal_v2_prepare; seal_v2_encrypt; else
  gzip -n -9 -c "$WORK/vault.tar" > "$WORK/vault.tar.gz" || die "★ gzip FAILED: refusing"   # @mut:gzip
  _gz=$(wc -c < "$WORK/vault.tar.gz" | tr -d ' ')
  head -c $(( (10240 - _gz % 10240) % 10240 )) /dev/zero >> "$WORK/vault.tar.gz" || die "could not pad the archive"
  age -r "$DATA_RECIP" $ARMOR_FLAG -o "$PKG/vault.tar.gz.age" "$WORK/vault.tar.gz" || die "payload encryption failed"   # @mut:armor-payload
  [ -s "$PKG/vault.tar.gz.age" ] || die "sealed payload is empty — refusing"
  fi

  # PATH A — TIME. The data key sealed to a drand round; opens itself when the round arrives.
  # With the PINNED chain info, served on loopback (info_serve: tle's own fetch is not trusted for
  # the scheme, E4); tle_net, the key as a FILE argument so a retry re-reads it.
  info_serve "$PKG"
  tle_net --encrypt --chain="$CHAIN" --round="$ROUND" --output="$PKG/unlock-TIME.age" --network="http://127.0.0.1:$INFO_PORT" $ARMOR_FLAG "$WORK/identity.key" || die "timelock of the data key failed"   # @mut:armor-time
  info_stop

  # PATH B — KEY. The same data key, to a recipient YOU hold. Optional, and it changes what this
  # artefact guarantees; see the README section it generates.
  if [ -n "$RECOVERY" ]; then
    age -r "$RECOVERY" $ARMOR_FLAG -o "$PKG/unlock-KEY.age" "$WORK/identity.key" || die "recovery-key encryption failed"   # @mut:armor-key
  fi
  # ── ★★★ PROVE THE PAYLOAD OPENS WITH THE DATA KEY, NOW, BEFORE THE KEY IS DESTROYED ─────────
  #    (the TIME wrap cannot be opened before its round, and the KEY wrap needs recovery.key: neither
  #    is exercised here; --self-test exercises both on a 60 s seal; claims review F-9)
  #    Sealing and not unsealing is the whole class of backup that fails on the day it is needed.
  #    This decrypts the REAL ciphertext with the REAL data key, extracts it, and checks every
  #    item against its manifest digest. Byte comparison only — no value is read or shown.
  #    With --armor this is the ARMORED file exactly as written: age -d and tle --decrypt detect
  #    armor by content (measured 2026-10-09: age v1.3.1, tle v1.2.0), so no de-armoring step exists
  #    that could pass while the shipped bytes fail.
  #    It extracts INSIDE $WORK ($WORK/rt), so the traps that remove $WORK cover it (audit K20).
  #    --list (lane B): the index and EVERY block, each decrypted, cut and gunzipped (seal_v2_roundtrip).
  if [ "$LIST" = 1 ]; then seal_v2_roundtrip; else
  RT="$WORK/rt"; mkdir -m 700 "$RT"
  age -d -i "$WORK/identity.key" -o "$RT/rt.tar.gz" "$PKG/vault.tar.gz.age" \
    || die "★ the sealed payload did NOT open with its own data key"
  tar -xzf "$RT/rt.tar.gz" -C "$RT" || die "★ the sealed archive did not extract"
  rtbad=0; rtn=0
  while IFS=, read -r id sha _f _s _l; do
    [ "$id" = "item_id" ] && continue
    rtn=$((rtn+1))
    if [ ! -f "$RT/items/$id.json" ]; then rtbad=$((rtbad+1)); continue; fi
    h=$(sha256_of "$RT/items/$id.json") || exit 1
    [ "$h" = "$sha" ] || rtbad=$((rtbad+1))
  done < "$WORK/s/MANIFEST.csv"
  # ...and every attachment against ATTACHMENTS.csv, which must itself come back byte-identical
  rabad=0; ran=0
  cmp -s "$RT/ATTACHMENTS.csv" "$WORK/s/ATTACHMENTS.csv" || rabad=1
  while IFS=, read -r id fid _b sha; do
    [ "$id" = "item_id" ] && continue
    ran=$((ran+1))
    h=; [ ! -f "$RT/files/$id/$fid" ] || { h=$(sha256_of "$RT/files/$id/$fid") || exit 1; }
    [ "$h" = "$sha" ] || rabad=$((rabad+1))
  done < "$WORK/s/ATTACHMENTS.csv"
  obliterate "$RT"
  [ "$rtbad" -eq 0 ] && [ "$rabad" -eq 0 ] || die "★ round-trip FAILED for $rtbad of $rtn item(s) and $rabad of $ran attachment(s). Refusing to ship a package that does not reopen."   # @mut:rt-attachments
  echo "  unsealed   round-tripped $rtn/$rtn items and $ran/$ran attachments through the real ciphertext, digests match"
  fi

  obliterate "$WORK/identity.key"

  # ── 5b. ★ STRUCTURE.txt (Task S3): the shape of what was just sealed, from the sanitised work copies,
  #    after the round-trip proof. Built, counted against MANIFEST.csv, audited and copied in a subshell:
  #    a failure there leaves the package to finish (it is sound) and is reported at the end, where the
  #    seal then does NOT report success, as for SEALED.txt.
  STRUCT_ERR=
  set +e
  ( set -e; structure_prepare ) 2> "$WORK/structure.err"
  _sst=$?
  set -e
  if [ "$_sst" != 0 ]; then
    STRUCT_ERR=$(tr '\n' ' ' < "$WORK/structure.err" | sed 's/ *$//') || STRUCT_ERR=
    STRUCT_ERR=${STRUCT_ERR:-the step exited $_sst}
    rm -f "$PKG/STRUCTURE.txt"
  fi

  # A copy of the manifest also stays BESIDE the package (the sealed one is inside). It does NOT let
  # anyone verify the archive without opening it: its digests are of the item JSON inside. It lets
  # `open` check, after decrypting, that every item came back intact, and it lets you read the item
  # count without decrypting. This local copy adds op_item_id, the REAL 1Password UUID behind each
  # pseudonym (Task S2 §7). It holds no values, but it names item UUIDs and carries unsalted
  # digests of revealed items, so it stays local and is never published (R44).
  cp "$WORK/MANIFEST.local.csv" "$PKG/MANIFEST.csv"
  # UUIDs of entries that were genuinely blank at seal time — opaque ids, no titles, no values.
  # Shipped so a restore ten years from now can tell "this was empty when sealed" from "this was
  # lost in transit", which the digests alone cannot say.
  if [ -s "$WORK/blank-items.txt" ]; then
    sort -u "$WORK/blank-items.txt" > "$PKG/BLANK-AT-SEAL.txt"
  fi
  echo "$ROUND" > "$PKG/round"
  # informational only: readers (open, seal-text, publish) detect armor by CONTENT, never by this
  if [ -n "$ARMOR_FLAG" ]; then
    echo pem > "$PKG/ARMOR"
    ARMORED="yes: every .age here is PEM-armored age (marker file ARMOR);
                     age -d and tle --decrypt read it as is, like the binary form"
  else ARMORED="no (binary age)"; fi
  if [ "$CLEARNET" = 1 ]; then
    VIA="CLEARNET (--clearnet): drand saw this IP ask for round $ROUND.
                     Re-seal over Tor before publishing this anywhere (R40)."
  else VIA="through Tor only (R40)"; fi

  # ── 6. ★★ NEGATIVE CONTROL. Sealing without proving it is SHUT is theatre. ─────────────────
  #    Locally (the pinned parameters and the clock, no network), then drand through Tor: tle's
  #    "too early" for unlock-TIME.age exactly as written AND the relay's HTTP 425 for the round
  #    (assert_shut). Any of them failing refuses.
  assert_future "$ROUND"
  assert_shut "$PKG/unlock-TIME.age" "$ROUND"
  # and an UNRELATED key must be told "no identity matched": the payload is an age file encrypted
  # to a recipient, not plaintext and not passphrase-encrypted. (`age -d` WITHOUT -i fails on any
  # input, plaintext included, so the old check here could never fire: claims review F-14.)
  age-keygen 2>/dev/null | grep '^AGE-SECRET-KEY-1' > "$WORK/unrelated.key" || die "age-keygen failed"
  # (--list: the index and every block)
  if [ "$LIST" = 1 ]; then for _uf in "$PKG/index" "$PKG"/b[0-9]*; do unrelated_check "$_uf"; done
  else unrelated_check "$PKG/vault.tar.gz.age"; fi

  # the optional files, for the README's list (claims review F-4)
  KEYLINE=; BLANKLINE=; STRUCTLINE=; LOCALS="README.txt, MANIFEST.csv"
  [ -z "$RECOVERY" ] || KEYLINE="  unlock-KEY.age     the same identity, age-encrypted to your recovery recipient
                     (the KEY path; never publish this file)
"
  [ ! -f "$PKG/BLANK-AT-SEAL.txt" ] || BLANKLINE="  BLANK-AT-SEAL.txt  1Password ids of the items that were blank when sealed
"
  # STRUCTURE.txt (Task S3): listed only when it was written; local only, like the manifest (R44 class)
  [ -n "$STRUCT_ERR" ] || { STRUCTLINE="  STRUCTURE.txt      the vault's shape with every value removed: categories, field
                     types, set/empty, counts and the archive's own ids, bound to
                     vault.tar.gz.age by SHA-256. Never publish this file.
"; LOCALS="$LOCALS, STRUCTURE.txt"; }
  [ ! -f "$PKG/BLANK-AT-SEAL.txt" ] || LOCALS="$LOCALS, BLANK-AT-SEAL.txt"
  [ -z "$RECOVERY" ] || LOCALS="$LOCALS, unlock-KEY.age"
  # --list (lane B): the per-file README (readme_v2); the format /1 one below is unchanged
  if [ "$LIST" = 1 ]; then readme_v2; else
  cat > "$PKG/README.txt" <<EOF
================================================================================
 1PASSWORD VAULT "$VAULT" — SEALED UNTIL $WHEN
================================================================================
Sealed $(date -u +%Y-%m-%dT%H:%M:%SZ) · $DECLARED items · drand round $ROUND
Unlocks $WHEN (UTC), when drand publishes round $ROUND. Requested: $REQ.

  vault.tar.gz.age   the vault (tar.gz), age-encrypted to a one-time X25519 key
  unlock-TIME.age    that key's age identity, tlock-encrypted to drand round $ROUND
${KEYLINE}  SEALED.txt         the self-contained text to publish: both files above as text,
                     the drand parameters and the literal commands that open them
  MANIFEST.csv       item ids + SHA-256 of each item's sealed JSON + field/section/
                     file counts + 1Password's own item id. No values, but the digests
                     are unsalted: anyone holding a candidate item can confirm it.
                     Never publish this file.
${STRUCTLINE}${BLANKLINE}  chain-info.json    drand quicknet's parameters, as pinned at sealing
  round              $ROUND
  README.txt         this file (it names the vault: never publish it)
  local only         $LOCALS: never published
                     SEALED-plaintext.txt: local only, created by open --plaintext after
                     the unlock time (every entry decrypted, in plain text, mode 600);
                     never publish it; delete it and restored/ promptly (Spotlight may
                     index them, and backups may copy them, while they exist)
  ASCII armor        $ARMORED
  drand contacted    $VIA

 1. WHAT KEEPS IT SHUT UNTIL $WHEN -- AND WHAT THAT ASSUMES
    The vault is age-encrypted to a one-time key; that key is encrypted to drand
    round $ROUND (tlock: identity-based encryption on BLS12-381). The decryption key
    for the TIME path is drand quicknet's threshold BLS signature for round $ROUND,
    which the network is designed to publish at $WHEN. It can exist earlier if:
    (a) t or more quicknet key shares are combined -- by colluding operators, or by
    whoever steals or compels them; shares from before a reshare count -- which
    yields the signature at any time, without trace; (b) BLS12-381's pairing
    assumptions fail -- a large quantum computer would break them, and every copy
    kept or published now stays exposed until then; (c) recovery.key is used, if
    unlock-KEY.age exists (section 2). Short of these, fewer than t shares cannot
    produce the signature.

 2. HOW TO OPEN IT — TWO PATHS, either one is enough
    The payload is encrypted once to a fresh age key. That key is sealed twice, so
    recovering it EITHER way opens everything.

    PATH A -- TIME. Works once drand has published round $ROUND (due $WHEN), with no
    key and no secret:
        go install github.com/drand/tlock/cmd/tle@v1.2.0
        sh 1password-timelock.sh open .
        sh 1password-timelock.sh open . --plaintext   (also writes SEALED-plaintext.txt)
      or by hand (through Tor, as at sealing; SEALED.txt has the same steps):
        env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=identity.key unlock-TIME.age
        age -d -i identity.key -o vault.tar.gz vault.tar.gz.age
        mkdir restored && tar -xzf vault.tar.gz -C restored

    PATH B -- KEY. Works at ANY time, including today, if unlock-KEY.age is present:
        sh 1password-timelock.sh open . --identity recovery.key
      or by hand:
        age -d -i recovery.key -o identity.key unlock-KEY.age
        age -d -i identity.key -o vault.tar.gz vault.tar.gz.age

    ★★ WHAT PATH B COSTS, STATED PLAINLY: a recovery key DEFEATS THE TIMELOCK. Anyone
    holding recovery.key can open this today. The timelock then binds only people who do
    NOT hold it. That is the right trade if your worry is "drand disappears and this is
    lost forever"; it is the wrong trade if your worry is "somebody opens this early".
    Sealing without --recovery-recipient produces no unlock-KEY.age and leaves TIME as
    the only way in.

 3. HOW TO VERIFY IT IS COMPLETE, once open (open does this itself; by hand, here,
    after restored/ exists):
        tail -n +2 MANIFEST.csv | while IFS=, read -r id h _; do
          [ "\$(shasum -a 256 "restored/items/\$id.json" 2>/dev/null | cut -d' ' -f1)" = "\$h" ] \\
            || echo "MISSING OR MISMATCH \$id"
        done
    It must print nothing, and MANIFEST.csv must have $DECLARED rows. Attachments: each
    row of restored/ATTACHMENTS.csv (item,file,bytes,sha256) must match the file
    restored/files/<item>/<file>; SEALED.txt's last step checks both with shasum -c.
    The ids inside the archive are this seal's pseudonyms; MANIFEST.csv's last column
    (op_item_id, here only) maps each one to 1Password's own item id.

 4. IF THE TOOLING IS GONE
    SEALED.txt, beside this file, is self-contained: it carries both .age files as
    text and the literal commands to open them. unlock-TIME.age is a standard age
    file with one tlock stanza; its plaintext is the age identity (AGE-SECRET-KEY-1...)
    that opens vault.tar.gz.age, an age file with one X25519 stanza. For
    unlock-TIME.age you need the drand signature for round $ROUND on chain $CHAIN:
        curl --noproxy '' --proxy socks5h://127.0.0.1:9050 https://api.drand.sh/$CHAIN/public/$ROUND
    (through Tor, as at sealing). Scheme: bls-unchained-g1-rfc9380. Public key:
    chain-info.json, beside this file. Mirrors: api2.drand.sh, api3.drand.sh.

 5. IF DRAND IS GONE
    Then this is not openable, and that was the risk accepted. A timelock stops early
    opening (under the assumptions in section 1); it does not stop PERMANENT loss. Store
    a Shamir split with trustees as a second, human path -- the two fail in opposite
    directions.

 6. WHAT THE CAPTURE DID AND DID NOT GUARANTEE
    Items were read with \`op item get --reveal\`, because op CONCEALS sensitive fields
    by default and an export without it restores nothing. Archived items were included.
    Every attachment was fetched (op read / op document get), checked against the size
    the item reports, and is in the archive with its digest (ATTACHMENTS.csv).
    Inside the seal, each item keeps every value, title, label, URL, tag and file, but
    not the account metadata around it (vault id and name, who last edited it and
    when, versions, content paths, op:// references) unless --keep-item-metadata was
    given, and 1Password's ids are replaced by this seal's pseudonyms unless
    --keep-item-ids was given. The archive's own metadata is neutral (owner nobody, a
    fixed time), and the time-locked key is one line, with no creation time.
    NOT captured: vault-level settings, sharing/ACLs, item history (prior versions), and
    anything a Business policy blocked from export.
================================================================================
EOF
  fi

  PKG_PARTIAL=""   # complete: from here on a failure must not remove it
  obliterate "$WORK"; trap - EXIT HUP INT TERM
  # STRUCTURE.txt (Task S3): said first, so a SEALED.txt failure below cannot hide it
  [ -z "$STRUCT_ERR" ] || printf '%s\n' "★ STRUCTURE.txt could not be written: $STRUCT_ERR" \
    "  The package is complete, verified and kept at $PKG/; only its local STRUCTURE.txt is missing. STRUCTURE.txt is built only from the plaintext at seal time, which is now removed: to have one, fix the cause above and seal the vault again." >&2
  write_sealed_txt   # ★ the last step: no SEALED.txt, no success (Task S2 §5)
  [ -z "$STRUCT_ERR" ] || die "★ this seal has NOT finished: STRUCTURE.txt was not written (see above). The package is kept at $PKG/."
  echo "  package    $PKG/"
  if [ "$LIST" = 1 ]; then echo "  size       $(cat "$PKG/index" "$PKG"/b[0-9]* | wc -c | tr -d ' ') bytes in $(( NB + 1 )) age files (the index and $NB blocks; SEALED.txt format /2, padding: $V2_PADDING)"
  else echo "  size       $(wc -c < "$PKG/vault.tar.gz.age" | tr -d ' ') bytes"; fi
  echo "  opens      $WHEN  (drand round $ROUND; requested: $REQ)"
  echo "  verified   does NOT open now (local round check; the drand relay answered HTTP 425 for round $ROUND$( [ "$CLEARNET" = 1 ] && echo ', directly (--clearnet)' || echo ' through Tor' ))"
  [ -z "$ARMOR_FLAG" ] || echo "  armor      every .age is ASCII-armored (PEM); marker file ARMOR"
  [ "$CLEARNET" = 0 ] || echo "  ★ CLEARNET drand saw this IP ask for round $ROUND: re-seal over Tor before publishing (R40)"
  echo "  plaintext  unlinked from $WORK (an unlink, not a wipe: FileVault guards the stale blocks)"
}

# ── open ─────────────────────────────────────────────────────────────────────────────────────
# Two paths, and they are ORs. Either recovers the data key; the data key opens the payload.
# Every .age may be binary or ASCII-armored (--armor): age -d and tle --decrypt both detect armor by
# content, so the same commands open either form (the self-test opens one package of each).
cmd_open() {
  case ${1:-} in -*) die "open <package-dir> [options]: '$1' is an option, not a package: the package comes first" ;; esac   # @mut:pt-dash-open
  DIR=${1:?usage: open <package-dir> [--identity recovery.key] [--clearnet] [--plaintext [--force]]}
  shift
  IDENT=""; PLAINTEXT=0; PT_FORCE=0; PT_TMP=; PT_ITEMS=0; STRUCT_STATE=unchecked; ARCH=vault.tar.gz.age
  while [ $# -gt 0 ]; do
    case "$1" in
      --identity) IDENT=${2:?--identity needs a path to your age secret key}; shift 2 ;;
      --clearnet) CLEARNET=1; shift ;;   # the TIME path's drand request goes direct (R40 opt-out)
      --plaintext) PLAINTEXT=1; shift ;;   # Task SP: SEALED-plaintext.txt after a verified open
      --force) PT_FORCE=1; shift ;;
      *) die "unexpected argument: $1" ;;
    esac
  done
  [ "$PT_FORCE" = 0 ] || [ "$PLAINTEXT" = 1 ] || die "--force goes with --plaintext only (it lets an existing SEALED-plaintext.txt be replaced)"
  command -v age >/dev/null 2>&1 || die "age is not installed — brew install age"
  command -v shasum >/dev/null 2>&1 || die "shasum is missing: open verifies every digest with it"
  # a bare package name resolves against $OUT; an existing path always wins
  [ -d "$DIR" ] || [ ! -d "$OUT/$DIR" ] || DIR="$OUT/$DIR"
  # a seal --list package (lane B): its layout file says per-file; its index and blocks replace vault.tar.gz.age
  if [ -e "$DIR/layout" ] || [ -L "$DIR/layout" ]; then v2_layout "$DIR"; ARCH=index; fi
  [ "$ARCH" = index ] || [ -f "$DIR/vault.tar.gz.age" ] || die "no vault.tar.gz.age in $DIR"

  _tmpd=${TMPDIR:-/tmp}   # an explicit template: a bare `mktemp -d` ignores $TMPDIR on macOS
  WORK=$(mktemp -d "${_tmpd%/}/1password-timelock.XXXXXXXX") || die "mktemp failed"; chmod 700 "$WORK"
  # (PT_TMP: SEALED-plaintext.txt's temp file in the package dir, once it exists; it holds plaintext)
  trap 'obliterate "$WORK" "$PT_TMP"' EXIT; trap 'obliterate "$WORK" "$PT_TMP"; exit 130' HUP INT TERM   # @mut:pt-trap
  # --plaintext (Task SP): everything that can refuse it before a byte is decrypted
  [ "$PLAINTEXT" = 0 ] || plaintext_precheck "$DIR"

  if [ -n "$IDENT" ]; then
    # ── PATH B: the recovery key. Works at ANY time, including before the round.
    [ -f "$DIR/unlock-KEY.age" ] || die "this package has no unlock-KEY.age — it was sealed
   without --recovery-recipient, so the TIME path is the only way in."
    age -d -i "$IDENT" -o "$WORK/identity.key" "$DIR/unlock-KEY.age" \
      || die "the recovery key did not open unlock-KEY.age"
    echo "  path       KEY (recovery identity)"
  else
    # ── PATH A: time. Refuses until the round is published, and says how long is left.
    # drand (the round's signature) through Tor only, like every other drand request (R40)
    command -v "$TLE" >/dev/null 2>&1 || die "tle is not installed — go install github.com/drand/tlock/cmd/tle@v1.2.0"
    # checked HERE, loudly: inside the call below a refusal would only reach $WORK/err (Task S1 review)
    [ -f "$DIR/unlock-TIME.age" ] || die "no unlock-TIME.age (a regular file) in $DIR: the TIME path has nothing to open"   # @mut:time-file
    tor_preflight
    if ! tle_net --decrypt --output="$WORK/identity.key" "$DIR/unlock-TIME.age" 2>"$WORK/err"; then
      R=$(round_of "$DIR")
      case $R in *[!0-9]*) UNTIL="the date in README.txt" ;; *) UNTIL="$(round_iso "$R") (UTC)" ;; esac
      printf '  %s\n' "$(cat "$WORK/err")" >&2
      # only tle's own "too early" means LOCKED; anything else (network, a damaged file) is not
      grep -q 'too early' "$WORK/err" || die "could not open unlock-TIME.age (the error is above)"
      # ...and tle says "too early" for ANY failure to fetch the signature (a 5 s timeout over Tor):
      # after the round, by the pinned parameters and the clock, it is a fetch failure (F-17)
      case $R in *[!0-9]*) ;; *) [ "$R" -gt $(( ($(date -u +%s) - GENESIS) / PERIOD + 1 )) ] || die "★ drand did not return round $R's signature (network or Tor; tle reports this as \"too early\"). The round passed at $UNTIL: retry." ;; esac   # @mut:open-passed
      die "★ not yet — locked until $UNTIL, drand round $R. Re-run after that,
   or use --identity <recovery.key> if this package was sealed with a recovery recipient."
    fi
    echo "  path       TIME (drand round $(round_of "$DIR"))"
  fi

  # (lane B) a per-file package: the index, then every block, into a NEW restored/ (open_v2); a v1 one: the archive
  if [ "$ARCH" = index ]; then open_v2 "$DIR"; else
  age -d -i "$WORK/identity.key" -o "$WORK/vault.tar.gz" "$DIR/vault.tar.gz.age" \
    || die "the data key did not open the payload — the package is inconsistent"
  # ★ The plaintext goes only into a NEW directory this run creates (commit security review of
  #   827e4ed): mkdir WITHOUT -p fails on ANY existing path called restored (a directory, a file, a
  #   symlink planted to redirect the write, dangling or not); and the archive is listed first,
  #   regular files and directories only (tar_entries_ok).
  tar_entries_ok "$WORK/vault.tar.gz"   # the listing wall first, before restored/ exists
  mkdir -m 700 "$DIR/restored" || die "★ $DIR/restored already exists (a directory, a file or a symlink): move it away first. open writes plaintext only into a NEW restored/ it creates itself."   # @mut:restored-fresh
  extract_verified "$WORK/vault.tar.gz" "$DIR/restored"
  fi

  # ★ VERIFY ON THE WAY OUT. An archive that extracts is not an archive that is COMPLETE, and
  #   ten years is long enough for bit-rot, a truncated copy, or a partial download.
  #   The manifest BESIDE the package if there is one; otherwise the copy that was sealed INSIDE
  #   the archive (a fetched bundle carries no MANIFEST.csv: it is never published, R44). Either
  #   way the output names the one that was used.
  if [ -f "$DIR/MANIFEST.csv" ]; then MF="$DIR/MANIFEST.csv"; MFW="MANIFEST.csv beside the package"
  elif [ -f "$DIR/restored/MANIFEST.csv" ]; then MF="$DIR/restored/MANIFEST.csv"; MFW="restored/MANIFEST.csv, the copy sealed inside the archive (none beside the package)"   # @mut:manifest-inside
  else MF=""; fi
  if [ -n "$MF" ]; then
    echo "  manifest   $MFW"
    bad=0; rows=0; : > "$WORK/fcounts"
    while IFS=, read -r id sha _fc _sc _lc _real; do
      [ "$id" = "item_id" ] && continue
      # an id becomes a PATH and is printed: only 1Password's own charset, else refuse (the manifest
      # may be the copy from inside a fetched archive: untrusted text; Task S1 review)
      case $id in ''|*[!a-z0-9]*) die "★ $MFW has a row whose item id is not [a-z0-9]+: refusing to use it as a path or print it" ;; esac   # @mut:manifest-id
      rows=$((rows+1))
      case $_lc in ''|*[!0-9]*) die "★ $MFW has a row whose file_count is not a number: refusing" ;; esac
      is_sha256 "$sha" || die "★ $MFW row $id: the digest is not 64 hex characters: refusing (it would verify nothing)"   # @mut:open-digest
      echo "$id $_lc" >> "$WORK/fcounts"
      f="$DIR/restored/items/$id.json"
      if [ ! -f "$f" ]; then echo "  MISSING $id"; bad=$((bad+1)); continue; fi
      h=$(sha256_of "$f") || exit 1
      [ "$h" = "$sha" ] || { echo "  DIGEST MISMATCH $id"; bad=$((bad+1)); }
    done < "$MF"
    if [ "$bad" -eq 0 ]; then
      [ "$rows" = 0 ] || PT_ITEMS=1   # (Task SP: every item verified against a manifest)
      echo "  verified   $rows/$rows items match their manifest digest"
    else
      die "★ $bad of $rows items failed verification — the archive is NOT intact."
    fi
  else
    echo "  ⚠ no MANIFEST.csv beside the package or inside the archive — extracted, but completeness is UNVERIFIED"
  fi
  # attachments: ATTACHMENTS.csv exists only INSIDE the archive (packages from before Task S2 have
  # none). Its ids become paths: [a-z0-9]+ only, as for the manifest (untrusted text).
  [ -f "$WORK/fcounts" ] || : > "$WORK/fcounts"
  # ★ Cross-checked against the manifest's file_count (S2 review): a manifest that lists attachments
  #   with no ATTACHMENTS.csv, or an item whose rows there differ from its file_count, is NOT
  #   verified, and open does not report success (restored/ keeps what the archive held).
  _fl=0; [ ! -s "$WORK/fcounts" ] || _fl=$(awk '{ n += $2 } END { print n + 0 }' "$WORK/fcounts")
  [ -f "$DIR/restored/ATTACHMENTS.csv" ] || [ "$_fl" = 0 ] || die "★ the manifest lists $_fl attachment(s), but the archive holds no ATTACHMENTS.csv: the attachments are UNVERIFIED (a package sealed before Task S2 never checked them, or the archive lost the list). restored/ holds what the archive had."   # @mut:open-att-missing
  if [ -f "$DIR/restored/ATTACHMENTS.csv" ]; then
    while read -r id lc; do
      [ "$(grep -c "^$id," "$DIR/restored/ATTACHMENTS.csv" || true)" = "$lc" ] || die "★ item $id: the manifest lists $lc attachment(s), ATTACHMENTS.csv holds $(grep -c "^$id," "$DIR/restored/ATTACHMENTS.csv" || true): the archive is NOT intact."   # @mut:open-att-count
    done < "$WORK/fcounts"
    abad=0; arows=0
    while IFS=, read -r id fid _b sha; do
      [ "$id" = "item_id" ] && continue
      case "$id/$fid" in */|/*|*[!a-z0-9/]*|*/*/*) die "★ restored/ATTACHMENTS.csv has a row whose ids are not [a-z0-9]+: refusing to use it as a path or print it" ;; esac   # @mut:att-id
      arows=$((arows+1))
      is_sha256 "$sha" || die "★ restored/ATTACHMENTS.csv row $id/$fid: the digest is not 64 hex characters: refusing (it would verify nothing)"
      h=; [ ! -f "$DIR/restored/files/$id/$fid" ] || { h=$(sha256_of "$DIR/restored/files/$id/$fid") || exit 1; }
      [ "$h" = "$sha" ] || { echo "  ATTACHMENT MISSING OR MISMATCH $id/$fid"; abad=$((abad+1)); }
    done < "$DIR/restored/ATTACHMENTS.csv"
    [ "$abad" -eq 0 ] || die "★ $abad of $arows attachment(s) failed verification — the archive is NOT intact."
    echo "  verified   $arows/$arows attachments match ATTACHMENTS.csv"
  fi
  # STRUCTURE.txt (Task S3): rebuilt from restored/ and compared; a warning at most, never a refusal
  structure_check "$DIR"
  echo "  restored   $DIR/restored/"
  # SEALED-plaintext.txt (Task SP): only now, after the full open above, and only if it was VERIFIED
  if [ "$PLAINTEXT" = 1 ]; then
    plaintext_gate "$DIR"   # @mut:pt-verified
    plaintext_write "$DIR"
  fi
  obliterate "$WORK"; trap - EXIT HUP INT TERM
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
  # a fast tmutil (Task SP review m7): `tmutil addexclusion` takes ~1 s on a file and ~11 s on a directory
  # (measured 2026-10-09, macOS 26.2), so the offline --plaintext arms use this one; arm_plaintext_mode and the
  # real TIME-path opens use the real tmutil and check the exclusion
  printf '#!/bin/sh\ncase $1 in addexclusion) exit 0 ;; esac\nexec /usr/bin/tmutil "$@"\n' > "$T/fakebin/tmutil"
  chmod +x "$T/fakebin/curl" "$T/fakebin/tle" "$T/fakebin/tmutil"
  mkdir -p "$T/realtm" && ln -sf /usr/bin/tmutil "$T/realtm/tmutil"
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
# ── the 1password-specific arms ─────────────────────────────────────────────────────────────
arm_binary_pkg() {
  for f in vault.tar.gz.age unlock-TIME.age unlock-KEY.age; do
    is_binary_age "$1/$f" || { echo "    $f does not start with age-encryption.org/v1"; return 1; }
  done
  [ ! -e "$1/ARMOR" ] || { echo "    an ARMOR marker in a binary package"; return 1; }
}
arm_armored_pkg() {
  for f in vault.tar.gz.age unlock-TIME.age unlock-KEY.age; do
    is_armored "$1/$f" || { echo "    $f is not canonical age ASCII armor:"; head -c 200 "$1/$f" | head -3 | sed 's/^/      /'; return 1; }
  done
  [ "$(cat "$1/ARMOR" 2>/dev/null)" = pem ] || { echo "    no ARMOR marker saying pem"; return 1; }
}
# offline [VAR=value...] COMMAND...: run COMMAND (usually `sh SCRIPT seal|open ...`) from $T with the
# fake op, tle and curl first on PATH, packages under $FO (a fresh dir per arm), the fake call log
# in $FL, a 600 s horizon unless the arm overrides it. Output: $T/out.log. Returns COMMAND's status.
offline() {
  rm -f "$FL"; mkdir -p "$FO" "$T/tmp"
  ( cd "$T" && env VAULT_TIMELOCK_DIR="$FO" OP="$T/op" TLE=tle PATH="$T/fakebin:$PATH" FAKE_LOG="$FL" \
      TMPDIR="$T/tmp" TL_TEST_SECONDS=600 "$@" ) > "$T/out.log" 2>&1
}
arm_dir() { FO="$T/o-$1"; FL="$T/calls-$1"; rm -rf "$FO" "$FL"; }
pkg_in() { ls -d "$FO"/1password-"$1"-timelock-* 2>/dev/null | head -1; }
show() { sed 's/^/      /' "$@"; }

# --armor reaches EVERY .age writer (Task S1 §2)
arm_armor() {
  arm_dir armor
  offline sh "$1" seal Arm 10 --armor --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  arm_armored_pkg "$(pkg_in Arm)"
}
# every drand-bound call, curl and tle, seal and open, goes to the Tor proxy as R40 requires, even
# with NO_PROXY=* and a decoy HTTPS_PROXY in the environment (Task S1 §6)
arm_routes() {
  arm_dir routes
  offline NO_PROXY='*' no_proxy='*' HTTPS_PROXY=http://decoy.invalid:1 https_proxy=http://decoy.invalid:1 \
    sh "$1" seal Routes 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  cp "$FL" "$FL.seal"
  if offline NO_PROXY='*' no_proxy='*' HTTPS_PROXY=http://decoy.invalid:1 https_proxy=http://decoy.invalid:1 \
       sh "$1" open "$(pkg_in Routes)"; then echo "    the fake TIME path opened"; return 1; fi
  grep -q 'locked until' "$T/out.log" || { echo "    open did not report locked:"; show "$T/out.log"; return 1; }
  cat "$FL.seal" "$FL" > "$FL.all"
  [ "$(grep -c '^curl ' "$FL.all")" -ge 2 ] && [ "$(grep -c '^tle encrypt ' "$FL.all")" -ge 1 ] \
    && [ "$(grep -c '^tle decrypt ' "$FL.all")" -ge 2 ] \
    || { echo "    expected curl (info, status), tle encrypt (seal) and tle decrypt (seal, open) calls:"; show "$FL.all"; return 1; }
  # tle ENCRYPTS with the pinned info served on loopback (no drand request); everything else is Tor
  if grep '^tle encrypt ' "$FL.all" | grep -qv ' LOOPBACK$'; then echo "    an encrypt did NOT use the pinned loopback chain info:"; grep '^tle encrypt ' "$FL.all" | show; return 1; fi
  if grep -v ' TOR$' "$FL.all" | grep -v '^tle encrypt LOOPBACK$' | grep -q .; then echo "    a call did NOT go through Tor:"; grep -v ' TOR$' "$FL.all" | show; return 1; fi
}
# --clearnet is the one bypass, and it says so: banner, README, and every call direct
arm_clearnet() {
  arm_dir clear
  offline sh "$1" seal Clear 10 --clearnet || { echo "    the offline --clearnet seal failed:"; show "$T/out.log"; return 1; }
  grep -q -- '--clearnet: drand is contacted DIRECTLY' "$T/out.log" && grep -q 'CLEARNET.*re-seal over Tor' "$T/out.log" \
    && grep -q 'drand contacted    CLEARNET' "$(pkg_in Clear)/README.txt" \
    || { echo "    the banner or README does not name --clearnet"; show "$T/out.log"; return 1; }
  # (DIRECT whatever the caller's own proxy variables say: --clearnet leaves them as they are)
  [ "$(grep -c ' DIRECT' "$FL")" -ge 3 ] && ! grep -q ' TOR$' "$FL" || { echo "    calls:"; show "$FL"; return 1; }
}
# Tor down (its SOCKS port unreachable) -> refused before any drand call and before any export
arm_tor_down() {
  arm_dir down
  if offline sandbox-exec -p "$NO_TOR" sh "$1" seal Down 10; then echo "    SEALED with Tor unreachable"; return 1; fi
  grep -q 'Tor is not answering on 127.0.0.1:9050' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -s "$FL" ] || { echo "    a drand call ran before the refusal:"; show "$FL"; return 1; }
  ! grep -q 'declared' "$T/out.log" || { echo "    the vault was read before the refusal"; return 1; }
}
# quicknet pinned: one wrong parameter from a mirror -> refused, for each parameter
arm_pin() {
  for w in scheme hash genesis period key; do   # scheme first: tle itself would accept it
    arm_dir "pin-$w"
    if offline FAKE_DRAND_INFO=$w sh "$1" seal Pin 10; then echo "    a wrong $w was SEALED"; return 1; fi
    grep -q 'does not match pinned quicknet' "$T/out.log" || { echo "    wrong $w refused for another reason:"; show "$T/out.log"; return 1; }
  done
}
# the LOCAL negative control: a horizon inside the margin is refused, with no drand decrypt asked
arm_local_control() {
  arm_dir local
  if offline TL_TEST_SECONDS=6 sh "$1" seal Soon 10; then echo "    a 6-second horizon was SEALED"; return 1; fi
  grep -q 'is not safely in the future' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in Soon)" ] || { echo "    a partial package was left behind"; return 1; }
}
# drand's control: if the TIME file OPENS now -> refused, and the package does not survive
arm_drand_control() {
  arm_dir open-now
  if offline FAKE_TLE_DECRYPT=open sh "$1" seal Opens 10; then echo "    a package that OPENS NOW was shipped"; return 1; fi
  grep -q 'OPENS RIGHT NOW' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in Opens)" ] || { echo "    the refused package was left behind"; return 1; }
}
# ...and any answer other than "too early" fails closed (shut must be SHOWN, not inferred)
arm_drand_reason() {
  arm_dir neterr
  if offline FAKE_TLE_DECRYPT=neterr sh "$1" seal Neterr 10; then echo "    SEALED although drand never said 'too early'"; return 1; fi
  grep -q 'could not confirm through drand' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in Neterr)" ] || { echo "    the refused package was left behind"; return 1; }
}
# ...and the relay must answer HTTP 425 for the round: 200 (it has the signature), 500, or no
# answer at all (000) refuses, saying which (Task S2 §3)
arm_drand_425() {
  for c in 200 500 000; do
    arm_dir "s425-$c"
    if offline FAKE_DRAND_PUBLIC=$c sh "$1" seal S425 10; then echo "    SEALED although drand answered HTTP $c, not 425"; return 1; fi
    grep -q "did not answer HTTP 425 (Too Early) for round [0-9]* through Tor: HTTP $c" "$T/out.log" || { echo "    HTTP $c refused for another reason:"; show "$T/out.log"; return 1; }
    [ -z "$(pkg_in S425)" ] || { echo "    the refused package was left behind"; return 1; }
  done
}
# an UNRELATED key must be told "no identity matched": decrypting with it (sigbin/age's hook) or an
# answer that is not "no identity matched" (not an age file to a recipient) refuses (Task S2 §3)
arm_no_identity() {
  for m in open header; do
    arm_dir "unrel-$m"
    if offline PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_AGE_UNRELATED=$m sh "$1" seal Unrel 10; then echo "    SEALED although an unrelated key got: $m"; return 1; fi
    if [ "$m" = open ]; then w='decrypted with an UNRELATED identity'; else w='is not an age file encrypted to a recipient'; fi
    grep -q "$w" "$T/out.log" || { echo "    $m refused for another reason:"; show "$T/out.log"; return 1; }
    [ -z "$(pkg_in Unrel)" ] || { echo "    the refused package was left behind"; return 1; }
  done
}
# after the round, tle's "too early" is a fetch failure, not a lock: open says so (F-17)
arm_open_passed() {
  arm_dir passed
  offline sh "$1" seal Passed 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  echo 1000 > "$(pkg_in Passed)/round"
  if offline sh "$1" open "$(pkg_in Passed)"; then echo "    the fake TIME path opened"; return 1; fi
  grep -q "drand did not return round 1000's signature (network or Tor" "$T/out.log" && grep -q 'The round passed at 2023-08-23T15:59:24Z (UTC): retry' "$T/out.log" \
    || { echo "    a passed round was reported as locked:"; show "$T/out.log"; return 1; }
}
# ★ what the E4 pin relies on, measured on the REAL tle (no drand: loopback only, under LOOP_ONLY):
#   tle checks the chain hash of the info it fetches (a wrong period is refused), but the hash does
#   not bind the scheme (a hash-valid info saying bls-unchained-on-g1 is accepted). So the seal
#   serves tle the PINNED info, and the pin's own check (chain_info) refuses a wrong scheme.
arm_tle_pinning() {
  rm -rf "$T/ch"; mkdir "$T/ch"; echo synthetic > "$T/ch/in"
  _r=$(( ( $(date -u +%s) + 3600 - GENESIS ) / PERIOD + 1 ))
  for w in good period scheme; do
    FAKE_DRAND_INFO=$w "$T/fakebin/curl" "https://api.drand.sh/$CHAIN/info" > "$T/ch/chain-info.json"
    info_serve "$T/ch"
    st=0; sandbox-exec -p "$LOOP_ONLY" "$TLE" --encrypt --network="http://127.0.0.1:$INFO_PORT" --chain="$CHAIN" --round="$_r" --output="$T/ch/out-$w" "$T/ch/in" > "$T/ch/log-$w" 2>&1 || st=$?
    info_stop
    case $w in
      good) [ "$st" = 0 ] || { echo "    tle did not encrypt with the pinned quicknet info:"; show "$T/ch/log-$w"; return 1; } ;;
      period) [ "$st" != 0 ] && grep -q 'does not advertise the expected drand group' "$T/ch/log-$w" || { echo "    tle did not refuse a hash-invalid info:"; show "$T/ch/log-$w"; return 1; } ;;
      scheme) [ "$st" = 0 ] || { echo "    tle refused a hash-valid info with another scheme (re-check E4):"; show "$T/ch/log-$w"; return 1; } ;;
    esac
  done
}
# a network error (a slow Tor circuit) is retried, and then drand's answer counts
arm_retry() {
  arm_dir retry; rm -f "$T/flaky"
  offline FAKE_TLE_FLAKY="$T/flaky" sh "$1" seal Retry 10 || { echo "    a flaky first answer was not retried:"; show "$T/out.log"; return 1; }
  [ "$(grep -c '^tle decrypt ' "$FL")" -ge 2 ] || { echo "    no retry seen:"; show "$FL"; return 1; }
}
# ★ an interrupt during the round-trip (the revealed vault extracted in $WORK/rt) leaves NOTHING
#   under TMPDIR, exits 130 and leaves no half package (audit K20). SIGNAL: TERM or INT. Under
#   no_tmp_writes: a work dir anywhere but the TMPDIR given fails the seal.
arm_interrupt() {
  arm_dir "sig-${2:-TERM}"; E="$T/tmp-sig"; rm -rf "$E"; mkdir "$E"
  st=0; offline TMPDIR="$E" PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_AGE_SIGNAL="${2:-TERM}" \
    sandbox-exec -p "$(no_tmp_writes "$E")" sh "$1" seal Sig 10 || st=$?
  # (run the suite in the foreground: a background job starts with SIGINT ignored, which no shell
  # can trap, so the INT arm then fails here)
  [ "$st" = 130 ] || { echo "    exit status $st after SIG${2:-TERM}, not 130:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$E")" ] || { echo "    left under TMPDIR after SIG${2:-TERM}:"; ls -A "$E" | show; return 1; }
  [ -z "$(pkg_in Sig)" ] || { echo "    a half package was left behind"; return 1; }
  ! grep -q 'unsealed' "$T/out.log" || { echo "    the seal ran on past the signal"; return 1; }
}
arm_interrupt_int() { arm_interrupt "$1" INT; }
arm_interrupt_hup() { arm_interrupt "$1" HUP; }
# ...and so does a FAILURE there (the EXIT trap): the round-trip decrypt fails
arm_rt_failure() {
  arm_dir rtfail; E="$T/tmp-rtf"; rm -rf "$E"; mkdir "$E"
  if offline TMPDIR="$E" PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_AGE_FAIL_RT=1 \
       sandbox-exec -p "$(no_tmp_writes "$E")" sh "$1" seal Rtf 10
  then echo "    a failing round-trip was SEALED"; return 1; fi
  grep -q 'did NOT open with its own data key' "$T/out.log" || { echo "    failed for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$E")" ] || { echo "    left under TMPDIR after a failure:"; ls -A "$E" | show; return 1; }
  [ -z "$(pkg_in Rtf)" ] || { echo "    a half package was left behind"; return 1; }
}
# the package dir is 0700 whatever the umask (SA-N10)
arm_pkg_mode() {
  arm_dir mode
  ( umask 022 && offline sh "$1" seal Mode 10 ) || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  m=$(stat -f %Lp "$(pkg_in Mode)" 2>/dev/null || stat -c %a "$(pkg_in Mode)")
  [ "$m" = 700 ] || { echo "    package dir mode $m under umask 022, not 700"; return 1; }
}
# open with no MANIFEST.csv beside the package (a fetched bundle, R44) verifies against the copy
# sealed inside the archive, and says which manifest it used
arm_manifest_inside() {
  arm_dir mf
  offline sh "$1" seal Mf 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Mf); mv "$P/MANIFEST.csv" "$T/mf.aside"
  offline sh "$1" open "$P" --identity "$T/recovery.key" || { echo "    open failed:"; show "$T/out.log"; return 1; }
  grep -q 'manifest   restored/MANIFEST.csv, the copy sealed inside' "$T/out.log" && grep -q '3/3 items match' "$T/out.log" \
    || { echo "    not verified against the sealed manifest:"; show "$T/out.log"; return 1; }
}

# ── open never follows a planted symlink (commit security review of 827e4ed) ─────────────────
# a planted `restored` symlink (to a directory, and dangling) makes open REFUSE: plaintext goes only
# into a restored/ it creates itself; the directory it points at is byte-for-byte unchanged
arm_restored_symlink() {
  arm_dir plant
  offline sh "$1" seal Plant 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Plant)
  rm -rf "$T/canarydir"; mkdir "$T/canarydir"; echo canary > "$T/canarydir/canary"
  ln -s "$T/canarydir" "$P/restored"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then
    [ "$(ls -A "$T/canarydir")" = canary ] || { echo "    a planted restored symlink redirected the extraction: the directory it points at CHANGED"; return 1; }
    echo "    open did not refuse a planted restored symlink"; return 1
  fi
  [ "$(ls -A "$T/canarydir")" = canary ] && [ "$(cat "$T/canarydir/canary")" = canary ] \
    || { echo "    a planted restored symlink redirected the extraction: the directory it points at CHANGED"; return 1; }
  grep -q 'restored already exists' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  rm "$P/restored"; ln -s "$T/nowhere" "$P/restored"   # dangling
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    open followed a dangling restored symlink"; return 1; fi
  [ ! -e "$T/nowhere" ] || { echo "    the dangling symlink's target was created"; return 1; }
}
# a hand-made package whose vault archive is the tarball $2 (KEY path: real age, no drand)
craft_vault() {
  P="$FO/1password-Craft-timelock-x"; mkdir -p "$P"
  age-keygen -o "$T/craft.key" 2>/dev/null
  age -r "$(age-keygen -y "$T/craft.key")" -o "$P/vault.tar.gz.age" "$2"
  age -r "$RECIP" -o "$P/unlock-KEY.age" "$T/craft.key"; rm -f "$T/craft.key"
}
craft_tars() {
  rm -rf "$T/craft"; mkdir -p "$T/craft/l" "$T/craft/s/t" "$T/craft/h"
  ln -s "$T/canarydir" "$T/craft/l/link"; tar -czf "$T/link.tgz" -C "$T/craft/l" .
  echo dotdot > "$T/craft/s/x"; ( cd "$T/craft/s/t" && tar -czf "$T/dotdot.tgz" -P ../x )
  echo hard > "$T/craft/h/a"; ln "$T/craft/h/a" "$T/craft/h/b"; tar -czf "$T/hard.tgz" -C "$T/craft/h" .
  echo abs > "$T/abs-target"; tar -czf "$T/abs.tgz" -P "$T/abs-target" 2>/dev/null   # an ABSOLUTE entry
}
# a vault archive with a symlink entry is refused with the reason, and nothing is extracted
arm_vault_tar_type() {
  arm_dir craft-type; mkdir -p "$FO"; rm -rf "$T/canarydir"; mkdir "$T/canarydir"; craft_tars; craft_vault "$1" "$T/link.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an archive with a symlink entry was EXTRACTED"; return 1; fi
  grep -q 'refusing to extract vault.tar.gz: an entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }   # the LISTING wall
  [ -z "$(find "$P" -type l)" ] || { echo "    a symlink was extracted"; return 1; }
}
# a vault archive with a "../x" entry is refused with the reason, and nothing lands outside
arm_vault_tar_path() {
  arm_dir craft-path; mkdir -p "$FO"; craft_tars; craft_vault "$1" "$T/dotdot.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an archive with a ../x entry was EXTRACTED"; return 1; fi
  grep -q "an absolute path or a '..' component" "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$P/x" ] || { echo "    ../x was written"; return 1; }
}
# a data dir ($OUT) that is a symlink is refused, and nothing is written through it
arm_out_symlink() {
  arm_dir outlink; rm -rf "$T/outtarget" "$T/outlink"; mkdir "$T/outtarget"; ln -s "$T/outtarget" "$T/outlink"
  if offline VAULT_TIMELOCK_DIR="$T/outlink" sh "$1" seal Outlink 10; then echo "    SEALED through a symlinked data dir"; return 1; fi
  grep -q 'is a symlink: refusing to write packages through it' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$T/outtarget")" ] || { echo "    something was written through the symlink"; return 1; }
}

# ── fix round 1 (Task S1 review): untrusted package text, a missing TIME file ───────────────
# a round file that is not a round number is never printed raw by open
arm_round_text() {
  arm_dir roundtext
  offline sh "$1" seal Rt 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  printf '12x; echo PWNED\n' > "$(pkg_in Rt)/round"
  if offline sh "$1" open "$(pkg_in Rt)"; then echo "    the fake TIME path opened"; return 1; fi
  ! grep -q PWNED "$T/out.log" || { echo "    the round file was printed raw:"; show "$T/out.log"; return 1; }
  grep -q 'drand round (invalid round file)' "$T/out.log" || { echo "    no '(invalid round file)':"; show "$T/out.log"; return 1; }
}
# a manifest row whose item id is not [a-z0-9]+ is refused before it becomes a path or is printed
arm_manifest_id() {
  arm_dir mfid
  offline sh "$1" seal Mfid 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  echo '../../evil,0000000000000000000000000000000000000000000000000000000000000000,1,0,0' >> "$(pkg_in Mfid)/MANIFEST.csv"
  if offline sh "$1" open "$(pkg_in Mfid)" --identity "$T/recovery.key"; then echo "    a manifest with a '../../evil' id was used"; return 1; fi
  grep -q 'item id is not \[a-z0-9\]+' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q 'evil' "$T/out.log" || { echo "    the bad id was printed"; return 1; }
}
# the TIME path with no unlock-TIME.age says so (it used to exit 1 silently)
arm_time_file() {
  arm_dir timefile
  offline sh "$1" seal Tf 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  rm "$(pkg_in Tf)/unlock-TIME.age"
  if offline sh "$1" open "$(pkg_in Tf)"; then echo "    opened without unlock-TIME.age"; return 1; fi
  grep -q 'no unlock-TIME.age (a regular file)' "$T/out.log" || { echo "    refused without saying why:"; show "$T/out.log"; return 1; }
}
# a vault archive with a HARDLINK entry, or an ABSOLUTE path, is refused with the reason
arm_vault_tar_hard() {
  arm_dir craft-hard; mkdir -p "$FO"; craft_tars; craft_vault "$1" "$T/hard.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an archive with a hardlink entry was EXTRACTED"; return 1; fi
  grep -q 'not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
arm_vault_tar_abs() {
  arm_dir craft-abs; mkdir -p "$FO"; craft_tars; cp "$T/abs-target" "$T/abs-target.orig"; craft_vault "$1" "$T/abs.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an archive with an absolute entry was EXTRACTED"; return 1; fi
  grep -q "an absolute path or a '..' component" "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  cmp -s "$T/abs-target" "$T/abs-target.orig" || { echo "    the absolute target changed"; return 1; }
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
# the "._y" symlink merge: open refuses on the on-disk check, restored/ is removed, the canary is
# untouched (--no-mac-metadata does NOT stop this merge, measured: the on-disk check is the wall)
arm_ad_sym() {
  arm_dir ad-sym; mkdir -p "$FO"; craft_ad || return 1; craft_vault "$1" "$T/ad-sym.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an AppleDouble-merged symlink was EXTRACTED and accepted"; return 1; fi
  grep -q 'on disk, an extracted entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$P/restored" ] && [ "$(cat "$T/adcanary")" = adcanary ] || { echo "    restored/ was left behind or the canary changed"; return 1; }
}
# AppleDouble ACL+xattr members, on a file and on "." (restored/ itself): --no-mac-metadata drops
# them; open succeeds and nothing extracted, restored/ included, carries an xattr or an ACL
arm_ad_acl() {
  for a in acl root; do
    arm_dir "ad-$a"; mkdir -p "$FO"; craft_ad || return 1; craft_vault "$1" "$T/ad-$a.tgz"
    offline sh "$1" open "$P" --identity "$T/recovery.key" || { echo "    open refused the AppleDouble $a archive (the extraction applied its ACL/xattrs):"; show "$T/out.log"; return 1; }
    [ -z "$(attrs_under "$P/restored")" ] || { echo "    an xattr or an ACL reached restored/ ($a)"; return 1; }
  done
}
# a tar that ignores the hardening flags (sigbin/tar, FAKE_TAR_PLAIN) applies the AppleDouble ACL:
# the on-disk attribute check refuses and removes restored/
arm_ad_attr() {
  arm_dir ad-attr; mkdir -p "$FO"; craft_ad || return 1; craft_vault "$1" "$T/ad-acl.tgz"
  if offline PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_TAR_PLAIN=1 sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an extraction carrying an ACL was accepted"; return 1; fi
  grep -q 'carries extended attributes or an ACL' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$P/restored" ] || { echo "    restored/ was left behind"; return 1; }
}
# a chain info that repeats a key is refused, whichever copy carries the pinned value; a good one is
# stored (and served to tle) as its canonical bytes, jq -cS
arm_pin_dup() {
  for w in dupfirst duplast; do
    arm_dir "dup-$w"
    if offline FAKE_DRAND_INFO=$w sh "$1" seal Dup 10; then echo "    a chain info with a repeated key ($w) was SEALED"; return 1; fi
    grep -q 'is not JSON, or repeats a key' "$T/out.log" || { echo "    $w refused for another reason:"; show "$T/out.log"; return 1; }
  done
  arm_dir canon
  offline sh "$1" seal Canon 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  [ "$(cat "$(pkg_in Canon)/chain-info.json")" = "$INFO_PINNED" ] \
    || { echo "    chain-info.json is not INFO_PINNED"; return 1; }
}

# ── S2 review, fix round 1: the audit fails closed, its coverage has floors; open checks the
#    attachment counts; archived items ─────────────────────────────────────────────────────────
sb() { echo "$T/sigbin:$T/fakebin:$PATH"; }
# grep failing inside the audit (exit 2) refuses: "0 hits" is never read from a failed search
arm_audit_grep() {
  arm_dir agrep
  if offline PATH="$(sb)" FAKE_GREP_FAIL=1 sh "$1" seal Agrep 10; then echo "    SEALED although the audit's grep failed"; return 1; fi
  grep -q 'PII/ID audit: grep failed (exit 2)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in Agrep)" ] || { echo "    a package was left behind"; return 1; }
}
# a 3-char login is searched (as a whole word: no false hit on hex digests or JSON keys) and listed in
# the audit line; a 5-char login that IS in the archive (every tar header carries "ustar") is found;
# a 2-char login cannot be searched: refused, unless --allow-short-operator-strings, which says so
arm_audit_short() {
  arm_dir ash3
  offline PATH="$(sb)" FAKE_ID_UN=abc sh "$1" seal Ash3 10 || { echo "    the seal with a 3-char login failed:"; show "$T/out.log"; return 1; }
  grep -q 'searched: S .*; P .*login-name=1' "$T/out.log" || { echo "    a 3-char login was not searched:"; show "$T/out.log"; return 1; }
  arm_dir ash5
  if offline PATH="$(sb)" FAKE_ID_UN=ustar sh "$1" seal Ash5 10; then echo "    SEALED although the 5-char login is a word in every tar header"; return 1; fi
  grep -q 'PII/ID audit: [0-9]* hit(s) (categories: login-name)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  arm_dir ash2
  if offline PATH="$(sb)" FAKE_ID_UN=ab sh "$1" seal Ash2 10; then echo "    SEALED with a login too short to search"; return 1; fi
  grep -q 'too short to search (categories: login-name): REFUSING' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  arm_dir ash2ok
  offline PATH="$(sb)" FAKE_ID_UN=ab sh "$1" seal Ash2ok 10 --allow-short-operator-strings || { echo "    --allow-short-operator-strings did not seal:"; show "$T/out.log"; return 1; }
  grep -q 'allow-short-operator-strings: NOT searched for (1-2 characters): login-name' "$T/out.log" || { echo "    no warning naming the unsearched category"; return 1; }
}
# an empty identifier set (a jq / op JSON shape fault) refuses: S must hold an item id per item
arm_audit_floor() {
  arm_dir afloor
  if offline PATH="$(sb)" FAKE_JQ_EMPTY_S=1 sh "$1" seal Afl 10; then echo "    SEALED with an empty identifier set"; return 1; fi
  grep -q 'the item JSON yields 0 item id(s) for 3 declared item(s)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# an item whose JSON carries its id under another key: no pseudonym exists for it, and the seal
# refuses instead of putting the real id into the archive's paths
arm_pseudo_strict() {
  arm_dir noid
  if offline OP_FIXTURE_NOID=1 sh "$1" seal Noid 10; then echo "    SEALED although an item had no pseudonym"; return 1; fi
  grep -q 'no pseudonym for 1Password id synthitemb0000000000000002' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# rc_open P / rc_close P: decrypt P's archive (KEY path, real age) into $T/rc, then seal $T/rc
# again to a new key: a package whose archive the test changed
rc_open() { rm -rf "$T/rc"; mkdir "$T/rc" && age -d -i "$T/recovery.key" -o "$T/rc.key" "$1/unlock-KEY.age" && age -d -i "$T/rc.key" "$1/vault.tar.gz.age" | tar -xzf - -C "$T/rc"; }
rc_close() {
  COPYFILE_DISABLE=1 tar -czf "$T/rc.tgz" -C "$T/rc" items files $( [ ! -f "$T/rc/MANIFEST.csv" ] || echo MANIFEST.csv ) $( [ ! -f "$T/rc/ATTACHMENTS.csv" ] || echo ATTACHMENTS.csv ) && age-keygen -o "$T/rc2.key" 2>/dev/null \
    && age -r "$(age-keygen -y "$T/rc2.key")" -o "$1/vault.tar.gz.age" "$T/rc.tgz" && age -r "$RECIP" -o "$1/unlock-KEY.age" "$T/rc2.key"
  _rs=$?; rm -f "$T/rc.key" "$T/rc2.key"; return $_rs
}
# open: a manifest listing attachments with no ATTACHMENTS.csv in the archive does not report success
arm_open_att_missing() {
  arm_dir oattm
  offline sh "$1" seal Oattm 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Oattm); rc_open "$P" && rm "$T/rc/ATTACHMENTS.csv" && rc_close "$P" || { echo "    could not repack the archive"; return 1; }
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    open reported success with no ATTACHMENTS.csv for 2 listed attachments"; return 1; fi
  grep -q 'the manifest lists 2 attachment(s), but the archive holds no ATTACHMENTS.csv' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# open: an item whose ATTACHMENTS.csv rows differ from its manifest file_count does not report success
arm_open_att_count() {
  arm_dir oattc
  offline sh "$1" seal Oattc 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Oattc); rc_open "$P" && sed -i '' '2d' "$T/rc/ATTACHMENTS.csv" && rc_close "$P" || { echo "    could not repack the archive"; return 1; }
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    open reported success with an attachment row missing"; return 1; fi
  grep -q 'attachment(s), ATTACHMENTS.csv holds 0: the archive is NOT intact' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# an ARCHIVED Document is fetched (op document get --include-archive); an archived item's attachment
# (op read documents no --include-archive) refuses, naming item/file ids and why
arm_archived() {
  arm_dir archdoc
  offline OP_FIXTURE_ARCHIVED=doc sh "$1" seal Archd 10 --recovery-recipient "$RECIP" || { echo "    the archived Document was not sealed:"; show "$T/out.log"; return 1; }
  grep -q 'attachments 3 file(s)' "$T/out.log" || { echo "    the archived Document's file is missing:"; show "$T/out.log"; return 1; }
  offline sh "$1" open "$(pkg_in Archd)" --identity "$T/recovery.key" && grep -q '4/4 items match' "$T/out.log" && grep -q '3/3 attachments match' "$T/out.log" \
    || { echo "    open did not verify 4 items and 3 attachments:"; show "$T/out.log"; return 1; }
  arm_dir archatt
  if offline OP_FIXTURE_ARCHIVED=att sh "$1" seal Archa 10; then echo "    SEALED an archived item without its attachment"; return 1; fi
  grep -q 'synthiteme0000000000000005/synthfilee0000000000000001 (an ARCHIVED item: op read documents no --include-archive' "$T/out.log" \
    || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}

# seal_one SCRIPT INFO-VARIANT / pkg_new: one offline seal with that chain-info variant; its package
seal_one() { offline FAKE_DRAND_INFO=$2 sh "$1" seal Px 10; }
pkg_new() { pkg_in Px; }
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
# the mode-000 directory hiding a merged symlink: open refuses on the ON-DISK check and restored/ is
# gone; a mode-000 directory holding a regular file opens (the owner gets rw/rwx back; nothing hidden)
arm_m0() {
  arm_dir m0sym; mkdir -p "$FO"; craft_m0; craft_vault "$1" "$T/m0-sym.tgz"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    a symlink inside a mode-000 directory was accepted"; return 1; fi
  grep -q 'on disk, an extracted entry is not a regular file or a directory' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$P/restored" ] && [ "$(cat "$T/adcanary")" = adcanary ] || { echo "    restored/ is left, or the canary changed"; return 1; }
  arm_dir m0file; mkdir -p "$FO"; craft_m0; craft_vault "$1" "$T/m0-file.tgz"
  offline sh "$1" open "$P" --identity "$T/recovery.key" && [ "$(cat "$P/restored/d/f")" = regular-content ] \
    || { echo "    a mode-000 directory with a regular file did not open readable:"; show "$T/out.log"; return 1; }
}
# a refused extraction that cannot be removed (sigbin/rm refuses it) is reported, naming the path
arm_xv_gone() {
  arm_dir xvgone; mkdir -p "$FO"; craft_m0; craft_vault "$1" "$T/m0-sym.tgz"
  if offline PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_RM_FAIL=1 sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    open succeeded"; return 1; fi
  grep -q "could not remove $P/restored after refusing it: decrypted content may remain" "$T/out.log" || { echo "    an extraction that could not be removed was not reported:"; show "$T/out.log"; return 1; }
  find "$P/restored" -type d -exec chmod u+rwx {} \; ; rm -rf "$P/restored"
}
# ── S2 re-review I-3: no digest may be empty ──────────────────────────────────────────────────────
# a shasum that prints nothing, or fails: the seal refuses before encrypting, and leaves no package
arm_sha_seal() {
  for m in empty fail; do
    arm_dir "sha-$m"
    if offline PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_SHASUM=$m sh "$1" seal Sha 10; then echo "    SEALED with shasum $m (no digest)"; return 1; fi
    if [ "$m" = empty ]; then _sm='shasum gave no SHA-256'; else _sm='shasum failed on'; fi
    grep -q "$_sm" "$T/out.log" || { echo "    shasum $m: refused for another reason:"; show "$T/out.log"; return 1; }
    [ -z "$(pkg_in Sha)" ] || { echo "    a package was left behind"; return 1; }
  done
}
# open: a sealed MANIFEST row with an empty digest (the archive repacked, no manifest beside) refuses
arm_open_digest() {
  arm_dir odig
  offline sh "$1" seal Odig 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Odig); rc_open "$P" && sed -i '' '2s/^\([^,]*\),[0-9a-f]*,/\1,,/' "$T/rc/MANIFEST.csv" && rc_close "$P" && rm "$P/MANIFEST.csv" || { echo "    could not repack"; return 1; }
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    open reported success with an empty digest"; return 1; fi
  grep -q 'the digest is not 64 hex characters' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# ── S2 re-review M-6: item ids must be 1Password's documented shape ─────────────────────────────
arm_item_id() {
  arm_dir badid
  if offline OP_FIXTURE_BADID=1 sh "$1" seal Badid 10; then echo "    SEALED with a malformed item id"; return 1; fi
  grep -q 'op item list returned 1 item id(s) that are not 26' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q 'a[.]c' "$T/out.log" || { echo "    the malformed id was printed"; return 1; }
}
# the vault-name narrowing, compensated: a 2-char vault name is reported as not searched (no value)
arm_vault_short() {
  arm_dir vshort
  offline sh "$1" seal Vn 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  grep -q '; vault-name: 1 string(s) of 1-2 chars not searched$' "$T/out.log" || { echo "    the audit line does not say the vault name was skipped:"; show "$T/out.log"; return 1; }
}

# ── Task S2 §5: SEALED.txt at seal time ─────────────────────────────────────────────────────────
# a vt-broadcast that is not runnable refuses the seal BEFORE the vault is read
arm_need_vtb() {
  arm_dir needvtb
  if offline VT_BROADCAST="$T/nonexistent-vtb" sh "$1" seal Nvtb 10; then echo "    SEALED without a runnable vt-broadcast"; return 1; fi
  grep -q 'the broadcast tool is not runnable' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q 'declared' "$T/out.log" || { echo "    the vault was read before the refusal"; return 1; }
}
# fake_vtb: env-names works, seal-text refuses (a SEALED.txt that cannot be written)
fake_vtb() {
  printf '#!/bin/sh\ncase $1 in env-names) echo PATH ;; seal-text) echo "refused sealed.selfcheck: synthetic failure" >&2; exit 2 ;; *) exit 64 ;; esac\n' > "$T/fakevtb"
  chmod +x "$T/fakevtb"
}
# a SEALED.txt that cannot be written: the seal does NOT report success, the package is kept, and
# the message says how to write the text
arm_sealed_txt_fail() {
  arm_dir sealtxt; fake_vtb
  if offline VT_BROADCAST="$T/fakevtb" sh "$1" seal Stxt 10; then echo "    reported success without SEALED.txt"; return 1; fi
  P=$(pkg_in Stxt)
  grep -q "SEALED.txt could not be written (refused sealed.selfcheck: synthetic failure). The package is complete and kept at" "$T/out.log" \
    && grep -q -- "seal-text $P --write -- until then this seal has NOT finished" "$T/out.log" \
    && [ -f "$P/README.txt" ] && [ ! -e "$P/SEALED.txt" ] && ! grep -q '^  package    ' "$T/out.log" \
    || { echo "    not refused as a kept, unfinished package:"; show "$T/out.log"; return 1; }
}
# an ordinary seal ends with SEALED.txt: path, bytes and sha256 printed; the file is the one
# seal-text builds (re-running seal-text --write on it changes nothing)
arm_sealed_txt() {
  arm_dir sealok
  offline sh "$1" seal Sok 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Sok)
  grep -q "^  SEALED.txt $P/SEALED.txt  $(wc -c < "$P/SEALED.txt" | tr -d ' ') bytes  sha256 $(shasum -a 256 "$P/SEALED.txt" | cut -d' ' -f1)\$" "$T/out.log" \
    && head -1 "$P/SEALED.txt" | grep -q '^== vault-timelock sealed package: self-contained, age + drand timelock ==$' \
    && "$VT_BROADCAST" seal-text "$P" --write > /dev/null 2>&1 \
    || { echo "    no SEALED.txt line, or not seal-text's own text:"; show "$T/out.log"; return 1; }
}

# ── Task S2 §1: attachments are captured with the documented commands, verified, fail closed ───
# a seal fetches the attachment with op read and the Document with op document get, and open
# verifies both against the sealed ATTACHMENTS.csv
arm_attachments() {
  arm_dir att
  offline FAKE_OP_LOG="$T/oplog-att" sh "$1" seal Att 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  grep -q 'attachments 2 file(s): every listed file fetched' "$T/out.log" && grep -q 'and 2/2 attachments through the real ciphertext' "$T/out.log" \
    || { echo "    the seal did not capture and round-trip 2 attachments:"; show "$T/out.log"; return 1; }
  [ "$(grep -c '^op read --out-file$' "$T/oplog-att")" = 1 ] && [ "$(grep -c '^op document get$' "$T/oplog-att")" = 1 ] \
    || { echo "    expected one op read (attachment) and one op document get (Document item):"; show "$T/oplog-att"; return 1; }
  offline sh "$1" open "$(pkg_in Att)" --identity "$T/recovery.key" || { echo "    open failed:"; show "$T/out.log"; return 1; }
  grep -q '2/2 attachments match ATTACHMENTS.csv' "$T/out.log" || { echo "    open did not verify the attachments:"; show "$T/out.log"; return 1; }
}
# att_refused SCRIPT FIXTURE REASON: a seal with that op failure mode is refused for REASON, leaves no
# package, and names no file NAME (ids only)
att_refused() {
  arm_dir "att-$2"
  if offline "OP_FIXTURE_$2=1" sh "$1" seal Attf 10; then echo "    SEALED with OP_FIXTURE_$2"; return 1; fi
  grep -q -- "$3" "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q 'synthetic-attachment\|synthetic-document' "$T/out.log" || { echo "    a file NAME was printed"; return 1; }
  [ -z "$(pkg_in Attf)" ] || { echo "    a package was left behind"; return 1; }
}
arm_att_failed() { att_refused "$1" FAILFILE 'attachment(s) could not be fetched (item/file ids): synthitema0000000000000001/synthfilea0000000000000001'; }
arm_att_count() { att_refused "$1" NOFILE 'lists 1 attachment(s); 0 of them were fetched'; }
arm_att_size() { att_refused "$1" SHORTFILE 'bytes, but the item JSON says'; }
arm_att_doc() { att_refused "$1" DOCFAIL 'attachment(s) could not be fetched (item/file ids): synthitemc0000000000000003/synthfilec0000000000000001'; }
# an ATTACHMENTS.csv row whose ids are not [a-z0-9]+ is refused by open before it becomes a path
arm_att_id() {
  arm_dir attid
  offline sh "$1" seal Attid 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  # craft a package whose archive's ATTACHMENTS.csv carries a "../" id (KEY path, real age)
  P=$(pkg_in Attid); rm -rf "$T/attid"; mkdir -p "$T/attid/items" "$T/attid/files"
  rm "$P/MANIFEST.csv"
  printf 'item_id,file_id,bytes,sha256\n..,evil,1,%064d\n' 0 > "$T/attid/ATTACHMENTS.csv"
  tar czf "$T/attid.tgz" -C "$T/attid" ATTACHMENTS.csv items files
  age-keygen -o "$T/attid.key" 2>/dev/null
  age -r "$(age-keygen -y "$T/attid.key")" -o "$P/vault.tar.gz.age" "$T/attid.tgz"
  age -r "$RECIP" -o "$P/unlock-KEY.age" "$T/attid.key"; rm -f "$T/attid.key"
  if offline sh "$1" open "$P" --identity "$T/recovery.key"; then echo "    an ATTACHMENTS.csv with a '..' id was used"; return 1; fi
  grep -q 'ATTACHMENTS.csv has a row whose ids are not' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}
# the round trip re-checks every attachment: a tar that leaves files/ out of the archive is refused
arm_rt_attachments() {
  arm_dir rtatt
  if offline PATH="$T/sigbin:$T/fakebin:$PATH" FAKE_TAR_EXCLUDE='files/*' sh "$1" seal Rtatt 10; then echo "    SEALED although the archive lost its attachments"; return 1; fi
  grep -q '0 of 3 item(s) and 2 of 2 attachment(s)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in Rtatt)" ] || { echo "    a package was left behind"; return 1; }
}

# ── Task S2 §2: the archive carries no metadata of the sealing account ──────────────────────────
# scrub_check TGZ NORMALISED: the decrypted payload's gzip header has MTIME 0 and no name; the tar
# inside holds no occurrence of the login name, no xattr pax records, no AppleDouble ._ entry, every
# entry owned by 0/0 nobody/nobody; NORMALISED=yes: every extracted mtime is exactly 946684800
# (2000-01-01T00:00:00Z) and every mode 600 (files) / 700 (dirs)
scrub_check() {
  _g=$(head -c 10 "$1" | od -An -tx1 | tr -d ' \n')
  case $_g in 1f8b08??00000000*) ;; *) echo "    gzip header MTIME is not 0 (header $_g)"; return 1 ;; esac
  [ $(( 0x$(printf '%s' "$_g" | cut -c7-8) & 8 )) = 0 ] || { echo "    the gzip header carries a file name"; return 1; }
  rm -rf "$T/scrubx"; mkdir "$T/scrubx"
  gzip -dc < "$1" > "$T/scrubx.tar" 2>/dev/null || [ $? = 2 ] || { echo "    the payload is not gzip"; return 1; }
  _n=$(grep -a -c -F -- "$(id -un)" "$T/scrubx.tar" || true)
  [ "$_n" = 0 ] || { echo "    the login name occurs in $_n line(s) of the archive"; return 1; }
  _n=$(grep -a -c 'LIBARCHIVE\.xattr\|SCHILY\.xattr' "$T/scrubx.tar" || true)
  [ "$_n" = 0 ] || { echo "    xattr records in the archive ($_n line(s))"; return 1; }
  ! tar -tf "$T/scrubx.tar" | grep -q '\(^\|/\)\._' || { echo "    AppleDouble ._ entries in the archive"; return 1; }
  tar --numeric-owner -tvf "$T/scrubx.tar" | awk '$3 != "0" || $4 != "0" { bad = 1 } END { exit bad }' \
    && tar -tvf "$T/scrubx.tar" | awk '$3 != "nobody" || $4 != "nobody" { bad = 1 } END { exit bad }' \
    || { echo "    an entry is not owned by 0/0 nobody/nobody:"; tar -tvf "$T/scrubx.tar" | show; return 1; }
  [ "$2" = yes ] || return 0
  tar -xf "$T/scrubx.tar" -C "$T/scrubx" || { echo "    the archive did not extract"; return 1; }
  _b=$(find "$T/scrubx" -mindepth 1 -exec stat -f '%m %Lp %HT' {} + | awk '!(($1 == 946684800) && (($2 == 600 && $3 == "Regular") || ($2 == 700 && $3 == "Directory")))' | head -3)
  [ -z "$_b" ] || { echo "    an entry's mtime is not 2000-01-01T00:00:00Z or its mode not 600/700:"; printf '%s\n' "$_b" | show; return 1; }
}
# a synthetic seal (with an attachment that carries an xattr), decrypted on the KEY path with real
# age, inspected byte by byte. TZ=Pacific/Honolulu (UTC-10, no DST): a mtime set in local time shows
arm_scrub() {
  arm_dir scrub
  offline TZ=Pacific/Honolulu sh "$1" seal Scrub 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Scrub)
  age -d -i "$T/recovery.key" -o "$T/scrub.key" "$P/unlock-KEY.age" && age -d -i "$T/scrub.key" -o "$T/scrub.tgz" "$P/vault.tar.gz.age" \
    || { echo "    could not decrypt the synthetic seal"; return 1; }
  rm -f "$T/scrub.key"
  scrub_check "$T/scrub.tgz" yes
}

# ── Task S2 §7: no operator PII and no 1Password identifier inside the sealed payload ──────────
# decrypt_pkg P: the archive (KEY path, real age) into $T/pii.tgz and the time-locked key file
# (the fake tle wraps its input in a 4-line header) into $T/pii.key
decrypt_pkg() {
  age -d -i "$T/recovery.key" -o "$T/pii.id" "$1/unlock-KEY.age" && age -d -i "$T/pii.id" -o "$T/pii.tgz" "$1/vault.tar.gz.age" \
    || { echo "    could not decrypt the synthetic seal"; return 1; }
  tail -n +5 "$1/unlock-TIME.age" > "$T/pii.key"
  cmp -s "$T/pii.id" "$T/pii.key" || { echo "    the time-locked key file is not the recovery-wrapped one"; return 1; }
  gzip -dc < "$T/pii.tgz" > "$T/pii.tar" 2>/dev/null || [ $? = 2 ] || { echo "    the payload is not gzip"; return 1; }
  rm -rf "$T/piix"; mkdir "$T/piix"; tar -xf "$T/pii.tar" -C "$T/piix"
}
# (7c) the PII scan: in the decrypted archive AND the time-locked key file, ZERO occurrences of the
# operator's login name, full name, short host name, $HOME, UTC offset (±HH:MM), today's date (UTC
# and local), uid as a word, and the fake vault's real item ids, member UUID and vault names.
# Counts only, never a value. Strings shorter than 3 characters are not searched.
arm_pii_scan() {
  arm_dir piiscan
  offline sh "$1" seal SynthPiiVault 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  decrypt_pkg "$(pkg_in SynthPiiVault)" || return 1
  [ "$(wc -l < "$T/pii.key" | tr -d ' ')" = 1 ] && grep -q '^AGE-SECRET-KEY-1' "$T/pii.key" \
    || { echo "    the time-locked key file is not the one AGE-SECRET-KEY-1 line ($(wc -l < "$T/pii.key" | tr -d ' ') lines)"; return 1; }
  age -d -i "$T/pii.key" -o /dev/null "$(pkg_in SynthPiiVault)/vault.tar.gz.age" || { echo "    age -d -i does not accept the one-line key"; return 1; }
  _z=$(date +%z); _bad=0
  for kv in "login-name=$(id -un)" "full-name=$(id -F 2>/dev/null || true)" "host-name=$(hostname -s)" "home-dir=$HOME" \
            "tz-offset=${_z%??}:${_z#???}" "date-utc=$(date -u +%Y-%m-%d)" "date-local=$(date +%Y-%m-%d)" \
            "item-id=synthitema0000000000000001" "item-id=synthitemb0000000000000002" "item-id=synthitemc0000000000000003" \
            "member-id=SYNTHMEMBER000000000000001" "vault-name=SyntheticVaultNameX" "vault-name=SynthPiiVault" "vault-id=synthvault0000000000000001"; do
    _v=${kv#*=}; [ ${#_v} -ge 3 ] || continue
    _n=$(( $(LC_ALL=C grep -a -o -F -- "$_v" "$T/pii.tar" | wc -l) + $(LC_ALL=C grep -a -o -F -- "$_v" "$T/pii.key" | wc -l) ))
    [ "$_n" = 0 ] || { echo "    ${kv%%=*}: $_n occurrence(s) in the sealed payload"; _bad=1; }
  done
  _n=$(( $(LC_ALL=C grep -a -c -w -- "$(id -u)" "$T/pii.tar" || true) + $(LC_ALL=C grep -a -c -w -- "$(id -u)" "$T/pii.key" || true) ))
  [ "$_n" = 0 ] || { echo "    uid: $_n line(s) with the uid as a word"; _bad=1; }
  return $_bad
}
# (7b/7d) the sanitiser and the built-in audit: the seal prints the audit line; inside the archive
# the item JSON has no account metadata, every 1Password id is a pseudonym (consistently: a field's
# section.id is its section's), built-in ids and every value are kept, attachment paths are
# pseudonyms; the LOCAL manifest maps each pseudonym to the real op item id
arm_pii_audit() {
  arm_dir piiaudit
  offline sh "$1" seal Audit 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  grep -q '^  audit      0 operator identifiers, 0 1Password identifiers in the sealed payload (searched: S .*item-id=3.*; P .*home-dir=1.*login-name=1' "$T/out.log" \
    && grep -q 'sanitised  3 item(s): account metadata dropped, 8 1Password id(s) pseudonymised; values untouched' "$T/out.log" \
    || { echo "    no audit / sanitiser line:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Audit); decrypt_pkg "$P" || return 1
  _j=$(jq -c . "$T"/piix/items/*.json)
  for k in vault last_edited_by version created_at updated_at content_path reference; do
    ! printf '%s' "$_j" | grep -q "\"$k\":" || { echo "    the key $k survived the sanitiser"; return 1; }
  done
  for v in '"id":"username"' '"id":"password"' '"id":"notesPlain"' 'synthetic custom value' 'https://example.invalid/login' 'synthetic-attachment.txt' 's3cr3t-a' 'Synthetic Section'; do
    printf '%s' "$_j" | grep -qF "$v" || { echo "    a value or built-in id was lost: $v"; return 1; }
  done
  _a=; for f in "$T"/piix/items/*.json; do ! jq -e '[.fields[].value] | index("synthetic custom value ZZCANARY107")' "$f" >/dev/null || _a=$f; done
  jq -e '(.sections[0].id) as $s | ($s | test("^[0-9a-f]{32}$")) and ([.fields[] | select(.section) | .section.id] == [$s]) and ([.files[0].section.id] == [$s]) and (.id | test("^[0-9a-f]{32}$")) and (.files[0].id | test("^[0-9a-f]{32}$")) and (.urls[0].id | test("^[0-9a-f]{32}$"))' "$_a" >/dev/null \
    || { echo "    ids are not consistent 32-hex pseudonyms:"; show "$_a"; return 1; }
  _pi=$(basename "$_a" .json); _pf=$(jq -r '.files[0].id' "$_a")
  [ -f "$T/piix/files/$_pi/$_pf" ] && grep -q "^$_pi,$_pf,[0-9]*,[0-9a-f]\{64\}\$" "$T/piix/ATTACHMENTS.csv" \
    || { echo "    the attachment is not at files/<pseudo item>/<pseudo file> with its ATTACHMENTS.csv row"; return 1; }
  head -1 "$P/MANIFEST.csv" | grep -q ',op_item_id$' && grep -q "^$_pi,.*,synthitema0000000000000001\$" "$P/MANIFEST.csv" \
    && ! grep -q 'synthitem' "$T/piix/MANIFEST.csv" \
    || { echo "    the local manifest does not map pseudonym -> real id, or the sealed one has real ids"; return 1; }
}
# a note mentioning another item's UUID inside a longer value: the audit refuses, naming the
# category only; nothing is sealed and no id is printed
arm_pii_idinnote() {
  arm_dir idinnote
  if offline OP_FIXTURE_IDINNOTE=1 sh "$1" seal Note 10; then echo "    SEALED a payload holding a 1Password item id"; return 1; fi
  grep -q 'PII/ID audit: 1 hit(s) (categories: item-id)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q 'synthitem' "$T/out.log" || { echo "    an id was printed"; return 1; }
  [ -z "$(pkg_in Note)" ] && [ -z "$(ls -A "$T/tmp")" ] || { echo "    a package or plaintext was left behind"; return 1; }
}
# --keep-item-metadata and --keep-item-ids: each warns, naming what it exposes after the unlock, and
# the kept data is inside (the audit does not search what the operator chose to keep)
arm_pii_keep() {
  arm_dir keepmeta
  offline sh "$1" seal Keepm 10 --recovery-recipient "$RECIP" --keep-item-metadata || { echo "    the --keep-item-metadata seal failed:"; show "$T/out.log"; return 1; }
  grep -q -- '--keep-item-metadata: the vault id and name, the member UUID' "$T/out.log" || { echo "    no --keep-item-metadata warning"; return 1; }
  decrypt_pkg "$(pkg_in Keepm)" || return 1
  grep -q '"last_edited_by": *"SYNTHMEMBER000000000000001"' "$T"/piix/items/*.json && ! grep -q 'synthitema' "$T"/piix/items/*.json \
    || { echo "    --keep-item-metadata did not keep the metadata, or the ids were not pseudonymised"; return 1; }
  arm_dir keepids
  offline sh "$1" seal Keepi 10 --recovery-recipient "$RECIP" --keep-item-ids || { echo "    the --keep-item-ids seal failed:"; show "$T/out.log"; return 1; }
  grep -q -- "--keep-item-ids: 1Password's item, file, section and field ids" "$T/out.log" || { echo "    no --keep-item-ids warning"; return 1; }
  decrypt_pkg "$(pkg_in Keepi)" || return 1
  [ -f "$T/piix/items/synthitema0000000000000001.json" ] && grep -q 'content_path' "$T/piix/items/synthitema0000000000000001.json" \
    && ! grep -q 'last_edited_by' "$T/piix/items/synthitema0000000000000001.json" \
    || { echo "    --keep-item-ids did not keep the ids (or kept the metadata too)"; return 1; }
}

# ── Task S3: STRUCTURE.txt, the sealed vault's shape with every value removed (offline) ─────────────
# grow INDENT NAME TYPE PURPOSE STATE: one expected field row, laid out here with printf (the tool's
# layout is jq's): "field", the name in 12 columns, the type in 10, the purpose in 17, the state
grow() { printf '%sfield %-12s %-10s %-17s %s\n' "$1" "$2" "$3" "$4" "$5"; }
# struct_head DIGEST TOTALS: the expected header (golden), then a blank line
struct_head() {
  printf '%s\n' '== vault-timelock structure: shape only, every value removed (LOCAL ONLY, never published) ==' \
    'format: vault-timelock-structure/1' \
    'what-this-is: the layout of what vault.tar.gz.age holds. No titles, labels, values, URLs, tags,' \
    '  file names, sizes or lengths. <set>/<empty> says only whether a value exists. Item and file ids' \
    "  are the archive's own (items/<id>.json, files/<id>/<file>); MANIFEST.csv maps item ids to 1Password's." \
    "binds-to: vault.tar.gz.age sha256=$1   (valid for this archive only)" "totals: $2" ''
}
# struct_golden REAL-ID: the expected block of that synthetic item; the arm fills in <N> (its place in
# pseudonym order), <ID> (its pseudonym) and <FILE> (its file's pseudonym)
struct_golden() {
  case $1 in
    synthitema0000000000000001) printf '%s\n' 'item <N>  LOGIN  items/<ID>.json' '  title          <set>'
      grow '  ' username STRING purpose=USERNAME '<set>'; grow '  ' password CONCEALED purpose=PASSWORD '<set>'
      printf '%s\n' '  section 1'; grow '    ' custom STRING '' '<set>'
      printf '%s\n' '  urls           1 (1 primary)' '  tags           1' '  file           attachment files/<ID>/<FILE>' '' ;;
    synthitemb0000000000000002) printf '%s\n' 'item <N>  LOGIN  items/<ID>.json' '  title          <set>'
      grow '  ' username STRING purpose=USERNAME '<set>'; grow '  ' password CONCEALED purpose=PASSWORD '<set>'
      printf '%s\n' '  urls           0 (0 primary)' '  tags           0' '' ;;
    synthitemc0000000000000003) printf '%s\n' 'item <N>  DOCUMENT  items/<ID>.json' '  title          <set>'
      grow '  ' notesPlain STRING purpose=NOTES '<set>'
      printf '%s\n' '  urls           0 (0 primary)' '  tags           0' '  file           document   files/<ID>/<FILE>' '' ;;
    synthitemg0000000000000006) printf '%s\n' 'item <N>  OTHER  items/<ID>.json' '  title          <set>'
      grow '  ' username STRING purpose=USERNAME '<set>'; grow '  ' password CONCEALED purpose=PASSWORD '<empty>'
      grow '  ' custom MONTH_YEAR '' '<empty>'; grow '  ' custom MENU '' '<set>'
      printf '%s\n' '  section 1'; grow '    ' custom OTHER '' '<set>'; grow '    ' custom PHONE '' '<set>'
      printf '%s\n' '  section 2' '  urls           2 (1 primary)' '  tags           2' '' ;;
  esac
}
# the fake vault with every shape (OP_FIXTURE_SHAPES): STRUCTURE.txt is mode 600; holds no ZZCANARY and
# no other string of the fake vault (but the allowlisted tokens); is exactly the golden text with this
# seal's ids; says OTHER for the unknown category and field type; its rows equal MANIFEST.csv's counts
# item by item (counted here); binds to vault.tar.gz.age's SHA-256, the one SEALED.txt carries; README
# lists it as local only; SEALED.txt never carries it
arm_structure() {
  arm_dir struct
  offline OP_FIXTURE_SHAPES=1 sh "$1" seal Shapes 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Shapes); S="$P/STRUCTURE.txt"
  [ -f "$S" ] && [ ! -L "$S" ] && [ "$(stat -f %Lp "$S")" = 600 ] || { echo "    no STRUCTURE.txt of mode 600 beside the package"; return 1; }
  grep -q '^  structure  STRUCTURE.txt: 4 item(s), shape only, every value removed; counts = MANIFEST.csv (local only, mode 600)$' "$T/out.log" \
    && grep -q '^  audit      STRUCTURE.txt: 0 operator identifiers, 0 1Password identifiers' "$T/out.log" \
    || { echo "    no structure / audit line:"; show "$T/out.log"; return 1; }
  _n=$(grep -c ZZCANARY "$S" || true)
  [ "$_n" = 0 ] || { echo "    ZZCANARY: $_n line(s) of STRUCTURE.txt carry a canary"; return 1; }
  for _g in synthitema0000000000000001 synthitemb0000000000000002 synthitemc0000000000000003 synthitemg0000000000000006; do
    OP_FIXTURE_SHAPES=1 "$T/op" item get "$_g" --format json --reveal --include-archive
  done | jq -r '.. | strings' | grep -vxE 'LOGIN|DOCUMENT|STRING|CONCEALED|MONTH_YEAR|MENU|PHONE|USERNAME|PASSWORD|NOTES|username|password|notesPlain' \
    | awk 'length > 0' | LC_ALL=C sort -u > "$T/struct.vals"
  [ "$(wc -l < "$T/struct.vals")" -ge 60 ] || { echo "    only $(wc -l < "$T/struct.vals") strings of the fake vault to search for"; return 1; }
  _n=$(LC_ALL=C grep -c -F -f "$T/struct.vals" "$S" || true)
  [ "$_n" = 0 ] || { echo "    $_n line(s) of STRUCTURE.txt carry a string of the fake vault"; return 1; }
  decrypt_pkg "$P" || return 1
  _bh=$(shasum -a 256 "$P/vault.tar.gz.age" | cut -c1-64)
  tail -n +2 "$P/MANIFEST.csv" | cut -d, -f1,6 | LC_ALL=C sort > "$T/struct.ids"
  { struct_head "$_bh" '4 items, 12 fields, 3 sections, 3 urls, 2 files   by category: DOCUMENT 1, LOGIN 2, OTHER 1'
    _k=0
    while IFS=, read -r _pid _rid; do
      _k=$((_k + 1)); _pf=$(awk -F, -v p="$_pid" '$1 == p { print $2 }' "$T/piix/ATTACHMENTS.csv")
      struct_golden "$_rid" | sed "s/<N>/$_k/; s/<ID>/$_pid/g; s/<FILE>/$_pf/"
    done < "$T/struct.ids"
    echo '== end =='
  } > "$T/struct.want"
  cmp -s "$T/struct.want" "$S" || { echo "    STRUCTURE.txt is not the golden text (synthetic; < golden, > written):"; diff "$T/struct.want" "$S" | show; return 1; }
  grep -q '^item [0-9]  OTHER  items/[0-9a-f]\{32\}\.json$' "$S" && grep -q '^    field custom       OTHER  ' "$S" \
    || { echo "    the unknown category or field type is not OTHER"; return 1; }
  while IFS=, read -r _pid _h _fc _sc _lc _rid; do
    [ "$_pid" = item_id ] && continue
    _got=$(awk -v w="items/$_pid.json" '/^item / { on = ($NF == w); next } on && /^ +field / { f++ } on && /^  section / { s++ } on && /^  file / { l++ } END { printf "%d,%d,%d", f, s, l }' "$S")
    [ "$_got" = "$_fc,$_sc,$_lc" ] || { echo "    item $_rid: STRUCTURE.txt has $_got field/section/file rows, MANIFEST.csv says $_fc,$_sc,$_lc"; return 1; }
  done < "$P/MANIFEST.csv"
  grep -qx "binds-to: vault.tar.gz.age sha256=$_bh   (valid for this archive only)" "$S" \
    && grep -q "^\[file vault\.tar\.gz\.age bytes=[0-9]* sha256=$_bh\]\$" "$P/SEALED.txt" \
    || { echo "    binds-to is not vault.tar.gz.age's SHA-256 (the one SEALED.txt carries)"; return 1; }
  grep -q '^  STRUCTURE.txt      the vault.s shape with every value removed' "$P/README.txt" \
    && grep -q '^  local only         README.txt, MANIFEST.csv, STRUCTURE.txt, unlock-KEY.age: never published$' "$P/README.txt" \
    || { echo "    README.txt does not list STRUCTURE.txt as local only"; return 1; }
  ! grep -q 'STRUCTURE\|vault-timelock-structure\|ZZCANARY' "$P/SEALED.txt" || { echo "    SEALED.txt names STRUCTURE.txt or carries a canary"; return 1; }
}
# odd JSON shapes, through the seam (no seal: the seal's own checks refuse some of these earlier):
# entries that are not objects, non-string types and ids, an object for an array, duplicate and
# id-less sections, a field in a section that does not exist, file ids that are bad or not on disk:
# OTHER / custom / <empty> / "(invalid id)" / "(not on disk)", every entry counted, nothing echoed;
# an ARMORED archive is digested decoded; a non-JSON item and a bad item name are refused with fixed
# text that quotes nothing
arm_structure_shapes() {
  rm -rf "$T/shp"; mkdir -p "$T/shp/items" "$T/shp/files/bbbb2"
  printf '%s\n' '{"id":"x","category":7,"title":["ZZCANARY701"],"fields":{"a":{"id":"username","type":"STRING","purpose":"USERNAME","value":"ZZCANARY702"},"b":"ZZCANARY703"},"urls":"ZZCANARY704","tags":null}' > "$T/shp/items/aaaa1.json"
  printf '%s\n' '{"category":"LOGIN","fields":[{"id":5,"type":"CONCEALED","purpose":"ZZCANARY705","value":""},{"id":"password","type":["ZZCANARY706"],"value":0},{"id":"notesPlain","section":{"id":"s1"},"type":"STRING","purpose":"NOTES","value":"ZZCANARY707"},{"id":"ZZCANARY708","section":{"id":"nosuch"},"type":"URL","value":[]},{"section":"s1","type":"EMAIL","value":{}}],"sections":[{"id":"s1","label":"ZZCANARY709"},{"id":"s1"},"ZZCANARY710",{"label":"ZZCANARY711"}],"urls":[{"primary":true},{"primary":"true"},"ZZCANARY712"],"tags":["ZZCANARY713",5],"files":[{"id":"file1","name":"ZZCANARY714"},{"id":"ZZCANARY/../x"},{"id":"gone1"},7]}' > "$T/shp/items/bbbb2.json"
  echo synthetic > "$T/shp/files/bbbb2/file1"
  printf 'age-encryption.org/v1\nsynthetic archive bytes\n' > "$T/shp.bin"
  { echo '-----BEGIN AGE ENCRYPTED FILE-----'; base64 < "$T/shp.bin" | tr -d '\n' | fold -w 64; echo; echo '-----END AGE ENCRYPTED FILE-----'; } > "$T/shp.age"
  sh "$1" structure "$T/shp" "$T/shp.age" > "$T/shp.out" 2> "$T/shp.err" || { echo "    the structure seam failed:"; show "$T/shp.err"; return 1; }
  { struct_head "$(shasum -a 256 "$T/shp.bin" | cut -c1-64)" '2 items, 7 fields, 4 sections, 3 urls, 4 files   by category: LOGIN 1, OTHER 1'
    printf '%s\n' 'item 1  OTHER  items/aaaa1.json' '  title          <set>'
    grow '  ' username STRING purpose=USERNAME '<set>'; grow '  ' custom OTHER '' '<empty>'
    printf '%s\n' '  urls           0 (0 primary)' '  tags           0' '' 'item 2  LOGIN  items/bbbb2.json' '  title          <empty>'
    grow '  ' custom CONCEALED '' '<empty>'; grow '  ' password OTHER '' '<set>'; grow '  ' custom URL '' '<empty>'; grow '  ' custom EMAIL '' '<empty>'
    printf '%s\n' '  section 1'; grow '    ' notesPlain STRING purpose=NOTES '<set>'
    printf '%s\n' '  section 2' '  section 3' '  section 4' '  urls           3 (1 primary)' '  tags           2' \
      '  file           attachment files/bbbb2/file1' '  file           attachment files/bbbb2/(invalid id)  (not on disk)' \
      '  file           attachment files/bbbb2/gone1  (not on disk)' '  file           attachment files/bbbb2/(invalid id)  (not on disk)' '' '== end =='
  } > "$T/shp.want"
  cmp -s "$T/shp.want" "$T/shp.out" || { echo "    not the expected text (synthetic; < expected, > written):"; diff "$T/shp.want" "$T/shp.out" | show; return 1; }
  ! grep -q ZZCANARY "$T/shp.out" "$T/shp.err" || { echo "    a ZZCANARY was echoed"; return 1; }
  printf '{"title":"ZZCANARY715' > "$T/shp/items/cccc3.json"
  if sh "$1" structure "$T/shp" "$T/shp.age" > "$T/shp.out" 2>&1; then echo "    a non-JSON item was described"; return 1; fi
  grep -q 'an item could not be read as JSON (jq.s message is not shown' "$T/shp.out" && ! grep -q ZZCANARY "$T/shp.out" \
    || { echo "    a non-JSON item: not refused with the fixed text, or a canary echoed:"; show "$T/shp.out"; return 1; }
  rm "$T/shp/items/cccc3.json"; echo '{}' > "$T/shp/items/ZZCANARY716.json"
  if sh "$1" structure "$T/shp" "$T/shp.age" > "$T/shp.out" 2>&1; then echo "    an item named outside [a-z0-9] was described"; return 1; fi
  grep -q 'an item file name is not \[a-z0-9\]+.json (not printed)' "$T/shp.out" && ! grep -q ZZCANARY "$T/shp.out" \
    || { echo "    a bad item name: not refused with the fixed text, or the name echoed:"; show "$T/shp.out"; return 1; }
}
# open rebuilds the structure from restored/ and compares: "structure ✓". A tampered STRUCTURE.txt (a
# row, the binds-to line, a lost last line) is a WARNING naming only the first differing line number
# (never its content), and open still succeeds; without STRUCTURE.txt, open says it did not compare
arm_structure_open() {
  arm_dir structopen
  offline sh "$1" seal Sopen 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Sopen); cp "$P/STRUCTURE.txt" "$T/struct.orig"
  offline sh "$1" open "$P" --identity "$T/recovery.key" && grep -q '^  structure ✓ STRUCTURE.txt matches restored/ (items and files) and binds to this vault.tar.gz.age$' "$T/out.log" \
    || { echo "    open did not report 'structure ✓':"; show "$T/out.log"; return 1; }
  _nl=$(wc -l < "$T/struct.orig" | tr -d ' ')
  for m in "9|9s/.*/ZZCANARYTAMPER/" "6|6s/sha256=[0-9a-f]*/sha256=$(printf '%064d' 0)/" "$_nl|\$d"; do
    rm -rf "$P/restored"; sed "${m#*|}" "$T/struct.orig" > "$P/STRUCTURE.txt"
    ! cmp -s "$T/struct.orig" "$P/STRUCTURE.txt" || { echo "    the tamper '${m#*|}' changed nothing"; return 1; }
    offline sh "$1" open "$P" --identity "$T/recovery.key" || { echo "    open REFUSED over a tampered STRUCTURE.txt (it must only warn):"; show "$T/out.log"; return 1; }
    grep -q "^  ⚠ structure: STRUCTURE.txt differs from the structure of restored/ at line ${m%%|*} (its content is not shown)" "$T/out.log" && grep -q '^  restored   ' "$T/out.log" \
      || { echo "    a tampered STRUCTURE.txt (line ${m%%|*}) was not reported:"; show "$T/out.log"; return 1; }
    ! grep -q 'ZZCANARY\|structure ✓' "$T/out.log" || { echo "    the tampered line's content, or a ✓, was printed"; return 1; }
  done
  rm -rf "$P/restored" "$P/STRUCTURE.txt"
  offline sh "$1" open "$P" --identity "$T/recovery.key" && grep -q '^  structure  no STRUCTURE.txt beside the package: not compared$' "$T/out.log" \
    || { echo "    a package without STRUCTURE.txt did not open with 'not compared':"; show "$T/out.log"; return 1; }
}
# the audit refuses a STRUCTURE.txt that holds an operator string (here the login name is "custom", a
# word STRUCTURE.txt carries, while the payload holds it only inside values, where P is not searched):
# the seal does NOT report success; the package is kept with SEALED.txt and without STRUCTURE.txt (the
# README does not list it); the message says what to do; no value is printed
arm_structure_audit() {
  arm_dir structaudit
  if offline PATH="$(sb)" FAKE_ID_UN=custom sh "$1" seal Saud 10; then echo "    SEALED although STRUCTURE.txt holds the operator's login name"; return 1; fi
  P=$(pkg_in Saud)
  grep -q '★ STRUCTURE.txt could not be written: ★ PII/ID audit: [0-9]* hit(s) (categories: login-name) in STRUCTURE.txt: REFUSING to write it' "$T/out.log" \
    && grep -q 'fix the cause above and seal the vault again' "$T/out.log" \
    && grep -q "this seal has NOT finished: STRUCTURE.txt was not written (see above). The package is kept at $P/" "$T/out.log" \
    || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -n "$P" ] && [ -f "$P/SEALED.txt" ] && [ -f "$P/README.txt" ] && [ ! -e "$P/STRUCTURE.txt" ] && ! grep -q '^  package    ' "$T/out.log" \
    && ! grep -q 'STRUCTURE' "$P/README.txt" \
    || { echo "    not a kept package without STRUCTURE.txt (or its README lists it)"; return 1; }
}
# a generator that miscounts (sigbin/jq drops a field row): the MANIFEST count assertion refuses it;
# the seal does NOT report success; the package is kept with SEALED.txt and without STRUCTURE.txt
arm_structure_count() {
  arm_dir structcount
  if offline PATH="$(sb)" FAKE_JQ_STRUCT_DROP=1 sh "$1" seal Scnt 10; then echo "    SEALED although STRUCTURE.txt lost a field row"; return 1; fi
  P=$(pkg_in Scnt)
  grep -q '★ STRUCTURE.txt could not be written: ★ STRUCTURE.txt does not match MANIFEST.csv (per item: fields, sections, files)' "$T/out.log" \
    && [ -n "$P" ] && [ -f "$P/SEALED.txt" ] && [ ! -e "$P/STRUCTURE.txt" ] \
    || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
}

# ── Task SP: SEALED-plaintext.txt, every entry decrypted, written by open --plaintext (offline) ──────────
# PT_SRC is the PLAIN vault (items A B C G H, OP_FIXTURE_PLAIN), sealed offline by the UNMUTATED script with
# a 30 s horizon early in the suite, so that its round has passed when these arms run. Each arm opens its
# own COPY (KEY path, real age; the TIME path through the fake tle in arm_plaintext_mode).
# pt_pkg NAME: a fresh copy of PT_SRC in its own arm dir (P)
pt_pkg() { arm_dir "pt-$1"; mkdir -p "$FO" && cp -Rp "$PT_SRC" "$FO/" && P="$FO/$(basename "$PT_SRC")"; }
# pt_open SCRIPT [ARG...]: open P on the KEY path with --plaintext
pt_open() { _po=$1; shift; offline sh "$_po" open "$P" --identity "$T/recovery.key" --plaintext "$@"; }
# pt_none: P holds no SEALED-plaintext.txt and no temp file of one
pt_none() { [ ! -e "$P/SEALED-plaintext.txt" ] && [ ! -L "$P/SEALED-plaintext.txt" ] && ! ls -A "$P" | grep -q 'SEALED-plaintext'; }
# pt_golden REAL-ID: the expected block of that synthetic item, laid out here independently of PLAIN_JS; the
# arm fills in <N> (its place in pseudonym order), <ID> (its pseudonym), <FILE> <FB> <FH> (its file's
# pseudonym, bytes and SHA-256). H's invalid byte arrives as U+FFFD: the seal's sanitiser (jq) replaced it
# at seal time, as op's own JSON encoder would; raw invalid bytes are the escape arm's (seam). H's notes hold
# a tab and a BEL, so that block is escaped ("\" in column 1); its keys outside the rows are "other values".
pt_golden() {
  case $1 in
    synthitema0000000000000001) printf '%s\n' '[item <N>] LOGIN  Synthetic login a ZZCANARY101' \
      '  username ZZCANARY102 : u-a-ZZCANARY103' '  password ZZCANARY104 : s3cr3t-a-ZZCANARY105' \
      '  section "Synthetic Section ZZCANARY108"' '    custom ZZCANARY106 : synthetic custom value ZZCANARY107' \
      '  url website ZZCANARY110 : https://example.invalid/login/ZZCANARY111   (primary)' '  tags : ZZCANARY112-tag' \
      '  file ZZCANARY109-synthetic-attachment.txt : files/<ID>/<FILE>  (<FB> B, sha256 <FH>)  [attachment]' '' ;;
    synthitemb0000000000000002) printf '%s\n' '[item <N>] LOGIN  Synthetic login b ZZCANARY201' \
      '  username ZZCANARY202 : u-b-ZZCANARY203' '  password ZZCANARY204 : s3cr3t-b-ZZCANARY205' '' ;;
    synthitemc0000000000000003) printf '%s\n' '[item <N>] DOCUMENT  Synthetic document ZZCANARY301' \
      '  notes :' '    synthetic document note ZZCANARY303' \
      '  file ZZCANARY304-synthetic-document.pdf : files/<ID>/<FILE>  (<FB> B, sha256 <FH>)  [document]' '' ;;
    synthitemg0000000000000006) printf '%s\n' '[item <N>] ZZCANARY602_CATEGORY  Synthetic shapes ZZCANARY601' \
      '  username ZZCANARY605 : u-g-ZZCANARY606' '  password ZZCANARY607 : (empty)' '  expiry ZZCANARY614 : (empty)' \
      '  menu ZZCANARY615 : {"choice":"ZZCANARY616"}' '  section "Shapes Section ZZCANARY603"' \
      '    odd type ZZCANARY609 : odd value ZZCANARY610' '    phone ZZCANARY612 : phone ZZCANARY613' \
      '  section "Empty Section ZZCANARY604"' '  url one ZZCANARY617 : https://example.invalid/ZZCANARY618   (primary)' \
      '  url two ZZCANARY619 : https://example.invalid/ZZCANARY620' '  tags : ZZCANARY621-tag, ZZCANARY622-tag' '' ;;
    synthitemh0000000000000007) printf '%s\n' '[item <N>] LOGIN  Synthetic plain h ZZCANARY801' \
      '  username ZZCANARY803 : u-h-ZZCANARY804' '  password ZZCANARY805 : (empty)' \
      '  answer ZZCANARY806 : line one ZZCANARY807' '      line two ZZCANARY808' '      ' \
      '  private key ZZCANARY826 : -----BEGIN PRIVATE KEY-----' '      PKCS8 ZZCANARY827' '      -----END PRIVATE KEY-----' \
      '  section "Security ZZCANARY802"' \
      '    one-time password ZZCANARY809 : otpauth://totp/Synthetic:h?secret=ZZCANARY810&issuer=Synthetic' \
      "    recovery code ZZCANARY811 : rc-ZZCANARY812-$(printf '\357\277\275')-end" \
      '    recovery codes ZZCANARY813 : code-1 ZZCANARY814' '        code-2 ZZCANARY815' \
      '  url website ZZCANARY820 : https://example.invalid/h/ZZCANARY821   (primary)' \
      '  url backup ZZCANARY822 : https://example.invalid/h2/ZZCANARY823' '  tags : ZZCANARY824-tag, second ZZCANARY825' \
      '\ notes :' '\   first line ZZCANARY817' '\   second\x09line ZZCANARY818' '\   bell \x07 here ZZCANARY819' \
      '  other values :' '    fields[1].password_details.history[0] : old ZZCANARY829' \
      '    fields[3].ssh_formats.openssh.value : -----BEGIN OPENSSH PRIVATE KEY-----' '        OPENSSH ZZCANARY828' '        -----END OPENSSH PRIVATE KEY-----' \
      '    additional_information : u-h ZZCANARY830' '    state : ARCHIVED' '    unknown_extra.note : ZZCANARY831' '    unknown_extra.n : 3' '' ;;
  esac
}
# the golden SEALED-plaintext.txt of the PLAIN vault: the header (SEALED.txt's and the archive's SHA-256,
# structure ✓, SEALED.txt's own unlock-after line), then every item's block in pseudonym order
arm_plaintext_golden() {
  pt_pkg gold || { echo "    could not copy the PLAIN package"; return 1; }
  pt_open "$1" || { echo "    open --plaintext failed:"; show "$T/out.log"; return 1; }
  tail -n +2 "$P/MANIFEST.csv" | cut -d, -f1,6 | LC_ALL=C sort > "$T/pt.ids"
  { printf '%s\n' '== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==' 'format: vault-timelock-plaintext/1' \
      "source: SEALED.txt sha256=$(shasum -a 256 "$P/SEALED.txt" | cut -c1-64)   archive: vault.tar.gz.age sha256=$(shasum -a 256 "$P/vault.tar.gz.age" | cut -c1-64)   structure: ✓" \
      "opened-after: $(sed -n 's/^unlock-after: \(.*\)  (drand round \([0-9]*\))$/\1   (drand round \2)/p' "$P/SEALED.txt")" \
      'escapes: a row with "\" in column 1 is escaped (\\ = one backslash, \xNN = one byte of UTF-8); every other row is verbatim; (empty) = an empty value' \
      'delete: this file and restored/ hold every secret: read them, then delete both promptly (Spotlight may index them, and backups may copy them, while they exist)' ''
    _k=0
    while IFS=, read -r _pid _rid; do
      _k=$((_k + 1)); _pr=$(awk -F, -v p="$_pid" '$1 == p { print $2 "," $3 "," $4 }' "$P/restored/ATTACHMENTS.csv")
      pt_golden "$_rid" | sed "s/<N>/$_k/; s/<ID>/$_pid/g; s/<FILE>/${_pr%%,*}/; s/<FB>/$(echo "$_pr" | cut -d, -f2)/; s/<FH>/${_pr##*,}/"
    done < "$T/pt.ids"
    echo '== end (5 items, 2 files) =='
  } > "$T/pt.want"
  cmp -s "$T/pt.want" "$P/SEALED-plaintext.txt" || { echo "    SEALED-plaintext.txt is not the golden text (synthetic; < golden, > written):"; diff "$T/pt.want" "$P/SEALED-plaintext.txt" | show; return 1; }
}
# PT_CANARY_JQ: from the fake op's own item JSON, every canary in a VALUE-bearing place, as "<canary> <kind>
# <item>" (item = the canary of its title): title, category, label/value (slabel/svalue in a section), a
# NOTES field's value (notes; its label is not printed), section, url-label, url-href, tag, file (its name),
# and "other" for every other value (SP review m5). Ids, types, purposes, a field's copy of its section label,
# reference/entropy/totp/password strength and account metadata are not values.
PT_CANARY_JQ='. as $it
| ($it.title | [match("ZZCANARY[0-9]+").string][0]) as $item
| [($it.sections // [])[] | .id] as $sids
| paths(type == "string") as $p
| (getpath($p) | [match("ZZCANARY[0-9]+"; "g").string][]) as $c
| (if $p == ["title"] then "title" elif $p == ["category"] then "category"
   elif $p[0] == "fields" then
     $it.fields[$p[1]] as $f
     | (($f.section.id? // null) as $s | $s != null and ($sids | index($s)) != null) as $insec
     | ((($f.purpose // "") == "NOTES") and ($insec | not)) as $notes
     | if $p[2] == "label" and ($p | length) == 3 then (if $notes then "skip" elif $insec then "slabel" else "label" end)
       elif $p[2] == "value" then (if $notes then "notes" elif $insec then "svalue" else "value" end)
       elif ($p[2] | IN("id", "section", "type", "purpose", "reference", "entropy", "totp")) or $p[2:4] == ["password_details", "strength"] then "skip"
       else "other" end
   elif $p[0] == "sections" then (if $p[2] == "label" then "section" elif $p[2] == "id" then "skip" else "other" end)
   elif $p[0] == "urls" then (if $p[2] == "label" then "url-label" elif $p[2] == "href" then "url-href" elif $p[2] == "id" then "skip" else "other" end)
   elif $p[0] == "tags" then "tag"
   elif $p[0] == "files" then (if $p[2] == "name" then "file" elif ($p[2] | IN("id", "section", "content_path")) then "skip" else "other" end)
   elif ($p[0] | IN("id", "version", "vault", "last_edited_by", "created_at", "updated_at")) then "skip"
   else "other" end) as $k
| select($k != "skip") | "\($c) \($k) \($item)"'
# PT_CANARY_AWK: every canary occurrence in SEALED-plaintext.txt, as "<canary> <kind> <item>", the kind read
# from the line's place in the format (header, field row label/value, section, url, tags, notes, file, other
# values); an escaped row's "\" in column 1 is read as the indentation it replaces
PT_CANARY_AWK='
/^\\\[item / { $0 = substr($0, 2) }
/^\\ / { $0 = " " substr($0, 2) }
function emit(s, k) { while (match(s, /ZZCANARY[0-9]+/)) { print substr(s, RSTART, RLENGTH), k, item; s = substr(s, RSTART + RLENGTH) } }
function lv(s, lk, vk,   p) { p = index(s, " : "); if (p == 0) { emit(s, "?"); return } emit(substr(s, 1, p - 1), lk); emit(substr(s, p + 3), vk) }
/^\[item [0-9]+\] / { m = $0; sub(/^\[item [0-9]+\] /, "", m); p = index(m, "  "); t = substr(m, p + 2); item = "?"
  if (match(t, /ZZCANARY[0-9]+/)) item = substr(t, RSTART, RLENGTH); emit(substr(m, 1, p - 1), "category"); emit(t, "title"); mode = "top"; next }
mode == "notes" && /^    / { emit($0, "notes"); next }
/^  section "/ { emit($0, "section"); mode = "sec"; next }
/^  notes :/ { emit(substr($0, 10), "?"); mode = "notes"; next }
/^  url / { lv(substr($0, 7), "url-label", "url-href"); mode = "url"; next }
/^  tags : / { emit(substr($0, 10), "tag"); mode = "tags"; next }
/^  file / { lv(substr($0, 8), "file", "?"); mode = "file"; next }
/^  other values :$/ { mode = "other"; next }
/^  [^ ]/ { lv(substr($0, 3), "label", "value"); mode = "topf"; next }
/^    [^ ]/ { if (mode == "sec" || mode == "secf") { lv(substr($0, 5), "slabel", "svalue"); mode = "secf" } else if (mode == "other" || mode == "otherv") { lv(substr($0, 5), "other-key", "other"); mode = "otherv" } else emit($0, "?"); next }
/^      / { if (mode == "topf") emit($0, "value"); else if (mode == "url") emit($0, "url-href"); else if (mode == "secf") emit($0, "svalue"); else if (mode == "otherv") emit($0, "other"); else emit($0, "?"); next }
{ emit($0, "?") }'
# completeness: EVERY canary value of the PLAIN vault is in SEALED-plaintext.txt exactly once, in the
# right item and the right place (computed from the fake op's JSON, not listed by hand); the attachments'
# bytes are not (listed, never inlined)
arm_plaintext_complete() {
  pt_pkg comp || { echo "    could not copy the PLAIN package"; return 1; }
  pt_open "$1" || { echo "    open --plaintext failed:"; show "$T/out.log"; return 1; }
  ! grep -q 'ZZCANARY113\|ZZCANARY305\|synthetic attachment bytes\|PDF-synthetic' "$P/SEALED-plaintext.txt" || { echo "    attachment bytes are inlined in SEALED-plaintext.txt"; return 1; }
  for _g in synthitema0000000000000001 synthitemb0000000000000002 synthitemc0000000000000003 synthitemg0000000000000006 synthitemh0000000000000007; do
    "$T/op" item get "$_g" --format json --reveal --include-archive
  done | jq -r "$PT_CANARY_JQ" | LC_ALL=C sort > "$T/pt.exp"
  [ "$(wc -l < "$T/pt.exp")" -ge 60 ] && [ "$(grep -c ' other ' "$T/pt.exp")" -ge 4 ] || { echo "    the fake vault yields fewer than 60 canaries, or fewer than 4 other values:"; show "$T/pt.exp"; return 1; }
  awk "$PT_CANARY_AWK" "$P/SEALED-plaintext.txt" | LC_ALL=C sort > "$T/pt.got"
  cmp -s "$T/pt.exp" "$T/pt.got" || { echo "    a canary value is missing or misplaced, or not there exactly once (< expected, > found):"; diff "$T/pt.exp" "$T/pt.got" | show; return 1; }
}
# mode 600 (created under umask 022 here), the TIME path (fake tle "opens"), the plaintext line (path,
# bytes, lines, sha256 of the file) and the warnings; the file and restored/ excluded from Time Machine
# (tmutil addexclusion, SP review m7); no value printed; no temp file left; structure ✓
arm_plaintext_mode() {
  pt_pkg mode || { echo "    could not copy the PLAIN package"; return 1; }
  ( umask 022 && offline PATH="$T/realtm:$T/fakebin:$PATH" FAKE_TLE_DECRYPT=open sh "$1" open "$P" --plaintext ) || { echo "    open --plaintext (TIME path) failed:"; show "$T/out.log"; return 1; }
  S="$P/SEALED-plaintext.txt"
  [ -f "$S" ] && [ ! -L "$S" ] || { echo "    no SEALED-plaintext.txt"; return 1; }
  _m=$(stat -f %Lp "$S"); [ "$_m" = 600 ] || { echo "    SEALED-plaintext.txt has mode $_m, not 600"; return 1; }
  grep -q '^  path       TIME (drand round ' "$T/out.log" \
    && grep -qxF "  plaintext  $S  $(wc -c < "$S" | tr -d ' ') bytes  $(wc -l < "$S" | tr -d ' ') lines  sha256 $(shasum -a 256 "$S" | cut -c1-64)" "$T/out.log" \
    && grep -qxF '  ★ SEALED-plaintext.txt contains every secret in plain text; delete it (and restored/) when done' "$T/out.log" \
    && grep -qxF '  ★ Time Machine exclusion (tmutil addexclusion): SEALED-plaintext.txt yes, restored/ yes. Spotlight may index both while they exist: read the file, then delete both promptly' "$T/out.log" \
    || { echo "    no TIME path, plaintext line (path, bytes, lines, sha256) or warnings:"; show "$T/out.log"; return 1; }
  tmutil isexcluded "$S" | grep -q '^\[Excluded\]' && tmutil isexcluded "$P/restored" | grep -q '^\[Excluded\]' || { echo "    SEALED-plaintext.txt or restored/ is not excluded from Time Machine"; return 1; }
  ! grep -q ZZCANARY "$T/out.log" || { echo "    a value was printed"; return 1; }
  [ "$(ls -A "$P" | grep -c 'SEALED-plaintext')" = 1 ] && [ -d "$P/restored" ] || { echo "    a temp file was left, or restored/ is missing"; ls -A "$P" | show; return 1; }
  sed -n 3p "$S" | grep -q '   structure: ✓$' || { echo "    the header does not say structure ✓"; return 1; }
}
# before the round: KEY path and TIME path both refused BEFORE anything is decrypted (no restored/, no
# drand request), and no file
arm_plaintext_round() {
  arm_dir ptround
  offline sh "$1" seal Ptr 10 --recovery-recipient "$RECIP" || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Ptr)
  if offline sh "$1" open "$P" --identity "$T/recovery.key" --plaintext; then echo "    written before the round (KEY path)"; return 1; fi
  grep -q 'the unlock time has not passed (.* UTC, drand round [0-9]*): SEALED-plaintext.txt exists only after the unlock time. Nothing was opened.' "$T/out.log" \
    && [ ! -e "$P/restored" ] && pt_none || { echo "    KEY path: refused for another reason, or restored/ or a file was written:"; show "$T/out.log"; return 1; }
  if offline sh "$1" open "$P" --plaintext; then echo "    written before the round (TIME path)"; return 1; fi
  grep -q 'the unlock time has not passed' "$T/out.log" && [ ! -e "$P/restored" ] && pt_none || { echo "    TIME path: refused for another reason:"; show "$T/out.log"; return 1; }
  ! grep -q '^tle decrypt' "$FL" 2>/dev/null || { echo "    drand was asked before the refusal"; return 1; }
}
# any verification failure: no file. A tampered item (open refuses); STRUCTURE.txt that differs (open only
# warns: --plaintext refuses); no manifest at all (UNVERIFIED); an item the manifest does not list; a
# SEALED.txt of another archive
arm_plaintext_verify() {
  pt_pkg vtamper || return 1
  rc_open "$P" && _ti=$(ls "$T/rc/items" | head -1) && printf ' ' >> "$T/rc/items/$_ti" && rc_close "$P" || { echo "    could not repack"; return 1; }
  if pt_open "$1"; then echo "    written although an item was tampered"; return 1; fi
  grep -q 'failed verification' "$T/out.log" && pt_none || { echo "    a tampered item: refused for another reason, or a file was written:"; show "$T/out.log"; return 1; }
  pt_pkg vstruct || return 1
  printf 'tampered\n' >> "$P/STRUCTURE.txt"
  if pt_open "$1"; then echo "    written although STRUCTURE.txt differs from restored/"; return 1; fi
  grep -q '⚠ structure: STRUCTURE.txt differs' "$T/out.log" && grep -q '★ --plaintext: STRUCTURE.txt does not match restored/' "$T/out.log" && [ -d "$P/restored" ] && pt_none \
    || { echo "    STRUCTURE.txt differs: refused for another reason, or a file was written:"; show "$T/out.log"; return 1; }
  pt_pkg vnomf || return 1
  rc_open "$P" && rm "$T/rc/MANIFEST.csv" "$P/MANIFEST.csv" "$P/STRUCTURE.txt" && rc_close "$P" || { echo "    could not repack"; return 1; }
  if pt_open "$1"; then echo "    written although no manifest verified the items"; return 1; fi
  grep -q 'completeness is UNVERIFIED' "$T/out.log" && grep -q '★ --plaintext: the items were not verified against a manifest' "$T/out.log" && pt_none \
    || { echo "    no manifest: refused for another reason, or a file was written:"; show "$T/out.log"; return 1; }
  pt_pkg vextra || return 1
  rc_open "$P" && echo '{}' > "$T/rc/items/zz0extra.json" && rm "$P/STRUCTURE.txt" && rc_close "$P" || { echo "    could not repack"; return 1; }
  if pt_open "$1"; then echo "    written although restored/ holds an item the manifest does not list"; return 1; fi
  grep -q '★ --plaintext: restored/items does not hold exactly the items the manifest lists and open verified (6 on disk, 5 verified)' "$T/out.log" && pt_none \
    || { echo "    an unlisted item: refused for another reason, or a file was written:"; show "$T/out.log"; return 1; }
  pt_pkg vsealed || return 1
  sed -i '' "s/^\(\[file vault\.tar\.gz\.age bytes=[0-9]* sha256=\)[0-9a-f]*\]\$/\1$(printf '%064d' 0)]/" "$P/SEALED.txt"
  if pt_open "$1"; then echo "    written although SEALED.txt describes another archive"; return 1; fi
  grep -q "★ --plaintext: SEALED.txt does not carry this vault.tar.gz.age's SHA-256" "$T/out.log" && pt_none \
    || { echo "    another SEALED.txt: refused for another reason, or a file was written:"; show "$T/out.log"; return 1; }
}
# seal --plaintext is refused, before op runs, with the reason, the flag last or FIRST; any other option where
# the vault name belongs, and an option where open's package belongs, are refused too (SP review m4)
arm_plaintext_seal() {
  for _a in 'Pts 10 --plaintext' '--plaintext' '--plaintext Pts 10'; do
    arm_dir ptseal; rm -f "$T/oplog-pts"
    if offline FAKE_OP_LOG="$T/oplog-pts" sh "$1" seal $_a; then echo "    seal $_a was accepted (the flag first or last)"; return 1; fi
    grep -qxF 'plaintext exists only after the unlock time — use open --plaintext' "$T/out.log" || { echo "    seal $_a: refused for another reason (the flag first or last):"; show "$T/out.log"; return 1; }
    [ ! -s "$T/oplog-pts" ] && [ -z "$(ls -A "$FO")" ] || { echo "    seal $_a: op ran, or a package was written (the flag first or last)"; return 1; }
  done
  arm_dir ptdash; rm -f "$T/oplog-pts"
  if offline FAKE_OP_LOG="$T/oplog-pts" sh "$1" seal -x Pts 10; then echo "    seal -x Pts 10 was accepted (an option first)"; return 1; fi
  grep -qxF "seal <vault-name> [DURATION] [options]: '-x' is an option, not a vault name: the vault name comes first" "$T/out.log" && [ ! -s "$T/oplog-pts" ] \
    || { echo "    seal -x: refused for another reason, or op ran (an option first):"; show "$T/out.log"; return 1; }
  if offline sh "$1" open --plaintext "$T/nowhere"; then echo "    open --plaintext <dir> was accepted (open with the flag first)"; return 1; fi
  grep -qxF "open <package-dir> [options]: '--plaintext' is an option, not a package: the package comes first" "$T/out.log" \
    || { echo "    open with the flag first: refused for another reason:"; show "$T/out.log"; return 1; }
}
# an existing SEALED-plaintext.txt is never overwritten without --force (refused before decrypting); --force
# replaces a regular file (mode 600, the same text); a symlink in its place is refused either way, its
# target untouched; --force without --plaintext is refused
arm_plaintext_force() {
  pt_pkg force || return 1
  pt_open "$1" || { echo "    open --plaintext failed:"; show "$T/out.log"; return 1; }
  cp "$P/SEALED-plaintext.txt" "$T/pt.first"; rm -rf "$P/restored"
  if pt_open "$1"; then echo "    an existing SEALED-plaintext.txt was overwritten without --force"; return 1; fi
  grep -q 'SEALED-plaintext.txt already exists: not overwritten (pass --force to replace it). Nothing was opened.' "$T/out.log" \
    && cmp -s "$T/pt.first" "$P/SEALED-plaintext.txt" && [ ! -e "$P/restored" ] || { echo "    refused for another reason, or the file changed:"; show "$T/out.log"; return 1; }
  echo old > "$P/SEALED-plaintext.txt"
  pt_open "$1" --force && cmp -s "$T/pt.first" "$P/SEALED-plaintext.txt" && [ "$(stat -f %Lp "$P/SEALED-plaintext.txt")" = 600 ] \
    && [ "$(ls -A "$P" | grep -c 'SEALED-plaintext')" = 1 ] \
    || { echo "    --force did not replace it with the plaintext (mode 600, no temp file left):"; show "$T/out.log"; return 1; }
  rm -rf "$P/restored" "$P/SEALED-plaintext.txt"; echo target > "$T/pt.target"; ln -s "$T/pt.target" "$P/SEALED-plaintext.txt"
  if pt_open "$1" --force; then echo "    --force replaced a symlink"; return 1; fi
  grep -q 'is not a regular file (a directory, a symlink or a FIFO): --force replaces only a regular file' "$T/out.log" || { echo "    a symlink with --force: refused for another reason:"; show "$T/out.log"; return 1; }
  if pt_open "$1"; then echo "    a symlink was written through"; return 1; fi
  grep -q 'already exists: not overwritten' "$T/out.log" && [ "$(cat "$T/pt.target")" = target ] && [ -L "$P/SEALED-plaintext.txt" ] && [ ! -e "$P/restored" ] \
    || { echo "    a symlink: refused for another reason, or its target changed:"; show "$T/out.log"; return 1; }
  if offline sh "$1" open "$P" --identity "$T/recovery.key" --force; then echo "    --force without --plaintext was accepted"; return 1; fi
  grep -q -- '--force goes with --plaintext only' "$T/out.log" || { echo "    --force alone: refused for another reason:"; show "$T/out.log"; return 1; }
}
# the escaping rules (SP review I1), through the seam on a crafted tree. A row is VERBATIM (a backslash as
# itself) unless a text needs escaping; then the whole row is escaped, "\" in column 1 of each of its lines,
# \\ for a backslash, \xNN per byte. Every class: raw invalid UTF-8 (a lone byte, a truncated sequence, an
# overlong form, an encoded surrogate, past U+10FFFF, an invalid lead byte); C0, DEL and C1 controls (escapes
# and raw bytes); lone surrogates; NBSP, U+200B, U+202E, U+FEFF, U+3000, U+2028, a variation selector, a
# private-use and an unassigned code point; the literal (empty); a backslash beside a control; spaces at a
# line edge; the row separators (" : " in a label, ", " in a tag, a space in the category, "(primary)" at a
# href's end); a newline in a label or tag; and the reviewer's pair: p\x07w (6 characters, verbatim) and
# p<BEL>w (escaped). Valid UTF-8, (empty) for "", null and missing, JSON for other types, continuation lines,
# an escaped notes block, an escaped item line, other values. Then refusals with fixed text, nothing echoed.
arm_plaintext_escape() {
  E="$T/pte"; rm -rf "$E"; mkdir -p "$E/items" "$E/files/aaaa1"
  printf '{"category":"LOGIN","title":"Escapes ZZCANARY901","fields":[{"label":"bytes","value":"a\377b c\303"},{"label":"overlong","value":"\300\200 \355\240\200 \364\220\200\200 \365"},{"label":"valid","value":"\303\251 \342\202\254 \360\237\230\200 \\u00e9 \\ud83d\\ude00"},{"label":"controls","value":"\\u0001\\t\\r\\u007f\\u0085\\b\\f\\/\\"\\\\ x\\\\x41"},{"label":"raw controls","value":"bel\007tab\011end"},{"label":"lone","value":"\\udcff \\ud800x"},{"label":"lines","value":"l1\\nl2\\n"},{"label":"","value":""},{"label":"null","value":null},{"label":"missing"},{"label":"number","value":-1.5e3},{"label":"bool","value":true},{"label":"object","value":{"k":"v\\nw","q":"\\"x\\\\","n":[1,null,false]}},{"label":"lab\\nel","value":"x"},{"label":"lit","value":"p\\\\x07w"},{"label":"bel","value":"p\\u0007w"},{"label":"nbsp","value":"a\\u00a0b"},{"label":"zw","value":"a\\u200bb"},{"label":"rlo","value":"a\\u202eb"},{"label":"bom","value":"a\\ufeffb"},{"label":"classes","value":"\\u3000\\u2028\\ufe0f\\ue000\\u0378"},{"label":"emptylit","value":"(empty)"},{"label":"both","value":"c:\\\\dir\\u0007"},{"label":"edges","value":" lead\\ntrail "},{"label":"a : b","value":"c"},{"label":"x\\\\y","value":"z"},{"label":"colon :","value":"b"},{"label":"colon","value":": b"},{"purpose":"NOTES","label":"notesPlain","value":"n1\\n\\u00a0n2"}],"sections":[{"id":"s1"}],"urls":[{"href":"https://example.invalid/e"},{"label":"p","href":"x (primary)"},{"label":"u :","href":"h"},{"label":"u","href":": h"}],"tags":["t\\none","","a, b"],"files":[{"id":"f1","name":"n\\u0000ame"}],"state":"ARCHIVED","extra":{"k":"v\\u0007","n":[2,null]}}' > "$E/items/aaaa1.json"
  echo '{}' > "$E/items/bbbb2.json"; printf '{"category":"MY CAT","title":" t"}' > "$E/items/bbbb3.json"; printf 'synthetic' > "$E/files/aaaa1/f1"
  _fh=$(shasum -a 256 "$E/files/aaaa1/f1" | cut -c1-64); printf 'item_id,file_id,bytes,sha256\naaaa1,f1,9,%s\n' "$_fh" > "$E/ATTACHMENTS.csv"
  sh "$1" plaintext-body "$E" > "$T/pte.out" 2> "$T/pte.err" || { echo "    the plaintext seam failed:"; show "$T/pte.err"; return 1; }
  printf '%s\n' '[item 1] LOGIN  Escapes ZZCANARY901' '\ bytes : a\xffb c\xc3' '\ overlong : \xc0\x80 \xed\xa0\x80 \xf4\x90\x80\x80 \xf5' \
    '  valid : é € 😀 é 😀' '\ controls : \x01\x09\x0d\x7f\xc2\x85\x08\x0c/"\\ x\\x41' '\ raw controls : bel\x07tab\x09end' \
    '\ lone : \xed\xb3\xbf \xed\xa0\x80x' '  lines : l1' '      l2' '      ' '  (empty) : (empty)' '  null : (empty)' '  missing : (empty)' \
    '  number : -1.5e3' '  bool : true' '  object : {"k":"v' '      w","q":"\"x\\","n":[1,null,false]}' '\ lab\x0ael : x' \
    '  lit : p\x07w' '\ bel : p\x07w' '\ nbsp : a\xc2\xa0b' '\ zw : a\xe2\x80\x8bb' '\ rlo : a\xe2\x80\xaeb' '\ bom : a\xef\xbb\xbfb' \
    '\ classes : \xe3\x80\x80\xe2\x80\xa8\xef\xb8\x8f\xee\x80\x80\xcd\xb8' '\ emptylit : \x28empty)' '\ both : c:\\dir\x07' \
    '\ edges : \x20lead' '\     trail\x20' '\ a \x3a b : c' '  x\y : z' '\ colon \x3a : b' '\ colon : \x3a b' '  section "(empty)"' \
    '  url (empty) : https://example.invalid/e' '\ url p : x \x28primary)' '\ url u \x3a : h' '\ url u : \x3a h' '\ tags : t\x0aone, (empty), a\x2c b' \
    '\ notes :' '\   n1' '\   \xc2\xa0n2' "\\ file n\\x00ame : files/aaaa1/f1  (9 B, sha256 $_fh)  [attachment]" \
    '  other values :' '    state : ARCHIVED' '\   extra.k : v\x07' '    extra.n[0] : 2' '' \
    '[item 2] (empty)  (empty)' '' '\[item 3] MY\x20CAT  \x20t' '' '== end (3 items, 1 files) ==' > "$T/pte.want"
  cmp -s "$T/pte.want" "$T/pte.out" || { echo "    not the expected text (synthetic; < expected, > written):"; diff "$T/pte.want" "$T/pte.out" | show; return 1; }
  for c in 'fields|{"fields":"ZZCANARY902"}|item cccc3: fields is not a list' 'dup|{"title":"ZZCANARY903","title":"x"}|item cccc3: a key is repeated' \
           'json|{"title":"ZZCANARY904|item cccc3: not JSON' 'entry|{"urls":["ZZCANARY905"]}|item cccc3: an entry of urls is not an object'; do
    _cb=${c#*|}; printf '%s' "${_cb%|*}" > "$E/items/cccc3.json"
    if sh "$1" plaintext-body "$E" > "$T/pte.out" 2>&1; then echo "    ${c%%|*}: described"; return 1; fi
    grep -qF "★ the plaintext could not be built: ${c##*|} (no value is shown)" "$T/pte.out" && ! grep -q ZZCANARY "$T/pte.out" \
      || { echo "    ${c%%|*}: not refused with the fixed text, or a value echoed:"; show "$T/pte.out"; return 1; }
  done
  rm "$E/items/cccc3.json"; printf 'synthetiX' > "$E/files/aaaa1/f1"
  if sh "$1" plaintext-body "$E" > "$T/pte.out" 2>&1; then echo "    a file that differs from ATTACHMENTS.csv was listed"; return 1; fi
  grep -q 'files/aaaa1/f1 does not match ATTACHMENTS.csv' "$T/pte.out" || { echo "    a changed file: refused for another reason:"; show "$T/pte.out"; return 1; }
  printf 'synthetic' > "$E/files/aaaa1/f1"; printf 'aaaa1,f2,9,%s\n' "$_fh" >> "$E/ATTACHMENTS.csv"
  if sh "$1" plaintext-body "$E" > "$T/pte.out" 2>&1; then echo "    an ATTACHMENTS.csv row no item lists was ignored"; return 1; fi
  grep -q 'ATTACHMENTS.csv lists aaaa1/f2, which no item lists' "$T/pte.out" || { echo "    an unlisted row: refused for another reason:"; show "$T/pte.out"; return 1; }
}
# never published: seal-text (the SEALED.txt builder) never reads it: a package before its round holding a
# canary SEALED-plaintext.txt gives exactly its SEALED.txt, with no canary; open --plaintext leaves
# SEALED.txt as it was; the sealer's README lists it as local only
arm_plaintext_published() {
  arm_dir ptpub
  offline sh "$1" seal Ptp 10 || { echo "    the offline seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in Ptp)
  printf '%s\n' '== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==' 'ZZCANARYSPPUBLISHED' > "$P/SEALED-plaintext.txt"
  "$VT_BROADCAST" seal-text "$P" > "$T/ptpub.txt" 2> "$T/ptpub.err" || { echo "    seal-text failed:"; show "$T/ptpub.err"; return 1; }
  cmp -s "$T/ptpub.txt" "$P/SEALED.txt" && ! grep -q 'ZZCANARYSPPUBLISHED\|SEALED-plaintext\|vault-timelock-plaintext' "$T/ptpub.txt" "$T/ptpub.err" \
    || { echo "    seal-text's text changed with SEALED-plaintext.txt beside it, or carries it"; return 1; }
  grep -q '^  local only         README.txt, MANIFEST.csv, STRUCTURE.txt: never published$' "$P/README.txt" \
    && grep -q '^                     SEALED-plaintext.txt: local only, created by open --plaintext after$' "$P/README.txt" \
    || { echo "    README.txt does not list SEALED-plaintext.txt as local only"; return 1; }
  pt_pkg pub || return 1
  cp "$P/SEALED.txt" "$T/ptpub.sealed"
  pt_open "$1" || { echo "    open --plaintext failed:"; show "$T/out.log"; return 1; }
  cmp -s "$T/ptpub.sealed" "$P/SEALED.txt" && ! grep -q 'ZZCANARY\|SEALED-plaintext' "$P/SEALED.txt" || { echo "    SEALED.txt changed, or names SEALED-plaintext.txt"; return 1; }
}
# hk_open SCRIPT [ARG...]: pt_open with $T/hooknode first on PATH: `node` is then the real node with the
# test-only hook $T/pthook.cjs preloaded (never part of the tool; it reads $T/pthook.conf, logs to
# $T/pthook.log): it records the temp file's mode at creation and its ls mode string at its first write, can
# plant something at the temp name or at SEALED-plaintext.txt, and can pause once the temp file is written
hk_open() { _ho=$1; shift; offline PATH="$T/hooknode:$T/fakebin:$PATH" sh "$_ho" open "$P" --identity "$T/recovery.key" --plaintext "$@"; }
hk_conf() { rm -f "$T/pthook.log" "$T/pthook.ready"; printf '%s\n' "$@" > "$T/pthook.conf"; }
# created safely (SP review m1, m6): in a package dir whose ACL makes every new file readable by everyone
# (file_inherit), under umask 022: the temp file is mode 600 AT CREATION, and at its first write it is
# -rw------- with no ACL (the inherited one stripped first); the final file carries no ACL
arm_plaintext_create() {
  pt_pkg create || return 1
  chmod +a "everyone allow read,file_inherit" "$P" && ls -led "$P" | head -1 | grep -q '^d[-rwx]*+ ' || { echo "    could not give the package dir an inheritable ACL"; return 1; }
  hk_conf
  ( umask 022 && hk_open "$1" ) || { echo "    open --plaintext failed in a dir with an inheritable ACL:"; show "$T/out.log"; chmod -N "$P"; return 1; }
  chmod -N "$P"
  grep -qx 'created mode 600' "$T/pthook.log" || { echo "    the temp file had mode $(sed -n 's/^created mode //p' "$T/pthook.log") at creation, not 600"; return 1; }
  grep -qE '^first-write ls -rw-------@? mode 600$' "$T/pthook.log" || { echo "    at its first write the temp file was not -rw------- without an ACL:"; show "$T/pthook.log"; return 1; }
  [ "$(ls -led "$P/SEALED-plaintext.txt" | wc -l | tr -d ' ')" = 1 ] && ls -led "$P/SEALED-plaintext.txt" | grep -q '^-rw-------@\{0,1\} ' \
    || { echo "    SEALED-plaintext.txt carries an ACL:"; ls -led "$P/SEALED-plaintext.txt" | show; return 1; }
}
# planted at SEALED-plaintext.txt DURING the open (after the precheck, before the file is put in place): a
# file, a directory, a symlink, a FIFO. Without --force: refused (link(2) never writes into or through it),
# the planted entry untouched, no temp file left. With --force: a directory, a symlink or a FIFO is refused;
# a regular file is replaced. Planted at the TEMP name: refused (O_EXCL, O_NOFOLLOW) and left alone.
arm_plaintext_planted() {
  echo target > "$T/pthook.target"
  for h in file dir symlink fifo; do
    pt_pkg "plant-$h" || return 1; hk_conf "plant=$h"
    if hk_open "$1"; then echo "    a $h planted at SEALED-plaintext.txt during the open: written anyway"; return 1; fi
    grep -q 'SEALED-plaintext.txt appeared during this open (a file, directory, symlink or FIFO): not overwritten' "$T/out.log" \
      || { echo "    a $h planted: refused for another reason, or the planted entry was replaced:"; show "$T/out.log"; return 1; }
    case $h in
      file) [ -f "$P/SEALED-plaintext.txt" ] && [ "$(cat "$P/SEALED-plaintext.txt")" = planted ] ;;
      dir) [ -d "$P/SEALED-plaintext.txt" ] && [ -z "$(ls -A "$P/SEALED-plaintext.txt")" ] ;;
      symlink) [ -L "$P/SEALED-plaintext.txt" ] && [ "$(cat "$T/pthook.target")" = target ] ;;
      fifo) [ -p "$P/SEALED-plaintext.txt" ] ;;
    esac || { echo "    a $h planted: the planted entry was replaced, or written into or through"; return 1; }
    [ "$(ls -A "$P" | grep -c '^\.SEALED-plaintext')" = 0 ] || { echo "    a $h planted: a temp file was left"; return 1; }
  done
  for h in dir symlink fifo; do
    pt_pkg "force-$h" || return 1; hk_conf "plant=$h"
    if hk_open "$1" --force; then echo "    --force replaced a $h planted during the open"; return 1; fi
    grep -q 'SEALED-plaintext.txt is not a regular file (a directory, symlink or FIFO is there): not replaced' "$T/out.log" && [ "$(cat "$T/pthook.target")" = target ] \
      && [ "$(ls -A "$P" | grep -c '^\.SEALED-plaintext')" = 0 ] || { echo "    --force over a planted $h: refused for another reason, or the planted entry changed:"; show "$T/out.log"; return 1; }
  done
  pt_pkg force-file || return 1; hk_conf "plant=file"
  hk_open "$1" --force && [ "$(head -1 "$P/SEALED-plaintext.txt")" = '== vault-timelock plaintext: every entry, decrypted (LOCAL ONLY — contains secrets) ==' ] \
    || { echo "    --force over a planted regular file did not replace it:"; show "$T/out.log"; return 1; }
  for h in fifo symlink; do
    pt_pkg "tmp-$h" || return 1; hk_conf "plant-tmp=$h"
    if hk_open "$1"; then echo "    a $h planted at the temp name: written anyway"; return 1; fi
    _tn=$(ls -A "$P" | grep '^\.SEALED-plaintext\.txt\.[0-9]*\.tmp$' || true)
    grep -q 'the temp file name \.SEALED-plaintext\.txt\.[0-9]*\.tmp is taken (something this open did not create: left alone)' "$T/out.log" && [ -n "$_tn" ] \
      && case $h in fifo) [ -p "$P/$_tn" ] ;; *) [ -L "$P/$_tn" ] ;; esac && [ "$(cat "$T/pthook.target")" = target ] && [ ! -e "$P/SEALED-plaintext.txt" ] \
      || { echo "    a $h at the temp name: refused for another reason, removed, or followed:"; show "$T/out.log"; return 1; }
  done
  rm -f "$T/pthook.conf"
}
# a temp file left by an interrupted --plaintext (SP review m3): refused before anything is decrypted, named,
# never shown, never removed by the tool
arm_plaintext_leftover() {
  pt_pkg left || return 1
  printf 'ZZCANARYSPLEFTOVER\n' > "$P/.SEALED-plaintext.txt.4242.tmp"
  if pt_open "$1"; then echo "    written although a leftover temp file may hold plaintext"; return 1; fi
  grep -q "holds .SEALED-plaintext.txt.4242.tmp, a temp file left by an interrupted open --plaintext: it may hold every secret in plain text. Delete it yourself (its content is not shown), then open again. Nothing was opened." "$T/out.log" \
    && ! grep -q ZZCANARY "$T/out.log" && [ ! -e "$P/restored" ] && [ "$(cat "$P/.SEALED-plaintext.txt.4242.tmp")" = ZZCANARYSPLEFTOVER ] && [ ! -e "$P/SEALED-plaintext.txt" ] \
    || { echo "    a leftover temp file: refused for another reason, shown, removed, or something was opened:"; show "$T/out.log"; return 1; }
}
# SIGTERM while the temp file is written (Ctrl-C reaches the shell and node alike): exit 130, the temp file
# removed by the traps, no SEALED-plaintext.txt (SP review m6)
arm_plaintext_signal() {
  pt_pkg sig || return 1; hk_conf pause
  hk_open "$1" &
  _sb=$!; _sw=0
  while [ ! -s "$T/pthook.ready" ] && [ "$_sw" -lt 600 ]; do sleep 0.1; _sw=$((_sw + 1)); done
  [ -s "$T/pthook.ready" ] || { kill "$_sb" 2>/dev/null; wait "$_sb" 2>/dev/null; rm -f "$T/pthook.conf"; echo "    the writer never paused"; show "$T/out.log"; return 1; }
  read -r _np _sp < "$T/pthook.ready"
  [ "$(ls -A "$P" | grep -c '^\.SEALED-plaintext\.txt\.[0-9]*\.tmp$')" = 1 ] || { kill "$_sp" "$_np" 2>/dev/null; wait "$_sb" 2>/dev/null; rm -f "$T/pthook.conf"; echo "    no temp file while the writer paused"; return 1; }
  kill -TERM "$_sp"; kill -TERM "$_np"
  st=0; wait "$_sb" || st=$?
  rm -f "$T/pthook.conf"
  [ "$st" = 130 ] || { echo "    exit status $st after SIGTERM, not 130:"; show "$T/out.log"; return 1; }
  [ "$(ls -A "$P" | grep -c 'SEALED-plaintext')" = 0 ] || { echo "    a temp file was left after SIGTERM:"; ls -A "$P" | show; return 1; }
}
# the two pre-decryption refusals (SP review m6): no SEALED.txt; an unlock-after that disagrees with the
# round file (or two of them). Nothing is decrypted, no file.
arm_plaintext_precheck() {
  pt_pkg nosealed || return 1; rm "$P/SEALED.txt"
  if pt_open "$1"; then echo "    written without SEALED.txt"; return 1; fi
  grep -q '★ --plaintext needs SEALED.txt beside the package' "$T/out.log" && [ ! -e "$P/restored" ] && pt_none \
    || { echo "    no SEALED.txt: refused for another reason, or something was opened:"; show "$T/out.log"; return 1; }
  pt_pkg disagree || return 1; echo $(( $(cat "$P/round") + 1 )) > "$P/round"
  if pt_open "$1"; then echo "    written although SEALED.txt's unlock-after disagrees with the round file"; return 1; fi
  grep -q 'has no single unlock-after line that agrees with the package.s round file' "$T/out.log" && [ ! -e "$P/restored" ] && pt_none \
    || { echo "    an unlock-after that disagrees: refused for another reason, or something was opened:"; show "$T/out.log"; return 1; }
  pt_pkg twolines || return 1; grep '^unlock-after: ' "$P/SEALED.txt" > "$T/pt.ul" && cat "$T/pt.ul" >> "$P/SEALED.txt"
  if pt_open "$1"; then echo "    written although SEALED.txt has two unlock-after lines"; return 1; fi
  grep -q 'has no single unlock-after line' "$T/out.log" && [ ! -e "$P/restored" ] && pt_none || { echo "    two unlock-after lines: refused for another reason:"; show "$T/out.log"; return 1; }
}
# injective rows, as a PROPERTY (SP re-review N1): random texts from an adversarial alphabet (":", a space,
# "\", "x", hex digits, a newline, NBSP, BEL, "(empty)", the separators " : ", ", " and two spaces, "(",
# "(primary)") become field (label, value) pairs, url (label, href) pairs, other values (key, value), section
# labels, notes, item lines (category, title) and tag lists, plus the reviewer's pairs ("colon :", "b") and
# ("colon", ": b"). Through the seam, every row must DECODE back, by the header's rule (a "\" in column 1:
# \\ = a backslash, \xNN = a byte; else verbatim; (empty) = empty) and its first separator, to exactly what was
# written; and no two distinct pairs of one item may print the same row. The generator and decoder are this
# test's own (ptprop.cjs, written here; seeded, so every run checks the same cases).
arm_plaintext_injective() {
  E="$T/ptq"; rm -rf "$E"; mkdir -p "$E/items"
  cat > "$T/ptprop.cjs" <<'FAKE'
const fs = require("fs")
const [mode, dir, arg] = process.argv.slice(2)
let s32 = 74
const rnd = (n) => { s32 ^= s32 << 13; s32 >>>= 0; s32 ^= s32 >>> 17; s32 ^= s32 << 5; s32 >>>= 0; return s32 % n }
const TOK = [":", " ", "\\", "x", "0", "7", "a", "f", "\n", " ", "\u0007", "(empty)", " : ", ", ", "  ", "(", "(primary)", ","]
const str = () => { let t = ""; const n = rnd(6); for (let i = 0; i < n; i++) t += TOK[rnd(TOK.length)]; return t }
const uniq = (ps) => { const seen = new Set(); return ps.filter((q) => { const k = JSON.stringify(q); if (seen.has(k)) return false; seen.add(k); return true }) }
const J = (v) => JSON.stringify(v)
if (mode === "gen") {
  const n = Number(arg)
  const pairs = (fix) => uniq([...fix, ...Array.from({ length: n }, () => [str(), str()])])
  const x = {
    fields: pairs([["colon :", "b"], ["colon", ": b"], ["a :", "b2"], ["a", ": b2"], [":", "x"], ["", ": x"], ["x:", "y"], ["x", ":y"], ["(empty)", ""], ["", "(empty)"], ["p", "p\\x07w"], ["p", "p\u0007w"]]),
    urls: pairs([["u :", "h"], ["u", ": h"], ["u", "x (primary)"], ["u (primary)", "x"]]),
    others: [], sections: uniq([[":"], ["s :"], ...Array.from({ length: n }, () => [str()])]).map((q) => q[0]),
    notes: uniq([[""], [": n"], ...Array.from({ length: n }, () => [str()])]).map((q) => q[0]), heads: [], tags: [],
  }
  const keys = new Set()
  for (const [k, v] of [["k :", "v"], ["k", ": v"], ...Array.from({ length: n }, () => [str(), str()])]) if (!keys.has(k)) { keys.add(k); x.others.push([k, v]) }
  for (let i = 0; i < 300; i++) { x.heads.push([str(), str()]); x.tags.push(Array.from({ length: 1 + rnd(3) }, str)) }
  const w = (id, body) => fs.writeFileSync(dir + "/items/" + id + ".json", body)
  w("p1", "{\"fields\":[" + x.fields.map(([l, v]) => "{\"label\":" + J(l) + ",\"value\":" + J(v) + "}").join(",") + "]}")
  w("p2", "{\"urls\":[" + x.urls.map(([l, h]) => "{\"label\":" + J(l) + ",\"href\":" + J(h) + "}").join(",") + "]}")
  w("p3", "{\"o\":{" + x.others.map(([k, v]) => J(k) + ":" + J(v)).join(",") + "}}")
  w("p4", "{\"sections\":[" + x.sections.map((l) => "{\"label\":" + J(l) + "}").join(",") + "]}")
  w("p5", "{\"fields\":[" + x.notes.map((v) => "{\"purpose\":\"NOTES\",\"label\":\"n\",\"value\":" + J(v) + "}").join(",") + "]}")
  x.heads.forEach(([c, t], i) => w("q" + String(i).padStart(4, "0"), "{\"category\":" + J(c) + ",\"title\":" + J(t) + ",\"tags\":" + J(x.tags[i]) + "}"))
  fs.writeFileSync(dir + "/expected.json", J(x))
  process.exit(0)
}
// check: decode every row of the seam output by the header rule, compare with what was written
const x = JSON.parse(fs.readFileSync(dir + "/expected.json", "utf8"))
const fail = (m) => { process.stdout.write(m + "\n"); process.exit(1) }
function unesc(t, e) {
  if (t === "(empty)") return ""
  if (!e) return t
  const b = []
  for (let i = 0; i < t.length; ) {
    if (t.startsWith("\\\\", i)) { b.push(92); i += 2 }
    else if (t[i] === "\\" && t[i + 1] === "x" && /^[0-9a-f]{2}$/.test(t.slice(i + 2, i + 4))) { b.push(parseInt(t.slice(i + 2, i + 4), 16)); i += 4 }
    else if (t[i] === "\\") fail("a lone backslash in an escaped row: " + J(t))
    else { const c = String.fromCodePoint(t.codePointAt(i)); b.push(...Buffer.from(c, "utf8")); i += c.length }
  }
  return Buffer.from(b).toString("utf8")
}
const items = []
let cur = null
for (const l of fs.readFileSync(arg, "utf8").split("\n")) {
  if (/^\\?\[item [0-9]+\] /.test(l)) { cur = [l]; items.push(cur) }
  else if (l === "" || l.startsWith("== end")) cur = null
  else if (cur) cur.push(l)
}
if (items.length !== 5 + x.heads.length) fail("expected " + (5 + x.heads.length) + " items, found " + items.length)
const lead = (l) => { let i = 1; while (i < l.length && l[i] === " ") i++; return i }
// rows at indent n (a row starts where its text starts at column n + 1; its continuation lines are 4 deeper)
function rows(ls, n) {
  const r = []
  for (const l of ls) {
    if (lead(l) === n && l.length > n) r.push([l])
    else if (r.length && lead(l) >= n + 4) r[r.length - 1].push(l)
    else fail("a line that is neither a row nor a continuation: " + J(l))
  }
  return r.map((g) => { const e = g[0][0] === "\\"; if (g.some((l) => (l[0] === "\\") !== e)) fail("a row whose lines disagree on the marker: " + J(g)); return { e, g, text: g.join("\n") } })
}
// pre: fixed text before the label slot ("url "); sp: the start of the slot itself (an other value path "o.")
function pairsOf(ls, n, pre, sp) {
  return rows(ls, n).map(({ e, g, text }) => {
    let b = g[0].slice(n)
    if (!b.startsWith(pre)) fail("a row without " + J(pre) + ": " + J(g))
    b = b.slice(pre.length)
    const k = b.indexOf(" : ")
    if (k < 0) fail("a row without its separator: " + J(g))
    const lab = unesc(b.slice(0, k), e)
    if (!lab.startsWith(sp)) fail("a label slot without " + J(sp) + ": " + J(g))
    return { text, got: [lab.slice(sp.length), unesc([b.slice(k + 3), ...g.slice(1).map((l) => l.slice(n + 4))].join("\n"), e)] }
  })
}
function same(what, got, want) {
  if (got.length !== want.length) fail(what + ": " + got.length + " rows for " + want.length + " written")
  const seen = new Map()
  got.forEach((r, i) => {
    if (J(r.got) !== J(want[i])) fail(what + " row " + i + " decodes to " + J(r.got) + ", not to the written " + J(want[i]) + ": " + J(r.text))
    if (seen.has(r.text)) fail(what + ": two distinct pairs " + J(want[seen.get(r.text)]) + " and " + J(want[i]) + " print the same row " + J(r.text))
    seen.set(r.text, i)
  })
}
same("fields", pairsOf(items[0].slice(1), 2, "", ""), x.fields)
same("urls", pairsOf(items[1].slice(1), 2, "url ", ""), x.urls)
if (!/^  other values :$/.test(items[2][1] || "")) fail("no other values block")
same("other values", pairsOf(items[2].slice(2), 4, "", "o."), x.others)
const secs = rows(items[3].slice(1), 2).map(({ e, g, text }) => { const b = g[0].slice(2); if (g.length !== 1 || !b.startsWith("section \"") || !b.endsWith("\"")) fail("not a section row: " + J(g)); return { text, got: [unesc(b.slice(9, -1), e)] } })
same("sections", secs, x.sections.map((l) => [l]))
const nb = []
for (const l of items[4].slice(1)) {
  if (lead(l) === 2) nb.push({ e: l[0] === "\\", h: l.slice(2), b: [] })
  else if (nb.length && lead(l) >= 4) nb[nb.length - 1].b.push(l.slice(4))
  else fail("a notes line out of place: " + J(l))
}
same("notes", nb.map((q) => { if (q.h === "notes : (empty)" && q.b.length === 0) return { text: q.h, got: [""] }; if (q.h !== "notes :") fail("not a notes block: " + J(q.h)); return { text: (q.e ? "\\" : " ") + q.h + "\n" + q.b.join("\n"), got: [unesc(q.b.join("\n"), q.e)] } }), x.notes.map((v) => [v]))
items.slice(5).forEach((it, i) => {
  const e = it[0][0] === "\\", m = it[0].slice(e ? 1 : 0).replace(/^\[item [0-9]+\] /, ""), k = m.indexOf("  ")
  if (k < 0) fail("an item line without its separator: " + J(it[0]))
  const got = [unesc(m.slice(0, k), e), unesc(m.slice(k + 2), e)]
  if (J(got) !== J(x.heads[i])) fail("item line " + i + " decodes to " + J(got) + ", not to the written " + J(x.heads[i]) + ": " + J(it[0]))
  const tr = rows(it.slice(1), 2)
  if (tr.length !== 1 || tr[0].g.length !== 1 || !tr[0].g[0].slice(2).startsWith("tags : ")) fail("not one tags row: " + J(it))
  const tg = tr[0].g[0].slice(2 + 7).split(", ").map((t) => unesc(t, tr[0].e))
  if (J(tg) !== J(x.tags[i])) fail("tags " + i + " decode to " + J(tg) + ", not to the written " + J(x.tags[i]) + ": " + J(tr[0].g[0]))
})
process.stdout.write("ok: " + x.fields.length + " fields, " + x.urls.length + " urls, " + x.others.length + " other values, " + x.sections.length + " sections, " + x.notes.length + " notes, " + x.heads.length + " item lines and tag rows decode back; no two distinct pairs share a row\n")
FAKE
  node "$T/ptprop.cjs" gen "$E" 1500 || { echo "    the generator failed"; return 1; }
  sh "$1" plaintext-body "$E" > "$T/ptq.out" 2> "$T/ptq.err" || { echo "    the plaintext seam failed:"; show "$T/ptq.err"; return 1; }
  node "$T/ptprop.cjs" check "$E" "$T/ptq.out" > "$T/ptq.log" 2>&1 || { echo "    rows are not injective (synthetic):"; show "$T/ptq.log"; return 1; }
  cat "$T/ptq.log"
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
  _b=$(date -u +%s); offline TL_TEST_SECONDS= TL_JITTER_SOURCE="$T/jsrc" sh "$1" seal Jit 1h || { echo "    the 1h seal failed:"; show "$T/out.log"; return 1; }; _a=$(date -u +%s)
  R=$(cat "$(pkg_in Jit)/round")
  jitter_round_ok "$R" "$_b" "$_a" 3959 || { echo "    round $R does not include the offset (359 s)"; return 1; }
  grep -q 'requested: 1h (+ random offset up to 6m); offset drawn from TL_JITTER_SOURCE (self-test))' "$T/out.log" \
    && grep -q 'Requested: 1h (+ random offset up to 6m); offset drawn from TL_JITTER_SOURCE (self-test)\.' "$(pkg_in Jit)/README.txt" \
    || { echo "    the banner or README does not give the maximum:"; show "$T/out.log"; return 1; }
  ! grep -q '359' "$(pkg_in Jit)/README.txt" || { echo "    the README prints the draw"; return 1; }
  arm_dir jit0
  _b=$(date -u +%s); offline TL_TEST_SECONDS= sh "$1" seal Jit0 1h --jitter 0 || { echo "    the --jitter 0 seal failed:"; show "$T/out.log"; return 1; }; _a=$(date -u +%s)
  jitter_round_ok "$(cat "$(pkg_in Jit0)/round")" "$_b" "$_a" 3600 || { echo "    --jitter 0 still moved the round"; return 1; }
  grep -q -- '★ --jitter 0: no random offset. The round then gives away the moment of sealing to within 3 s' "$T/out.log" || { echo "    no --jitter 0 warning"; return 1; }
  arm_dir jitbig
  if offline TL_TEST_SECONDS= sh "$1" seal Jitbig 1h --jitter 2h; then echo "    an offset longer than the duration was SEALED"; return 1; fi
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
# lit_vault_ok DIR: the printed manifest check said OK for exactly 3 items and 2 attachments, nothing else
lit_vault_ok() {
  [ "$(grep -c '^items/[0-9a-f]*\.json: OK$' "$1.out")" = 3 ] && [ "$(grep -c '^files/[0-9a-f]*/[0-9a-f]*: OK$' "$1.out")" = 2 ] && ! grep -q 'FAILED' "$1.out" \
    || { echo "    the printed manifest check did not say OK for 3 items and 2 attachments:"; show "$1.out"; return 1; }
}

# ── lane B (2026-10-14): seal --list, SEALED.txt format /2 (each captured file its own age block; the contract is
#    .superpowers/sdd/2026-10-14-vt-decrypt/v2-format.md). Offline (fake op, tle, curl; real age, gzip, awk), synthetic
#    vault only. The default seal staying format /1 is arm_v1_unchanged (plus every format /1 arm above and below).
# v2_index P: P's data key (KEY path, real age) into $T/v2.id; its index decrypted, cut at the layout's index-gzip,
#   gunzipped, into $T/v2.tsv
v2_index() {
  age -d -i "$T/recovery.key" -o "$T/v2.id" "$1/unlock-KEY.age" && age -d -i "$T/v2.id" -o "$T/v2.ibin" "$1/index" || return 1
  head -c "$(sed -n 's/^index-gzip: //p' "$1/layout")" "$T/v2.ibin" | gzip -dc > "$T/v2.tsv"
}
# v2_files P N PADDING: P holds exactly a format /2 file set for N blocks (with unlock-KEY.age; ARMOR when armored), no
#   vault.tar.gz.age; its layout says PADDING; SEALED.txt is format /2, layout per-file, blocks: N, padding: PADDING, its
#   [file] lines unlock-TIME.age, index (gzip= the layout's), b0001 ... bN in order, and it names no pseudonym of the vault
v2_files() {
  _bl=; _i=1; while [ "$_i" -le "$2" ]; do _bl="$_bl $(printf 'b%04d' "$_i")"; _i=$((_i + 1)); done
  _w=$(printf '%s\n' MANIFEST.csv README.txt SEALED.txt STRUCTURE.txt chain-info.json index layout round unlock-KEY.age unlock-TIME.age $_bl | LC_ALL=C sort | tr '\n' ' ')
  _h=$(ls -A "$1" | grep -vx ARMOR | LC_ALL=C sort | tr '\n' ' ')
  [ "$_h" = "$_w" ] || { echo "    the package's files are not a format /2 set for $2 blocks:"; echo "      have: $_h"; echo "      want: $_w"; return 1; }
  _g=$(sed -n 's/^index-gzip: //p' "$1/layout")
  printf 'layout: per-file\npadding: %s\nindex-gzip: %s\n' "$3" "$_g" | cmp -s - "$1/layout" || { echo "    layout is not exactly per-file / padding $3 / index-gzip:"; show "$1/layout"; return 1; }
  [ "$(sed -n 2,3p "$1/SEALED.txt" | tr '\n' ' ')" = 'format: vault-timelock-sealed/2 layout: per-file ' ] && grep -qx "blocks: $2" "$1/SEALED.txt" && grep -qx "padding: $3" "$1/SEALED.txt" \
    || { echo "    SEALED.txt does not say format /2, layout per-file, blocks: $2, padding: $3"; return 1; }
  _f=$(sed -n 's/^\[file \([^ ]*\) bytes=[0-9]* sha256=[0-9a-f]\{64\}\( gzip=[0-9]*\)\{0,1\}\]$/\1/p' "$1/SEALED.txt" | tr '\n' ' ')
  [ "$_f" = "unlock-TIME.age index$_bl " ] && grep -qx "\[file index bytes=[0-9]* sha256=[0-9a-f]\{64\} gzip=$_g\]" "$1/SEALED.txt" \
    || { echo "    SEALED.txt's [file] lines are not unlock-TIME.age, index (gzip=$_g), b0001 ... in order: $_f"; return 1; }
  # paths only inside the encrypted index: no item pseudonym (the local manifest's first column) in SEALED.txt
  for _p in $(tail -n +2 "$1/MANIFEST.csv" | cut -d, -f1); do ! grep -q "$_p" "$1/SEALED.txt" || { echo "    an item id is in SEALED.txt"; return 1; }; done
  ! grep -qE '(items|files)/[0-9a-f]{32}' "$1/SEALED.txt" || { echo "    a vault path is in SEALED.txt"; return 1; }
}
# v2_lit DIR TEXT FIRST LAST: TEXT alone in the new, empty DIR as SEALED.txt, its printed steps FIRST..LAST run exactly as
#   printed (lit_run), with the fake tle that opens (the fake drand: no network) first on PATH
v2_lit() { lit_init "$1" "$2" && ( export PATH="$T/fakebin:$PATH" FAKE_TLE_DECRYPT=open; lit_run "$1" "$3" "$4" ); }
# v2_lit_ok DIR N: the printed steps said OK for unlock-TIME.age, the index, index.tsv and N files, and the manifest check
#   OK for 3 items and 2 attachments
v2_lit_ok() {
  grep -qx 'OK unlock-TIME.age' "$1.out" && grep -qx 'OK index' "$1.out" && grep -qx 'OK index.tsv' "$1.out" \
    && [ "$(grep -cE '^OK (items/[0-9a-f]{32}[.]json|files/[0-9a-f]{32}/[0-9a-f]{32}|MANIFEST[.]csv|ATTACHMENTS[.]csv)$' "$1.out")" = "$2" ] && ! grep -q '^BAD' "$1.out" \
    || { echo "    the printed steps did not say OK for unlock-TIME.age, the index, index.tsv and $2 files:"; show "$1.out"; return 1; }
  lit_vault_ok "$1"
}
# a --list seal (3 items, 2 attachments: 7 blocks; padding none): the format /2 file set and SEALED.txt; the seal says
# what it did (the index audited, 7 blocks, the round trip through the index and every block); README says per-file;
# STRUCTURE.txt binds to the index; the index decrypts (KEY path) to 7 lines of sealed paths; open (KEY path) restores
# and verifies all of it, through the index
arm_v2_seal() {
  arm_dir v2s
  offline sh "$1" seal V2s 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V2s); v2_files "$P" 7 none || return 1
  grep -q '^  audit      the index: 0 operator identifiers, 0 1Password identifiers' "$T/out.log" && grep -q '^  blocks     7 file(s) as 7 block(s) + the index' "$T/out.log" \
    && grep -q '^  unsealed   round-tripped 3/3 items and 2/2 attachments through the real ciphertext (the index and all 7 blocks' "$T/out.log" \
    || { echo "    the seal does not report the index audit, the 7 blocks and the per-block round trip:"; show "$T/out.log"; return 1; }
  grep -q '^Layout: per-file (seal --list; SEALED.txt format vault-timelock-sealed/2)' "$P/README.txt" && grep -q '^  b0001 ... b0007   7 blocks' "$P/README.txt" \
    && ! grep -q 'vault.tar.gz.age   the vault' "$P/README.txt" || { echo "    README.txt does not describe a per-file package"; return 1; }
  _ix=$(sed -n 's/^\[file index bytes=[0-9]* sha256=\([0-9a-f]\{64\}\) gzip=[0-9]*\]$/\1/p' "$P/SEALED.txt")
  grep -qx "binds-to: index sha256=$_ix   (valid for this seal only: the index lists every block)" "$P/STRUCTURE.txt" && ! grep -q ZZCANARY "$P/STRUCTURE.txt" \
    || { echo "    STRUCTURE.txt does not bind to the index digest SEALED.txt carries"; return 1; }
  v2_index "$P" || { echo "    the index did not decrypt (KEY path)"; return 1; }
  [ "$(head -n 1 "$T/v2.tsv")" = vault-timelock-index/1 ] && [ "$(tail -n +2 "$T/v2.tsv" | grep -cE "^b000[1-7]${TAB}(items/[0-9a-f]{32}[.]json|files/[0-9a-f]{32}/[0-9a-f]{32}|MANIFEST[.]csv|ATTACHMENTS[.]csv)${TAB}[0-9]+${TAB}[0-9a-f]{64}${TAB}[0-9]+\$")" = 7 ] \
    || { echo "    the index is not vault-timelock-index/1 with 7 lines of block, sealed path, bytes, sha256, gzip bytes"; return 1; }
  offline sh "$1" open "$P" --identity "$T/recovery.key" || { echo "    open (KEY path) failed:"; show "$T/out.log"; return 1; }
  grep -q '^  blocks     7/7 block(s) opened with the data key' "$T/out.log" && grep -q '3/3 items match' "$T/out.log" && grep -q '2/2 attachments match' "$T/out.log" \
    && grep -q '^  structure ✓ STRUCTURE.txt matches restored/ (items and files) and binds to this index$' "$T/out.log" \
    || { echo "    open did not restore and verify 7 blocks, 3 items, 2 attachments, structure ✓:"; show "$T/out.log"; return 1; }
  [ "$(find "$P/restored" -type f | wc -l | tr -d ' ')" = 7 ] && [ -z "$(find "$P/restored" -type f ! -perm 600)" ] || { echo "    restored/ does not hold the 7 files, mode 600"; return 1; }
}
# the printed steps of a format /2 SEALED.txt, run EXACTLY as printed (awk, sed, base64, shasum, age, head, gunzip; tle is
# the fake drand that opens) in an empty directory holding only the text: padding none, --pad, and --pad --armor all
# recover the vault (every file OK, the manifests' shasum -c OK); step 1's tle line is format /1's, byte for byte
arm_v2_literal() {
  for v in none pad armor; do
    arm_dir "v2lit-$v"
    case $v in none) _fl= ;; pad) _fl=--pad ;; armor) _fl='--pad --armor' ;; esac
    offline sh "$1" seal V2l 10 --list $_fl --recovery-recipient "$RECIP" || { echo "    the --list $_fl seal failed:"; show "$T/out.log"; return 1; }
    v2_lit "$T/v2lit-$v" "$(pkg_in V2l)/SEALED.txt" 1 4 > "$T/v2lit.log" 2>&1 || { echo "    ($v) the printed steps failed:"; show "$T/v2lit.log"; return 1; }
    v2_lit_ok "$T/v2lit-$v" 7 || return 1
    [ "$(literal_steps "$T/v2lit-$v/SEALED.txt" 1 1 | tail -n 1)" = 'env -u NO_PROXY -u no_proxy HTTPS_PROXY=socks5h://127.0.0.1:9050 tle --decrypt --output=identity.key unlock-TIME.age' ] \
      || { echo "    step 1's tle line is not format /1's"; return 1; }
  done
  cp "$(pkg_in V2l)/SEALED.txt" "$T/v2lit-padded.txt"   # (a --pad text for the altered-step controls)
}
# --pad: every block and the index decrypt (KEY path) to exactly their bucket, zero bytes after the gzip stream; without
# --pad, to exactly the gzip stream; every gzip header carries no name and MTIME 0; pad-bucket gives the documented table
arm_v2_pad() {
  for kv in 1=1024 1024=1024 1025=2048 4097=8192 65536=65536 65537=131072 131072=131072 131073=262144 300000=393216; do
    [ "$(sh "$1" pad-bucket "${kv%%=*}")" = "${kv#*=}" ] || { echo "    pad-bucket ${kv%%=*} is not ${kv#*=}"; return 1; }
  done
  for v in pad none; do
    arm_dir "v2pad-$v"
    if [ "$v" = pad ]; then _fl=--pad; _pw=buckets; else _fl=; _pw=none; fi
    offline sh "$1" seal V2p 10 --list $_fl --recovery-recipient "$RECIP" || { echo "    the --list $_fl seal failed:"; show "$T/out.log"; return 1; }
    P=$(pkg_in V2p); v2_files "$P" 7 "$_pw" || return 1
    v2_index "$P" || { echo "    the index did not decrypt"; return 1; }
    _ig=$(sed -n 's/^index-gzip: //p' "$P/layout")
    tail -n +2 "$T/v2.tsv" | { while IFS="$TAB" read -r _b _p _n _h _g; do
        age -d -i "$T/v2.id" -o "$T/v2.blk" "$P/$_b" || { echo "    $_b did not decrypt"; exit 1; }
        _hd=$(head -c 10 "$T/v2.blk" | od -An -tx1 | tr -d ' \n')
        case $_hd in 1f8b08??00000000*) ;; *) echo "    $_b: its gzip header carries an MTIME (header $_hd)"; exit 1 ;; esac
        [ $(( 0x$(printf '%s' "$_hd" | cut -c7-8) & 8 )) = 0 ] || { echo "    $_b: its gzip header carries a file name"; exit 1; }
        _s=$(wc -c < "$T/v2.blk" | tr -d ' '); if [ "$v" = pad ]; then _w=$(sh "$1" pad-bucket "$_g"); else _w=$_g; fi
        [ "$_s" = "$_w" ] && [ "$(tail -c +$(( _g + 1 )) "$T/v2.blk" | tr -d '\000' | wc -c | tr -d ' ')" = 0 ] \
          || { echo "    $_b decrypts to $_s bytes for a gzip stream of $_g ($v: want $_w, zeros after the stream)"; exit 1; }
      done; } || return 1
    _s=$(wc -c < "$T/v2.ibin" | tr -d ' '); if [ "$v" = pad ]; then _w=$(sh "$1" pad-bucket "$_ig"); else _w=$_ig; fi
    [ "$_s" = "$_w" ] || { echo "    the index decrypts to $_s bytes for a gzip stream of $_ig ($v: want $_w)"; return 1; }
  done
  arm_dir v2padonly
  if offline sh "$1" seal V2po 10 --pad; then echo "    --pad without --list was SEALED"; return 1; fi
  grep -q -- '--pad goes with --list only' "$T/out.log" || { echo "    --pad without --list refused for another reason:"; show "$T/out.log"; return 1; }
}
# the block numbers follow the drawn order, not the paths: with TL_ORDER_SOURCE giving descending keys, b0001 is the last
# path in seal order (ATTACHMENTS.csv), b0002 MANIFEST.csv, b0007 the first sorted item or attachment path; the banner
# says the order came from the seam
arm_v2_order() {
  arm_dir v2order; : > "$T/v2order.src"
  _i=9; while [ "$_i" -ge 1 ]; do printf "\\000\\000\\000\\000\\000\\000\\000\\$(printf %03o "$_i")" >> "$T/v2order.src"; _i=$((_i - 1)); done
  offline TL_ORDER_SOURCE="$T/v2order.src" sh "$1" seal V2o 10 --list --recovery-recipient "$RECIP" || { echo "    the seeded --list seal failed:"; show "$T/out.log"; return 1; }
  grep -q 'numbered in a random order (drawn from TL_ORDER_SOURCE, a self-test seam: NOT random)' "$T/out.log" || { echo "    the banner does not name the seam"; return 1; }
  P=$(pkg_in V2o); grep -q 'here drawn from TL_ORDER_SOURCE,$' "$P/README.txt" && grep -q 'a SELF-TEST seam: NOT random (never seal a real vault so)' "$P/README.txt" \
    || { echo "    README.txt does not say the order came from the self-test seam"; return 1; }
  v2_index "$P" || { echo "    the index did not decrypt"; return 1; }
  _first=$(awk -F '\t' 'NR > 1 && $2 ~ /^(items|files)\// { print $2 }' "$T/v2.tsv" | LC_ALL=C sort | head -n 1)
  [ "$(sed -n 2p "$T/v2.tsv" | cut -f1,2)" = "b0001${TAB}ATTACHMENTS.csv" ] && [ "$(sed -n 3p "$T/v2.tsv" | cut -f1,2)" = "b0002${TAB}MANIFEST.csv" ] \
    && [ "$(sed -n 8p "$T/v2.tsv" | cut -f1,2)" = "b0007${TAB}$_first" ] || { echo "    b0001 is not the path the drawn order puts first:"; cut -f1,2 "$T/v2.tsv" | show; return 1; }
  # (fix round 1, minor c) a source whose keys repeat (all zero bytes) refuses before anything is encrypted
  arm_dir v2order0; head -c 72 /dev/zero > "$T/v2order0.src"
  if offline TL_ORDER_SOURCE="$T/v2order0.src" sh "$1" seal V2o0 10 --list; then echo "    SEALED although the order's keys repeat"; return 1; fi
  grep -q "the block order's random keys repeat (TL_ORDER_SOURCE?): REFUSING" "$T/out.log" && [ -z "$(pkg_in V2o0)" ] || { echo "    repeated keys: refused for another reason, or a package was left:"; show "$T/out.log"; return 1; }
}
# the index is audited before anything is encrypted: an operator string found only there (a login name "b0001", the
# first block's name) refuses the --list seal (counts and category only; no package, nothing left); the same vault
# seals without --list (no index)
arm_v2_audit() {
  arm_dir v2aud
  if offline PATH="$(sb)" FAKE_ID_UN=b0001 sh "$1" seal V2a 10 --list; then echo "    SEALED although the index holds the operator's login name"; return 1; fi
  grep -q 'PII/ID audit: [0-9]* hit(s) (categories: login-name) in the index (block, path, bytes, sha256, gzip bytes)' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(pkg_in V2a)" ] && [ -z "$(ls -A "$T/tmp")" ] || { echo "    a package or plaintext was left behind"; return 1; }
  ! grep -q '^  blocks ' "$T/out.log" || { echo "    blocks were reported before the index audit"; return 1; }
  arm_dir v2aud1
  offline PATH="$(sb)" FAKE_ID_UN=b0001 sh "$1" seal V2a 10 || { echo "    the same vault without --list did not seal:"; show "$T/out.log"; return 1; }
}
# flip FILE: its third-from-last byte changed (to that byte + 1, mod 256)
flip() {
  _fo=$(( $(wc -c < "$1") - 3 )); _fb=$(tail -c 3 "$1" | head -c 1 | od -An -tu1 | tr -d ' ')
  printf "\\$(printf %03o $(( (_fb + 1) % 256 )))" | dd of="$1" bs=1 seek="$_fo" conv=notrunc 2>/dev/null
}
# v2_reindex P FILE: P's index replaced by FILE (re-encrypted to P's own data key, $T/v2.id from v2_index; padding none),
#   and P's SEALED.txt rewritten by vt-broadcast seal-text for it: the text an author of a hostile index would publish
v2_reindex() {
  gzip -n -9 -c "$2" > "$T/v2.rgz" && age -r "$(age-keygen -y "$T/v2.id")" -o "$1/index" "$T/v2.rgz" \
    && printf 'layout: per-file\npadding: none\nindex-gzip: %s\n' "$(wc -c < "$T/v2.rgz" | tr -d ' ')" > "$1/layout" \
    && rm -f "$1/SEALED.txt" && "$VT_BROADCAST" seal-text "$1" > "$1/SEALED.txt" 2> "$T/v2.rerr"
}
# (fix round 1, C-1 + I-1) the PRINTED steps against a hostile index (an author controls it): one hostile value in every
# column (block, path, bytes, sha256, gzip bytes; option-, substitution-, arithmetic-, traversal-, control-byte-shaped)
# and the structural shapes (4 or 6 fields, CR, an empty line, a block this text does not carry, a repeated block or
# path), each as the LAST line, so earlier lines are good: the steps, run literally in a new directory, refuse the WHOLE
# index (only "BAD index.tsv line N"), write nothing (no restored/, no canary, nothing beside the directory) and print
# only printable ASCII; and the same text with its index check cut out DOES write restored/ (the arm has teeth)
arm_v2_hostile() {
  arm_dir v2host
  offline sh "$1" seal V2h 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V2h); v2_index "$P" || { echo "    the index did not decrypt"; return 1; }
  cp "$T/v2.tsv" "$T/v2h.good"; _n=$(wc -l < "$T/v2h.good" | tr -d ' ')
  _C="$T/v2h-box/CANARY"; _z=$(printf x | shasum -a 256 | cut -c1-64); _p2=$(sed -n 2p "$T/v2h.good" | cut -f2)   # (line 2's path: a repeat)
  for c in "1=-o$_C" "1=\$(touch $_C)" '1=b9999' '1=b0001' '1=b01' "2=../ZZCANARYV2H" "2=\$(touch $_C)" '2=items/../../ZZCANARYV2H' '2=items//x.json' '2=-rf' \
           '2=items/x.json\033]0;pwned\007\033[2J' "2=$_p2" '3=-1' "3=\$(touch $_C)" '3=1234567890123' "4=$(printf '%s' "$_z" | tr a-f A-F)" "4=\$(touch $_C)" \
           '5=-5' '5=$((1+1))' "5=\$(touch $_C)" '5=0x10' 'nf4' 'nf6' 'cr' 'empty'; do
    case $c in
      nf4) awk -v n="$_n" 'NR == n { sub(/\t[0-9]+$/, "") } 1' "$T/v2h.good" > "$T/v2h.tsv" ;;
      nf6) awk -v n="$_n" 'NR == n { $0 = $0 "\textra" } 1' "$T/v2h.good" > "$T/v2h.tsv" ;;
      cr) awk -v n="$_n" 'NR == n { $0 = $0 "\r" } 1' "$T/v2h.good" > "$T/v2h.tsv" ;;
      empty) { cat "$T/v2h.good"; echo; } > "$T/v2h.tsv" ;;
      *) awk -F '\t' -v OFS='\t' -v n="$_n" -v k="${c%%=*}" -v v="${c#*=}" 'NR == n { $k = v } 1' "$T/v2h.good" > "$T/v2h.tsv" ;;
    esac
    ! cmp -s "$T/v2h.good" "$T/v2h.tsv" || { echo "    the case ($c) changed nothing"; return 1; }
    v2_reindex "$P" "$T/v2h.tsv" || { echo "    could not re-seal the crafted index ($c):"; show "$T/v2.rerr"; return 1; }
    rm -rf "$T/v2h-box" "$T/ZZCANARYV2H"; mkdir "$T/v2h-box"
    if v2_lit "$T/v2h-box/w" "$P/SEALED.txt" 1 4 > "$T/v2h.log" 2>&1; then echo "    a hostile index ($c) was OPENED:"; show "$T/v2h-box/w.out"; return 1; fi
    grep -qE '^BAD index[.]tsv( line [0-9]+)?$' "$T/v2h-box/w.out" && ! grep -q '^OK items/\|^OK files/' "$T/v2h-box/w.out" \
      || { echo "    a hostile index ($c): not refused by the index check:"; show "$T/v2h-box/w.out"; return 1; }
    [ ! -e "$T/v2h-box/w/restored" ] && [ ! -e "$_C" ] && [ ! -e "$T/ZZCANARYV2H" ] && [ ! -e "$T/v2h-box/ZZCANARYV2H" ] \
      && [ "$(ls -A "$T/v2h-box" | tr '\n' ' ')" = 'w w.cmds w.out ' ] && [ "$(ls -A "$T/v2h-box/w" | LC_ALL=C sort | tr '\n' ' ')" = 'SEALED.txt identity.key index index.tsv unlock-TIME.age ' ] \
      || { echo "    a hostile index ($c): something was written:"; ls -A "$T/v2h-box" "$T/v2h-box/w" | show; return 1; }
    [ "$(LC_ALL=C tr -d '\n\040-\176' < "$T/v2h-box/w.out" | wc -c | tr -d ' ')" = 0 ] || { echo "    a hostile index ($c): a byte outside printable ASCII reached the terminal"; return 1; }
  done
  # the teeth: a path with a space on the last line, and the text's index check cut out: restored/ IS written
  awk -F '\t' -v OFS='\t' -v n="$_n" 'NR == n { $2 = "items/x y.json" } 1' "$T/v2h.good" > "$T/v2h.tsv" && v2_reindex "$P" "$T/v2h.tsv" || { echo "    could not re-seal"; return 1; }
  sed 's/( LC_ALL=C awk -F .* SEALED[.]txt index[.]tsv && mkdir restored/( mkdir restored/' "$P/SEALED.txt" > "$T/v2h.cut"
  ! cmp -s "$P/SEALED.txt" "$T/v2h.cut" || { echo "    the index check could not be cut out of the text"; return 1; }
  rm -rf "$T/v2h-box"; mkdir "$T/v2h-box"
  v2_lit "$T/v2h-box/w" "$T/v2h.cut" 1 4 > "$T/v2h.log" 2>&1
  [ -d "$T/v2h-box/w/restored/items" ] || { echo "    without its index check the text still wrote nothing (the arm tests nothing)"; show "$T/v2h-box/w.out"; return 1; }
}
# (fix round 1, minor b) an index whose last line has no trailing newline: open restores and verifies every block (none is
# skipped), and so do the printed steps
arm_v2_nonl() {
  arm_dir v2nonl
  offline sh "$1" seal V2n 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V2n); v2_index "$P" || { echo "    the index did not decrypt"; return 1; }
  printf '%s' "$(cat "$T/v2.tsv")" > "$T/v2n.tsv"; [ "$(tail -c 1 "$T/v2n.tsv" | od -An -tx1 | tr -d ' \n')" != 0a ] || { echo "    the index still ends in a newline"; return 1; }
  v2_reindex "$P" "$T/v2n.tsv" || { echo "    could not re-seal the index"; show "$T/v2.rerr"; return 1; }
  offline sh "$1" open "$P" --identity "$T/recovery.key" || { echo "    open refused an index without a final newline:"; show "$T/out.log"; return 1; }
  grep -q '^  blocks     7/7 block(s) opened' "$T/out.log" && grep -q '3/3 items match' "$T/out.log" && grep -q '2/2 attachments match' "$T/out.log" \
    || { echo "    open skipped the last index line:"; show "$T/out.log"; return 1; }
  v2_lit "$T/v2n-lit" "$P/SEALED.txt" 1 4 > "$T/v2n.log" 2>&1 && v2_lit_ok "$T/v2n-lit" 7 || { echo "    the printed steps skipped the last index line:"; show "$T/v2n.log"; return 1; }
}
# (fix round 1, minor e) open's TIME path on a --list package (the fake drand): locked before the round ("locked until",
# nothing restored), and once it "opens", every block restored and verified through the index
arm_v2_time() {
  arm_dir v2time
  offline sh "$1" seal V2w 10 --list || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V2w)
  if offline sh "$1" open "$P"; then echo "    the TIME path opened before the round"; return 1; fi
  grep -q 'locked until' "$T/out.log" && [ ! -e "$P/restored" ] || { echo "    the TIME path was not refused as locked, or restored/ was written:"; show "$T/out.log"; return 1; }
  offline FAKE_TLE_DECRYPT=open sh "$1" open "$P" || { echo "    the TIME path did not open:"; show "$T/out.log"; return 1; }
  grep -q '^  path       TIME (drand round [0-9]*)$' "$T/out.log" && grep -q '^  blocks     7/7 block(s) opened' "$T/out.log" && grep -q '3/3 items match' "$T/out.log" \
    && grep -q '2/2 attachments match' "$T/out.log" && grep -q '^  structure ✓ .* binds to this index$' "$T/out.log" \
    || { echo "    the TIME path did not restore and verify the 7 blocks:"; show "$T/out.log"; return 1; }
}
# v2_tamper P CASE SCRIPT: a copy of P (in $T/v2t) changed one way; open (KEY path) must refuse it for its reason, and
# leave no restored/
v2_tamper() {
  rm -rf "$T/v2t"; cp -Rp "$1" "$T/v2t"; Q="$T/v2t"
  case $2 in
    block) flip "$Q/b0003"; _why="block b0003 did not open with the data key" ;;
    index) flip "$Q/index"; _why='the data key did not open the index' ;;
    missing) rm "$Q/b0002"; _why="the package's blocks are not exactly the index's: 7 listed, 6 present" ;;
    extra) cp "$Q/b0001" "$Q/b0099"; _why="the package's blocks are not exactly the index's: 7 listed, 8 present" ;;
    swapped) mv "$Q/b0001" "$Q/x" && mv "$Q/b0002" "$Q/b0001" && mv "$Q/x" "$Q/b0002"; _why='★ block b0001 ' ;;
    gzip) _g=$(sed -n 's/^index-gzip: //p' "$Q/layout"); sed -i '' "s/^index-gzip: .*/index-gzip: $(( _g + 1 ))/" "$Q/layout"; _why="the index is not its gzip stream of $(( _g + 1 )) bytes" ;;
    both) cp "$Q/b0001" "$Q/vault.tar.gz.age"; _why='holds both a per-file layout and vault.tar.gz.age' ;;
  esac
  if offline sh "$3" open "$Q" --identity "$T/recovery.key"; then echo "    a $2-tampered package OPENED"; return 1; fi
  grep -q -- "$_why" "$T/out.log" || { echo "    $2: refused for another reason:"; show "$T/out.log"; return 1; }
  [ ! -e "$Q/restored" ] && [ ! -e "$Q/x" ] || { echo "    $2: restored/ (or a stray file) was left"; return 1; }
}
# open refuses a tampered package, for its reason, and leaves no restored/: a changed byte in a block or in the index, a
# missing block, an extra block, two blocks swapped, a wrong index-gzip, a layout beside vault.tar.gz.age
arm_v2_tamper() {
  arm_dir v2tamp
  offline sh "$1" seal V2t 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  for c in block index missing extra swapped gzip both; do v2_tamper "$(pkg_in V2t)" "$c" "$1" || return 1; done
}
# a crafted index (re-encrypted to the package's own data key, KEY path): a path with "..", a repeated block, a line
# that is not 5 fields: open refuses before anything is written, nothing lands outside restored/; a line whose SHA-256
# is not its block's file: refused, restored/ removed
arm_v2_index() {
  arm_dir v2idx; rm -f "$T/escaped"
  offline sh "$1" seal V2i 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  _z=$(printf '%064d' 0)
  for c in "s|${TAB}MANIFEST[.]csv${TAB}|${TAB}../../escaped${TAB}|=malformed or repeated line" "2s|^b0001${TAB}|b0002${TAB}|=malformed or repeated line" \
           "2s|${TAB}[0-9]*\$||=malformed or repeated line" "2s|${TAB}[0-9a-f]\{64\}${TAB}|${TAB}$_z${TAB}|=its file does not match the index (bytes or SHA-256)"; do
    _cw=${c#*=}; c=${c%%=*}
    rm -rf "$T/v2c"; cp -Rp "$(pkg_in V2i)" "$T/v2c"; Q="$T/v2c"
    v2_index "$Q" && sed "$c" "$T/v2.tsv" > "$T/v2.crafted" && ! cmp -s "$T/v2.tsv" "$T/v2.crafted" || { echo "    could not craft the index ($c)"; return 1; }
    gzip -n -9 -c "$T/v2.crafted" > "$T/v2.cgz" && age -r "$(age-keygen -y "$T/v2.id")" -o "$Q/index" "$T/v2.cgz" \
      && printf 'layout: per-file\npadding: none\nindex-gzip: %s\n' "$(wc -c < "$T/v2.cgz" | tr -d ' ')" > "$Q/layout" || { echo "    could not re-encrypt the crafted index"; return 1; }
    if offline sh "$1" open "$Q" --identity "$T/recovery.key"; then echo "    a crafted index ($c) was OPENED"; return 1; fi
    grep -q -- "$_cw" "$T/out.log" || { echo "    crafted index ($c): refused for another reason (want: $_cw):"; show "$T/out.log"; return 1; }
    [ ! -e "$Q/restored" ] && [ ! -e "$T/escaped" ] && [ ! -e "$Q/escaped" ] || { echo "    crafted index ($c): something was written"; return 1; }
  done
}
# a block that does not come back in the seal's round trip (sigbin/age changes the decrypted bytes) refuses the seal,
# naming the block; nothing is left under TMPDIR and no half package
arm_v2_rt() {
  arm_dir v2rt; E="$T/tmp-v2rt"; rm -rf "$E"; mkdir "$E"
  if offline TMPDIR="$E" PATH="$(sb)" FAKE_AGE_V2_RT=1 sh "$1" seal V2r 10 --list; then echo "    SEALED although a block did not round-trip"; return 1; fi
  grep -q 'round-trip FAILED: ★ block b[0-9]* is not its gzip stream of [0-9]* bytes' "$T/out.log" || { echo "    refused for another reason:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$E")" ] && [ -z "$(pkg_in V2r)" ] || { echo "    plaintext or a half package was left behind"; return 1; }
}
# SIGTERM while the blocks are encrypted (sigbin/age signals the seal at b0003): exit 130, nothing under TMPDIR, no half
# package (the gzipped plaintext blocks live in the work dir the traps remove)
arm_v2_signal() {
  arm_dir v2sig; E="$T/tmp-v2sig"; rm -rf "$E"; mkdir "$E"
  st=0; offline TMPDIR="$E" PATH="$(sb)" FAKE_AGE_SIGNAL_V2=TERM sandbox-exec -p "$(no_tmp_writes "$E")" sh "$1" seal V2g 10 --list || st=$?
  [ "$st" = 130 ] || { echo "    exit status $st after SIGTERM, not 130:"; show "$T/out.log"; return 1; }
  [ -z "$(ls -A "$E")" ] && [ -z "$(pkg_in V2g)" ] || { echo "    left under TMPDIR, or a half package, after SIGTERM"; return 1; }
}
# --armor reaches the index and every block (and both unlock files)
arm_v2_armor() {
  arm_dir v2arm
  offline sh "$1" seal V2r 10 --list --armor --recovery-recipient "$RECIP" || { echo "    the --list --armor seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V2r)
  for f in unlock-TIME.age unlock-KEY.age index $(cd "$P" && ls | grep '^b[0-9]'); do
    is_armored "$P/$f" || { echo "    $f is not canonical age ASCII armor"; return 1; }
  done
  [ "$(cat "$P/ARMOR")" = pem ] || { echo "    no ARMOR marker"; return 1; }
}
# the default seal (no --list) is format /1 exactly as before: its file set, SEALED.txt's format line and blocks, the
# README's archive line, and none of the format /2 output
arm_v1_unchanged() {
  arm_dir v1same
  offline sh "$1" seal V1s 10 --recovery-recipient "$RECIP" || { echo "    the default seal failed:"; show "$T/out.log"; return 1; }
  P=$(pkg_in V1s)
  [ "$(ls -A "$P" | LC_ALL=C sort | tr '\n' ' ')" = 'MANIFEST.csv README.txt SEALED.txt STRUCTURE.txt chain-info.json round unlock-KEY.age unlock-TIME.age vault.tar.gz.age ' ] \
    || { echo "    the default package's files changed:"; ls -A "$P" | show; return 1; }
  [ "$(sed -n 2p "$P/SEALED.txt")" = 'format: vault-timelock-sealed/1' ] && [ "$(sed -n 3p "$P/SEALED.txt" | cut -c1-14)" = 'what-this-is: ' ] \
    && [ "$(grep '^\[file ' "$P/SEALED.txt" | cut -d' ' -f2 | tr '\n' ' ')" = 'unlock-TIME.age vault.tar.gz.age ' ] && ! grep -qE '^(layout|blocks|padding): ' "$P/SEALED.txt" \
    || { echo "    SEALED.txt is not format /1 with unlock-TIME.age and vault.tar.gz.age"; return 1; }
  grep -q '^  vault.tar.gz.age   the vault (tar.gz), age-encrypted to a one-time X25519 key$' "$P/README.txt" && ! grep -q 'per-file' "$P/README.txt" \
    && grep -qx "binds-to: vault.tar.gz.age sha256=$(sed -n 's/^\[file vault\.tar\.gz\.age bytes=[0-9]* sha256=\([0-9a-f]\{64\}\)\]$/\1/p' "$P/SEALED.txt")   (valid for this archive only)" "$P/STRUCTURE.txt" \
    || { echo "    README.txt or STRUCTURE.txt is not format /1's"; return 1; }
  ! grep -qE '^  (layout|blocks)  ' "$T/out.log" && ! grep -q 'the index' "$T/out.log" || { echo "    the default seal printed format /2 output:"; show "$T/out.log"; return 1; }
}
# format /1 readers refuse a format /2 text on its format line: core's published-text parser (sealedFiles: what Open
# decrypts; checkPayload: what is published) names payload.sealed-line; and the format /1 open of this tool's own
# SEALED.txt check (--plaintext) refuses a /2 package whose SEALED.txt says /1 and a /1 package whose SEALED.txt says /2
arm_v2_reader() {
  arm_dir v2rd
  offline sh "$1" seal V2d 10 --list --recovery-recipient "$RECIP" || { echo "    the --list seal failed:"; show "$T/out.log"; return 1; }
  _core=$(dirname "$SELF")/packages/core/src/text/payload.ts
  env -i PATH="$PATH" node --input-type=module -e '
    const [core, file] = process.argv.slice(1)
    const { sealedFiles, checkPayload } = await import(core)
    const s = (await import("node:fs")).readFileSync(file, "utf8")
    const t = "vault-timelock/1 unlock=" + /^unlock-after: (\S+)/m.exec(s)[1] + "\nar://" + "A".repeat(43) + "\nsynthetic note\n\n" + s
    let r = "ACCEPTED"
    try { sealedFiles(t) } catch (e) { r = "refused " + e.guardId + ": " + e.message }
    const f = checkPayload(t).issues.find((i) => i.id === "payload.sealed-line")
    process.stdout.write(r + "\n" + (f ? f.message : "no format refusal") + "\n")' "$_core" "$(pkg_in V2d)/SEALED.txt" > "$T/v2rd.out" 2>&1
  grep -q '^refused payload.invalid: not a valid published text: payload.sealed-line' "$T/v2rd.out" && grep -q 'needs exactly one `format:` line' "$T/v2rd.out" \
    || { echo "    core's format /1 parser did not refuse the format /2 text on its format line:"; show "$T/v2rd.out"; return 1; }
}
# open --plaintext (after the round) of a --list package writes the SAME SEALED-plaintext.txt as format /1: the PLAIN vault
# sealed with --keep-item-ids both ways (so its ids, its paths and its order are the same) gives a byte-identical body; the
# header names the index (its digest) as the archive; its own SEALED.txt saying format /1, or no layout line: refused
arm_v2_plaintext() {
  for f in v1 v2; do
    eval "_src=\$PT_$f"; [ -n "$_src" ] || { echo "    no $f PLAIN package was sealed"; return 1; }
    rm -rf "$T/v2pt-$f"; mkdir -p "$T/v2pt-$f"; cp -Rp "$_src" "$T/v2pt-$f/"; eval "_q$f=\$T/v2pt-$f/\$(basename \"\$_src\")"
  done
  for f in v1 v2; do
    eval "Q=\$_q$f"
    offline sh "$1" open "$Q" --identity "$T/recovery.key" --plaintext || { echo "    open --plaintext ($f) failed:"; show "$T/out.log"; return 1; }
  done
  tail -n +7 "$_qv1/SEALED-plaintext.txt" > "$T/v2pt.b1"; tail -n +7 "$_qv2/SEALED-plaintext.txt" > "$T/v2pt.b2"
  [ -s "$T/v2pt.b1" ] && cmp -s "$T/v2pt.b1" "$T/v2pt.b2" || { echo "    the SEALED-plaintext.txt bodies differ (line $(first_diff_line "$T/v2pt.b1" "$T/v2pt.b2"); not shown)"; return 1; }
  [ "$(sed -n 3p "$_qv2/SEALED-plaintext.txt")" = "source: SEALED.txt sha256=$(shasum -a 256 "$_qv2/SEALED.txt" | cut -c1-64)   archive: index sha256=$(shasum -a 256 "$_qv2/index" | cut -c1-64)   structure: ✓" ] \
    && [ "$(sed -n 2p "$_qv2/SEALED-plaintext.txt")" = 'format: vault-timelock-plaintext/1' ] && [ "$(stat -f %Lp "$_qv2/SEALED-plaintext.txt")" = 600 ] \
    || { echo "    the format /2 SEALED-plaintext.txt header is not format /1's with archive: index"; sed -n 1,4p "$_qv2/SEALED-plaintext.txt" | show; return 1; }
  cp "$_qv2/SEALED.txt" "$T/v2pt.sealed"
  for e in 's|^format: vault-timelock-sealed/2$|format: vault-timelock-sealed/1|' '/^layout: per-file$/d'; do
    rm -rf "$_qv2/restored" "$_qv2/SEALED-plaintext.txt"; sed "$e" "$T/v2pt.sealed" > "$_qv2/SEALED.txt"
    ! cmp -s "$T/v2pt.sealed" "$_qv2/SEALED.txt" || { echo "    the edit ($e) changed nothing"; return 1; }
    if offline sh "$1" open "$_qv2" --identity "$T/recovery.key" --plaintext; then echo "    a format /2 package whose SEALED.txt was edited ($e) got a plaintext"; return 1; fi
    grep -q "★ --plaintext: SEALED.txt does not carry this index's SHA-256" "$T/out.log" && [ ! -e "$_qv2/SEALED-plaintext.txt" ] || { echo "    ($e) refused for another reason:"; show "$T/out.log"; return 1; }
  done
}

# ── self-test: the WHOLE pipeline, on a SYNTHETIC vault. No real vault is touched. ───────────
#    Every REAL drand contact below runs under sandbox-exec with B §6.1's profile (TOR_ONLY): the
#    kernel allows exactly one outbound destination, Tor's SOCKS port. The plumbing arms run on
#    fakes, offline; their mutation arms run the same arm on a one-line mutant that must fail.
cmd_selftest() {
  command -v jq  >/dev/null 2>&1 || die "jq required"
  command -v age >/dev/null 2>&1 || die "age required"
  command -v "$TLE" >/dev/null 2>&1 || die "tle required"
  command -v sandbox-exec >/dev/null 2>&1 || die "sandbox-exec required: the real drand contacts run Tor-only"
  SELF=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
  T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
  ok=0
  # ★ every seal below inherits this, so the suite can never write into the REAL data dir; and
  #   every seal's and open's plaintext work dir lands in $T/tmp, checked empty at the end
  export VAULT_TIMELOCK_DIR="$T"
  mkdir -p "$T/tmp"; export TMPDIR="$T/tmp"
  # SEALED.txt (Task S2 §5): every seal here writes it with the repo's own vt-broadcast (the arms run
  # MUTANT copies from $T, beside no broadcast/). VT_CONFINED=1: the wrapper then runs node directly
  # (env -i still): many seals here run inside sandbox-exec already, and macOS refuses a second
  # profile; seal-text and env-names are offline. The wrapper's own sandbox is broadcast's test.
  export VT_BROADCAST="$(dirname "$SELF")/broadcast/bin/vt-broadcast" VT_CONFINED=1

  # ── the DURATION grammar (Task S1 §1, §4): offline, and first, because every seal uses it ──────
  if arm_grammar "$SELF" > "$T/g" 2>&1
  then echo "  OK   DURATION: $(grep -c '^A' "$T/grammar.tsv") accepted forms give their exact seconds; $(grep -c '^R' "$T/grammar.tsv") refused forms are refused for the listed reason"
  else echo "  FAIL DURATION grammar"; sed 's/^/     /' "$T/g"; ok=1; fi
  check "the shared code (die, quicknet constants, the archive scrub flags, iso_of/round_iso/round_of, duration grammar, drand-through-Tor block, tar entry check, verified extraction) is byte-identical in $(basename "$SELF") and timelock-key.sh" \
    arm_same_shared "$SELF" "$(dirname "$SELF")/timelock-key.sh"
  mut_arm zero d arm_grammar "blanking the zero refusal" "'0d' ACCEPTED"
  mut_arm order d arm_grammar "blanking the y-d-h-m-s order check" "'1h1d' ACCEPTED"
  mut_arm cap d arm_grammar "blanking the 100-year cap" "'3155695201s' ACCEPTED"
  if ( OP=/nonexistent sh "$SELF" seal Test 10 20 ) > "$T/two" 2>&1; then echo "  FAIL two durations were accepted"; ok=1
  else grep -q "more than one duration: '10' and '20'" "$T/two" \
       && echo "  OK   two durations are refused, before anything else runs" \
       || { echo "  FAIL two durations refused for the wrong reason"; sed 's/^/     /' "$T/two"; ok=1; }; fi

  # ── the fake op: SYNTHETIC data only, and ONLY the documented op CLI 2.x forms this tool calls
  #    (docs, never a real op run):
  #      op item list --vault V --include-archive --format json
  #      op item get <itemID> --format json --reveal --include-archive
  #        JSON keys as https://www.1password.dev/cli/item-template-json shows them (id, title,
  #        version, vault, category, last_edited_by, created_at, updated_at, sections[id,label],
  #        fields[id, section{id,label}, type, purpose, label, value]), fields[].reference as
  #        https://www.1password.dev/cli/secret-reference-syntax describes, files[] (id, name, size,
  #        content_path, section{id}) as https://www.1password.dev/connect/api-reference/get-vault-item-by-id
  #      op read --out-file <path> op://<vaultID>/<itemID>/<fileID>
  #        (https://www.1password.dev/cli/reference/commands/read; ids in place of names per the
  #        secret-reference-syntax page). It refuses an existing --out-file (no overwrite).
  #      op document get <itemID> --vault <vaultID> --include-archive --out-file <path>
  #        (https://www.1password.dev/cli/reference/management-commands/document: an ITEM id;
  #        "--out-file won't overwrite an existing file"; --include-archive finds archived Documents)
  #    Anything else exits 2. Item A: a LOGIN with a custom section, a custom field, a tag and a FILE
  #    ATTACHMENT (non-Document); B: a plain LOGIN; C: a DOCUMENT item with its one file. Every
  #    identifier type of the documented shape appears with a distinctive synthetic value.
  #    ★ STRUCTURE.txt canaries (Task S3 §4): EVERY title, label, value, href, file name, section label
  #    and tag contains ZZCANARY<n> (attachment bytes too); STRUCTURE.txt must hold none of them.
  #    OP_FIXTURE_SHAPES=1 adds F: an UNKNOWN category, an UNKNOWN field type, an unknown purpose, an
  #    EMPTY password, a field with no value, an object value, a section with fields and an empty one,
  #    two urls (one primary) and two tags.
  #    Failure modes: OP_FIXTURE_FAILFILE (op read writes the file, then exits 1), _NOFILE (exit 0,
  #    nothing written), _SHORTFILE (one byte short, exit 0), _DOCFAIL (document get exits 1).
  #    FAKE_OP_LOG: one line per call, "op <cmd> <subcmd>" (no arguments, no values).
  cat > "$T/op" <<'FAKE'
#!/bin/sh
V=synthvault0000000000000001; VN=SyntheticVaultNameX; M=SYNTHMEMBER000000000000001
A=synthitema0000000000000001; B=synthitemb0000000000000002; C=synthitemc0000000000000003
S=synthsection00000000000001; F=synthfield0000000000000001; U=synthurl000000000000000001
FA=synthfilea0000000000000001; FC=synthfilec0000000000000001
# OP_FIXTURE_ARCHIVED=doc adds D, an ARCHIVED Document item; =att adds E, an ARCHIVED login with an
# attachment (op read documents no --include-archive: its fetch fails here)
D=synthitemd0000000000000004; E=synthiteme0000000000000005; FD=synthfiled0000000000000001; FE=synthfilee0000000000000001
# OP_FIXTURE_SHAPES=1 adds G (STRUCTURE.txt's shapes), with two sections and four non-built-in fields
G=synthitemg0000000000000006; GS1=synthsectiong000000000001; GS2=synthsectiong000000000002
GF1=synthfieldg00000000000001; GF2=synthfieldg00000000000002; GF3=synthfieldg00000000000003; GF4=synthfieldg00000000000004
# OP_FIXTURE_PLAIN=1 lists A B C G and H (SEALED-plaintext.txt's field kinds): an empty password, a multi-line
# custom field, a section with an OTP, a concealed value holding an INVALID UTF-8 byte and a multi-line one,
# a note with newlines, a tab and a control character, two urls (one primary), two tags; and keys outside the
# format's rows (SP review m5): an SSH key's OpenSSH form (ssh_formats), a password history, additional_information,
# state, an unknown nested key
H=synthitemh0000000000000007; HS=synthsectionh000000000001
HF1=synthfieldh00000000000001; HF2=synthfieldh00000000000002; HF3=synthfieldh00000000000003; HF4=synthfieldh00000000000004; HF5=synthfieldh00000000000005
CD='%PDF-synthetic archived document bytes for item d ZZCANARY405'
CE='synthetic attachment bytes for archived item e ZZCANARY507'
CA='synthetic attachment bytes for item a ZZCANARY113
second line'
CC='%PDF-synthetic document bytes for item c ZZCANARY305'
[ -z "${FAKE_OP_LOG:-}" ] || echo "op $1 $2" >> "$FAKE_OP_LOG"
meta() { printf '"version":7,"vault":{"id":"%s","name":"%s"},"last_edited_by":"%s","created_at":"2021-03-04T05:06:07Z","updated_at":"2022-04-05T06:07:08Z"' "$V" "$VN" "$M"; }
# login ID TAG N [extra fields JSON] [sections JSON] [files JSON] [urls JSON] [extra keys JSON]: values
# carry TAG, never the id; title, labels and values carry ZZCANARY<N>01..<N>05
login() {
  printf '{"id":"%s","title":"Synthetic login %s ZZCANARY%s01",%s,"category":"LOGIN","sections":[%s],"fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username ZZCANARY%s02","value":"u-%s-ZZCANARY%s03","reference":"op://%s/%s/username"},{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password ZZCANARY%s04","value":"s3cr3t-%s-ZZCANARY%s05","reference":"op://%s/%s/password"}%s],"urls":[%s],"files":[%s]%s}\n' \
    "$1" "$2" "$3" "$(meta)" "${5:-}" "$3" "$2" "$3" "$V" "$1" "$3" "$2" "$3" "$V" "$1" "${4:-}" "${7:-}" "${6:-}" "${8:-}"
}
size() { printf '%s' "$1" | wc -c | tr -d ' '; }
case "$1 $2" in
  "item list")
    case ${OP_FIXTURE_ARCHIVED:-} in
      doc) printf '[{"id":"%s"},{"id":"%s"},{"id":"%s"},{"id":"%s"}]\n' "$A" "$B" "$C" "$D" ;;
      att) printf '[{"id":"%s"},{"id":"%s"},{"id":"%s"},{"id":"%s"}]\n' "$A" "$B" "$C" "$E" ;;
      *) if [ "${OP_FIXTURE_BADID:-0}" = 1 ]; then printf '[{"id":"%s"},{"id":"%s"},{"id":"a.c"}]\n' "$A" "$B"
         elif [ "${OP_FIXTURE_SHAPES:-0}" = 1 ]; then printf '[{"id":"%s"},{"id":"%s"},{"id":"%s"},{"id":"%s"}]\n' "$A" "$B" "$C" "$G"
         elif [ "${OP_FIXTURE_PLAIN:-0}" = 1 ]; then printf '[{"id":"%s"},{"id":"%s"},{"id":"%s"},{"id":"%s"},{"id":"%s"}]\n' "$A" "$B" "$C" "$G" "$H"
         else printf '[{"id":"%s"},{"id":"%s"},{"id":"%s"}]\n' "$A" "$B" "$C"; fi ;;
    esac ;;
  "item get")
    if [ "${OP_FIXTURE_CONCEALED:-0}" = "1" ]; then
      # the --reveal failure mode: right shape, blank values
      printf '{"id":"%s","category":"LOGIN",%s,"fields":[{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password ZZCANARY901","value":""}],"files":[]}\n' "$3" "$(meta)"
    elif [ "$3" = "$A" ]; then
      login "$A" a 1 ",{\"id\":\"$F\",\"section\":{\"id\":\"$S\",\"label\":\"Synthetic Section ZZCANARY108\"},\"type\":\"STRING\",\"label\":\"custom ZZCANARY106\",\"value\":\"synthetic custom value ZZCANARY107\",\"reference\":\"op://$V/$A/$S/$F\"}" \
        "{\"id\":\"$S\",\"label\":\"Synthetic Section ZZCANARY108\"}" \
        "{\"id\":\"$FA\",\"name\":\"ZZCANARY109-synthetic-attachment.txt\",\"size\":$(size "$CA"),\"content_path\":\"v1/vaults/$V/items/$A/files/$FA/content\",\"section\":{\"id\":\"$S\"}}" \
        "{\"id\":\"$U\",\"label\":\"website ZZCANARY110\",\"primary\":true,\"href\":\"https://example.invalid/login/ZZCANARY111\"}" \
        ",\"tags\":[\"ZZCANARY112-tag\"]"
    elif [ "$3" = "$B" ]; then
      if [ "${OP_FIXTURE_HOLLOW:-0}" = "1" ]; then printf '{"id":"%s","category":"LOGIN",%s,"fields":[],"files":[]}\n' "$B" "$(meta)"
      elif [ "${OP_FIXTURE_IDINNOTE:-0}" = "1" ]; then
        # a note that mentions another item's UUID inside a longer value: a 1Password id in the payload
        login "$B" b 2 ",{\"id\":\"notesPlain\",\"type\":\"STRING\",\"purpose\":\"NOTES\",\"label\":\"notesPlain ZZCANARY206\",\"value\":\"see $A for the other login ZZCANARY207\"}"
      elif [ "${OP_FIXTURE_NOID:-0}" = "1" ]; then login "$B" b 2 | sed 's/^{"id":/{"uuid":/'   # the id under another key
      else login "$B" b 2; fi
    elif [ "$3" = "$C" ]; then
      if [ "${OP_FIXTURE_MIXED:-0}" = "1" ]; then
        # ordinary: a login saved with a username and no password
        printf '{"id":"%s","category":"LOGIN",%s,"fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username ZZCANARY306","value":"u-c-ZZCANARY307"},{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password ZZCANARY308","value":""}],"files":[]}\n' "$C" "$(meta)"
      else
        printf '{"id":"%s","title":"Synthetic document ZZCANARY301","category":"DOCUMENT",%s,"fields":[{"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain ZZCANARY302","value":"synthetic document note ZZCANARY303","reference":"op://%s/%s/notesPlain"}],"files":[{"id":"%s","name":"ZZCANARY304-synthetic-document.pdf","size":%s,"content_path":"v1/vaults/%s/items/%s/files/%s/content"}]}\n' \
          "$C" "$(meta)" "$V" "$C" "$FC" "$(size "$CC")" "$V" "$C" "$FC"
      fi
    elif [ "$3" = "$D" ]; then
      printf '{"id":"%s","title":"Synthetic archived document ZZCANARY401","category":"DOCUMENT","state":"ARCHIVED",%s,"fields":[{"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain ZZCANARY402","value":"synthetic archived note ZZCANARY403"}],"files":[{"id":"%s","name":"ZZCANARY404-synthetic-archived.pdf","size":%s,"content_path":"v1/vaults/%s/items/%s/files/%s/content"}]}\n' \
        "$D" "$(meta)" "$FD" "$(size "$CD")" "$V" "$D" "$FD"
    elif [ "$3" = "$E" ]; then
      login "$E" e 5 "" "" "{\"id\":\"$FE\",\"name\":\"ZZCANARY506-synthetic-archived-attachment.txt\",\"size\":$(size "$CE"),\"content_path\":\"v1/vaults/$V/items/$E/files/$FE/content\"}" | sed 's/^{/{"state":"ARCHIVED",/'
    elif [ "$3" = "$G" ]; then
      printf '{"id":"%s","title":"Synthetic shapes ZZCANARY601",%s,"category":"ZZCANARY602_CATEGORY","sections":[{"id":"%s","label":"Shapes Section ZZCANARY603"},{"id":"%s","label":"Empty Section ZZCANARY604"}],"fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username ZZCANARY605","value":"u-g-ZZCANARY606"},{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password ZZCANARY607","value":""},{"id":"%s","section":{"id":"%s","label":"Shapes Section ZZCANARY603"},"type":"ZZCANARY608_TYPE","label":"odd type ZZCANARY609","value":"odd value ZZCANARY610"},{"id":"%s","section":{"id":"%s","label":"Shapes Section ZZCANARY603"},"type":"PHONE","purpose":"ZZCANARY611","label":"phone ZZCANARY612","value":"phone ZZCANARY613"},{"id":"%s","type":"MONTH_YEAR","label":"expiry ZZCANARY614"},{"id":"%s","type":"MENU","label":"menu ZZCANARY615","value":{"choice":"ZZCANARY616"}}],"urls":[{"label":"one ZZCANARY617","primary":true,"href":"https://example.invalid/ZZCANARY618"},{"label":"two ZZCANARY619","href":"https://example.invalid/ZZCANARY620"}],"tags":["ZZCANARY621-tag","ZZCANARY622-tag"],"files":[]}\n' \
        "$G" "$(meta)" "$GS1" "$GS2" "$GF1" "$GS1" "$GF2" "$GS1" "$GF3" "$GF4"
    elif [ "$3" = "$H" ]; then
      XB=$(printf '\377')   # one byte that is not UTF-8, raw in the JSON text
      printf '{"id":"%s","title":"Synthetic plain h ZZCANARY801",%s,"category":"LOGIN","sections":[{"id":"%s","label":"Security ZZCANARY802"}],"fields":[{"id":"username","type":"STRING","purpose":"USERNAME","label":"username ZZCANARY803","value":"u-h-ZZCANARY804"},{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password ZZCANARY805","value":"","password_details":{"strength":"TERRIBLE","history":["old ZZCANARY829"]}},{"id":"%s","type":"STRING","label":"answer ZZCANARY806","value":"line one ZZCANARY807\\nline two ZZCANARY808\\n"},{"id":"%s","type":"SSHKEY","label":"private key ZZCANARY826","value":"-----BEGIN PRIVATE KEY-----\\nPKCS8 ZZCANARY827\\n-----END PRIVATE KEY-----","ssh_formats":{"openssh":{"value":"-----BEGIN OPENSSH PRIVATE KEY-----\\nOPENSSH ZZCANARY828\\n-----END OPENSSH PRIVATE KEY-----"}}},{"id":"%s","section":{"id":"%s","label":"Security ZZCANARY802"},"type":"OTP","label":"one-time password ZZCANARY809","value":"otpauth://totp/Synthetic:h?secret=ZZCANARY810&issuer=Synthetic"},{"id":"%s","section":{"id":"%s","label":"Security ZZCANARY802"},"type":"CONCEALED","label":"recovery code ZZCANARY811","value":"rc-ZZCANARY812-%s-end"},{"id":"%s","section":{"id":"%s","label":"Security ZZCANARY802"},"type":"CONCEALED","label":"recovery codes ZZCANARY813","value":"code-1 ZZCANARY814\\ncode-2 ZZCANARY815"},{"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain ZZCANARY816","value":"first line ZZCANARY817\\nsecond\\tline ZZCANARY818\\nbell \\u0007 here ZZCANARY819"}],"urls":[{"label":"website ZZCANARY820","primary":true,"href":"https://example.invalid/h/ZZCANARY821"},{"label":"backup ZZCANARY822","href":"https://example.invalid/h2/ZZCANARY823"}],"tags":["ZZCANARY824-tag","second ZZCANARY825"],"files":[],"additional_information":"u-h ZZCANARY830","state":"ARCHIVED","unknown_extra":{"note":"ZZCANARY831","n":3}}\n' \
        "$H" "$(meta)" "$HS" "$HF4" "$HF5" "$HF1" "$HS" "$HF2" "$HS" "$XB" "$HF3" "$HS"
    else echo "[ERROR] fake op: no item $3" >&2; exit 1; fi ;;
  "read --out-file")
    out=$3; ref=$4
    if [ $# -eq 4 ] && [ "$ref" = "op://$V/$E/$FE" ]; then echo "[ERROR] fake op read: \"$E\" isn't an item (archived; op read documents no --include-archive)" >&2; exit 1; fi
    [ $# -eq 4 ] && [ "$ref" = "op://$V/$A/$FA" ] || { echo "fake op read: not the documented form for a known file" >&2; exit 2; }
    [ ! -e "$out" ] || { echo "fake op read: $out exists" >&2; exit 1; }
    [ "${OP_FIXTURE_NOFILE:-0}" != 1 ] || exit 0
    if [ "${OP_FIXTURE_SHORTFILE:-0}" = 1 ]; then printf '%s' "$CA" | head -c $(( $(size "$CA") - 1 )) > "$out"; exit 0; fi
    printf '%s' "$CA" > "$out"
    # a downloaded file carries Spotlight's xattr on macOS: the archive scrub must keep it out
    xattr -w com.apple.metadata:kMDItemWhereFroms 'https://example.invalid/synthetic-download' "$out" 2>/dev/null || true
    [ "${OP_FIXTURE_FAILFILE:-0}" != 1 ] || { echo "[ERROR] fake op read: connection reset (synthetic)" >&2; exit 1; } ;;
  "document get")
    # the script's form: document get <item> --vault <vault> --include-archive --out-file <path>; an
    # ARCHIVED Document (D) is found only with --include-archive (the documented flag)
    [ $# -eq 8 ] && { [ "$3" = "$C" ] || [ "$3" = "$D" ]; } && [ "$4" = --vault ] && [ "$5" = "$V" ] && [ "$7" = --out-file ] \
      || { echo "fake op document get: not the documented form for a Document item" >&2; exit 2; }
    [ "$6" = --include-archive ] || [ "$3" != "$D" ] || { echo "[ERROR] fake op document get: \"$D\" isn't a document (archived; no --include-archive)" >&2; exit 1; }
    [ "$6" = --include-archive ] || { echo "fake op document get: unexpected flag $6" >&2; exit 2; }
    [ ! -s "$8" ] || { echo "fake op document get: $8 exists" >&2; exit 1; }
    [ "${OP_FIXTURE_DOCFAIL:-0}" != 1 ] || { echo "[ERROR] fake op document get: failed (synthetic)" >&2; exit 1; }
    if [ "$3" = "$D" ]; then printf '%s' "$CD" > "$8"; else printf '%s' "$CC" > "$8"; fi ;;
  *) echo "fake op: undocumented call $1 $2" >&2; exit 2 ;;
esac
FAKE
  chmod +x "$T/op"
  make_fakes
  # sigbin/age: the REAL age, plus a hook on the seal's round-trip decrypt (-o .../rt/rt.tar.gz):
  # FAKE_AGE_SIGNAL sends that signal to the seal; FAKE_AGE_FAIL_RT makes the decrypt fail
  mkdir -p "$T/sigbin"
  cat > "$T/sigbin/age" <<FAKE
#!/bin/sh
# FAKE_AGE_UNRELATED=open|header: the seal's decrypt with an UNRELATED key "succeeds", or answers
# with something other than "no identity matched"
case "\$*" in *"/unrelated.key"*)
  case \${FAKE_AGE_UNRELATED:-} in
    open) exit 0 ;;
    header) echo "age: error: failed to read header: parsing age header: unexpected intro (fake)" >&2; exit 1 ;;
  esac ;;
esac
"$(command -v age)" "\$@"; st=\$?
case "\$*" in *"/rt/rt.tar.gz"*)
  if [ -n "\${FAKE_AGE_SIGNAL:-}" ]; then kill -"\$FAKE_AGE_SIGNAL" "\$PPID"; fi
  if [ "\${FAKE_AGE_FAIL_RT:-0}" = 1 ]; then exit 1; fi ;;
esac
# (lane B, seal --list) FAKE_AGE_V2_RT=1: a block decrypted by v2_restore (-o .../v2.blk) gains one byte; FAKE_AGE_SIGNAL_V2:
# that signal to the seal when it encrypts block b0003 (from .../v2/gz/b0003)
case "\$*" in *"/v2.blk "*)
  if [ "\${FAKE_AGE_V2_RT:-0}" = 1 ]; then o=; p=; for a; do [ "\$p" != -o ] || o=\$a; p=\$a; done; printf x >> "\$o"; fi ;;
esac
case "\$*" in *"/v2/gz/b0003")
  if [ -n "\${FAKE_AGE_SIGNAL_V2:-}" ]; then kill -"\$FAKE_AGE_SIGNAL_V2" "\$PPID"; fi ;;
esac
exit \$st
FAKE
  # sigbin/tar: the REAL tar; FAKE_TAR_EXCLUDE=<pattern> leaves matching entries out of every call
  # (an archive that silently lost its attachments: the round trip must notice)
  cat > "$T/sigbin/tar" <<FAKE
#!/bin/sh
# FAKE_TAR_PLAIN=1: a tar that ignores the extraction hardening (drops the four --no-* flags)
if [ "\${FAKE_TAR_PLAIN:-0}" = 1 ]; then
  for a; do shift; case \$a in --no-mac-metadata|--no-xattrs|--no-acls|--no-fflags) ;; *) set -- "\$@" "\$a" ;; esac; done
fi
if [ -n "\${FAKE_TAR_EXCLUDE:-}" ]; then exec "$(command -v tar)" --exclude "\$FAKE_TAR_EXCLUDE" "\$@"; fi
exec "$(command -v tar)" "\$@"
FAKE
  # sigbin/grep, id, jq: the REAL tools, except: FAKE_GREP_FAIL=1 makes the audit's pattern search
  # (-o ... -f) fail like an unreadable file (exit 2); FAKE_ID_UN=<name> is `id -un`; FAKE_JQ_EMPTY_S=1
  # makes the audit's identifier extraction yield nothing (a jq / op JSON shape fault);
  # FAKE_JQ_STRUCT_DROP=1 makes STRUCTURE.txt's program lose its first top-level field row (a generator
  # that miscounts: the MANIFEST count assertion must notice)
  cat > "$T/sigbin/grep" <<FAKE
#!/bin/sh
if [ "\${FAKE_GREP_FAIL:-0}" = 1 ]; then case " \$* " in *" -o "*" -f "*) echo "grep: read error (fake)" >&2; exit 2 ;; esac; fi
exec "$(command -v grep)" "\$@"
FAKE
  cat > "$T/sigbin/id" <<FAKE
#!/bin/sh
if [ -n "\${FAKE_ID_UN:-}" ] && [ "\$*" = -un ]; then echo "\$FAKE_ID_UN"; exit 0; fi
exec "$(command -v id)" "\$@"
FAKE
  cat > "$T/sigbin/jq" <<FAKE
#!/bin/sh
if [ "\${FAKE_JQ_EMPTY_S:-0}" = 1 ]; then case "\$*" in *'out("item-id")'*) exit 0 ;; esac; fi
if [ "\${FAKE_JQ_STRUCT_DROP:-0}" = 1 ]; then case "\$*" in *structure_rows*) "$(command -v jq)" "\$@" | awk '!d && /^  field / { d = 1; next } { print }'; exit \$? ;; esac; fi
exec "$(command -v jq)" "\$@"
FAKE
  # sigbin/shasum: FAKE_SHASUM=empty prints nothing (exit 0), =fail exits 127; sigbin/rm: FAKE_RM_FAIL=1
  # refuses to remove a restored/ extraction (a tree that cannot be removed)
  cat > "$T/sigbin/shasum" <<FAKE
#!/bin/sh
case \${FAKE_SHASUM:-} in empty) exit 0 ;; fail) echo "shasum: not found (fake)" >&2; exit 127 ;; esac
exec "$(command -v shasum)" "\$@"
FAKE
  cat > "$T/sigbin/rm" <<FAKE
#!/bin/sh
if [ "\${FAKE_RM_FAIL:-0}" = 1 ]; then case "\$*" in */restored) echo "rm: Operation not permitted (fake)" >&2; exit 1 ;; esac; fi
exec "$(command -v rm)" "\$@"
FAKE
  chmod +x "$T/sigbin/age" "$T/sigbin/tar" "$T/sigbin/grep" "$T/sigbin/id" "$T/sigbin/jq" "$T/sigbin/shasum" "$T/sigbin/rm"
  # hooknode (Task SP review m1, m2, m6): a `node` that is the real node with the TEST-ONLY hook pthook.cjs
  # preloaded (--require; the tool runs node under env -i, so the hook reads its orders from $T/pthook.conf
  # beside it): "created mode" of the temp file and its "first-write ls" mode string are logged to
  # $T/pthook.log; plant=file|dir|symlink|fifo plants that at SEALED-plaintext.txt once the temp file is
  # written and fsynced, plant-tmp=fifo|symlink at the temp name just before it is created; pause writes
  # "<node pid> <parent pid>" to $T/pthook.ready and waits 30 s (a signal can then be sent)
  mkdir -p "$T/hooknode"
  printf '#!/bin/sh\nexec "%s" --require "%s" "$@"\n' "$(command -v node)" "$T/pthook.cjs" > "$T/hooknode/node"
  chmod +x "$T/hooknode/node"
  cat > "$T/pthook.cjs" <<'FAKE'
const fs = require("fs"), path = require("path"), cp = require("child_process")
const T = path.dirname(__filename)
const conf = fs.existsSync(T + "/pthook.conf") ? fs.readFileSync(T + "/pthook.conf", "utf8").split("\n") : []
const has = (k) => conf.includes(k)
const log = (s) => fs.appendFileSync(T + "/pthook.log", s + "\n")
const isTmp = (p) => typeof p === "string" && /[/][.]SEALED-plaintext[.]txt[.][0-9]+[.]tmp$/.test(p)
const plant = (p, how) => {
  if (how === "dir") fs.mkdirSync(p)
  else if (how === "symlink") fs.symlinkSync(T + "/pthook.target", p)
  else if (how === "fifo") cp.execFileSync("/usr/bin/mkfifo", [p])
  else if (how === "file") fs.writeFileSync(p, "planted\n")
}
const oOpen = fs.openSync, oWrite = fs.writeSync, oFsync = fs.fsyncSync
let tmp = null, tfd = -1, wrote = false, done = false
fs.openSync = function (p, ...r) {
  if (!isTmp(p)) return oOpen.call(fs, p, ...r)
  for (const h of ["fifo", "symlink"]) if (has("plant-tmp=" + h)) plant(p, h)
  const fd = oOpen.call(fs, p, ...r)
  tmp = p; tfd = fd
  log("created mode " + (fs.fstatSync(fd).mode & 0o777).toString(8))
  return fd
}
fs.writeSync = function (fd, ...r) {
  if (fd === tfd && !wrote) { wrote = true; log("first-write ls " + cp.execFileSync("/bin/ls", ["-ld", tmp]).toString().split(" ")[0] + " mode " + (fs.fstatSync(fd).mode & 0o777).toString(8)) }
  return oWrite.call(fs, fd, ...r)
}
fs.fsyncSync = function (fd) {
  const v = oFsync.call(fs, fd)
  if (fd === tfd && !done) {
    done = true
    for (const h of ["file", "dir", "symlink", "fifo"]) if (has("plant=" + h)) plant(path.dirname(tmp) + "/SEALED-plaintext.txt", h)
    if (has("pause")) { fs.writeFileSync(T + "/pthook.ready", process.pid + " " + process.ppid + "\n"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 30000) }
  }
  return v
}
FAKE
  age-keygen -o "$T/recovery.key" 2>"$T/rp"
  RECIP=$(grep -oE 'age1[a-z0-9]+' "$T/rp" | head -1)

  # ── TWO REAL SEALS through Tor, under the Tor+loopback sandbox: one binary, one --armor (Task S1 §2,
  #    §4, §6). Both carry a recovery recipient, and a 60-second horizon so the TIME path is
  #    reachable inside the test. A seal that succeeds here reached drand with no direct path.
  for v in Test TestA; do
    if [ "$v" = TestA ]; then fl=--armor; else fl=; fi
    if ( cd "$T" && OP="$T/op" TLE="$TLE" TL_TEST_SECONDS=60 sandbox-exec -p "$TOR_LOOP" \
         sh "$SELF" seal "$v" 10 --recovery-recipient "$RECIP" $fl ) >"$T/log-$v" 2>&1 \
       && grep -q 'drand      through Tor' "$T/log-$v"
    then echo "  OK   SEAL (${fl:-binary}), REAL drand through Tor under the Tor+loopback sandbox: 3-item synthetic vault, both unlock paths"
    else echo "  FAIL SEAL (${fl:-binary})"; sed 's/^/       /' "$T/log-$v"; ok=1; fi
  done
  PKG=$(ls -d "$T"/1password-Test-timelock-* 2>/dev/null | head -1)
  PKA=$(ls -d "$T"/1password-TestA-timelock-* 2>/dev/null | head -1)
  # Task SP: the PLAIN vault (items A B C G H) sealed offline NOW with a 30 s horizon, so that its round has
  # passed when the SEALED-plaintext.txt arms run much later (they open copies of it)
  arm_dir ptsrc; PT_SRC=
  if offline OP_FIXTURE_PLAIN=1 TL_TEST_SECONDS=30 sh "$SELF" seal Plain 10 --recovery-recipient "$RECIP"; then PT_SRC=$(pkg_in Plain)
  else echo "  FAIL the PLAIN vault (SEALED-plaintext.txt's fixture) did not seal"; show "$T/out.log"; ok=1; fi

  # every arm below is on packages whose payload holds a known canary
  if [ -f "$PKG/round" ] && [ -f "$PKA/round" ]; then
    # ── the format: binary without --armor (as before), PEM-armored with it ──────────────────
    check "without --armor all 3 .age files are binary (age-encryption.org/v1), no ARMOR file" arm_binary_pkg "$PKG"
    check "with --armor all 3 .age files are PEM-armored age in 64 columns, and ARMOR says pem" arm_armored_pkg "$PKA"

    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      grep -rq 's3cr3t' "$P/MANIFEST.csv" "$P/README.txt" 2>/dev/null \
        && { echo "  FAIL PII ($L): a secret reached the manifest or the README"; ok=1; } \
        || echo "  OK   PII ($L): no secret in MANIFEST.csv or README.txt"
    done
    # STRUCTURE.txt (Task S3) beside each real package: mode 600, no canary, and bound to the digest
    # SEALED.txt carries for vault.tar.gz.age (node's de-armoring there; the tool's here)
    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      _sh=$(sed -n 's/^\[file vault\.tar\.gz\.age bytes=[0-9]* sha256=\([0-9a-f]\{64\}\)\]$/\1/p' "$P/SEALED.txt")
      if [ -n "$_sh" ] && grep -qx "binds-to: vault.tar.gz.age sha256=$_sh   (valid for this archive only)" "$P/STRUCTURE.txt" \
         && ! grep -q ZZCANARY "$P/STRUCTURE.txt" && [ "$(stat -f %Lp "$P/STRUCTURE.txt")" = 600 ] && [ "$(grep -c '^item ' "$P/STRUCTURE.txt")" = 3 ]
      then echo "  OK   STRUCTURE.txt ($L): mode 600, 3 items, no ZZCANARY, bound to the vault.tar.gz.age digest SEALED.txt carries (the decoded binary)"
      else echo "  FAIL STRUCTURE.txt ($L)"; ok=1; fi
    done
    # the horizon is the round's exact UTC time + the round + the duration as typed (Task S1 §1)
    RW=$(round_iso "$(cat "$PKG/round")")
    if grep -q "SEALED UNTIL $RW\$" "$PKG/README.txt" \
       && grep -q "^Unlocks $RW (UTC), when drand publishes round $(cat "$PKG/round")\. Requested: 10 (years); overridden by TL_TEST_SECONDS=60" "$PKG/README.txt" \
       && grep -q "opens      $RW  (drand round $(cat "$PKG/round"); requested: 10 (years)" "$T/log-Test" \
       && grep -q 'drand contacted    through Tor only' "$PKG/README.txt"
    then echo "  OK   README and banner give the exact UTC unlock ($RW), the round, 'requested: 10 (years)', and 'through Tor only'"
    else echo "  FAIL the horizon text"; sed -n '1,14p' "$PKG/README.txt" | sed 's/^/       /'; ok=1; fi

    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      PW=$(round_iso "$(cat "$P/round")")
      # ── KEY path works NOW, before the round ──────────────────────────────────────────────
      if ( cd "$T" && TLE="$TLE" sh "$SELF" open "$P" --identity "$T/recovery.key" ) >"$T/k" 2>&1 \
         && grep -q '3/3 items match' "$T/k" && grep -q '2/2 attachments match' "$T/k" && grep -q '^  structure ✓ ' "$T/k"
      then echo "  OK   KEY path ($L) opens BEFORE the round, and all 3 item and 2 attachment digests verify; structure ✓ (STRUCTURE.txt rebuilt and equal)"
      else echo "  FAIL KEY path ($L)"; sed 's/^/       /' "$T/k"; ok=1; fi
      rm -rf "$P/restored"

      # ── TIME path must REFUSE right now (drand through Tor, under the Tor-only sandbox) ───
      if ( cd "$T" && TLE="$TLE" sandbox-exec -p "$TOR_ONLY" sh "$SELF" open "$P" ) >"$T/t1" 2>&1
      then echo "  FAIL TIME path ($L) opened before its round — nothing is locked"; ok=1
      elif grep -q "locked until $PW (UTC), drand round $(cat "$P/round")" "$T/t1"
      then echo "  OK   TIME path ($L) refuses before its round, saying: locked until $PW (UTC)"
      else echo "  FAIL TIME path ($L) refused for the wrong reason"; sed 's/^/       /' "$T/t1"; ok=1; fi
    done

    # ── ★ the LITERAL REHEARSAL, part 1 (Task S2 §5): each package's SEALED.txt ALONE in an empty
    #    directory; its printed steps 1-2 (cut, check) run exactly as printed; its printed tle step,
    #    before the round, through Tor, refuses "too early" and leaves the EMPTY file it warns about
    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      if lit_init "$T/lit-$L" "$P/SEALED.txt" && lit_run "$T/lit-$L" 1 2 > "$T/lit.log" 2>&1 \
         && [ "$(grep -c '^OK ' "$T/lit-$L.out")" = 2 ] && grep -q '^OK unlock-TIME.age$' "$T/lit-$L.out" && grep -q '^OK vault.tar.gz.age$' "$T/lit-$L.out" \
         && lit_early "$T/lit-$L" 3 identity.key >> "$T/lit.log" 2>&1
      then echo "  OK   LITERAL ($L): SEALED.txt alone; its printed steps 1-2 cut out both blocks and verify both; its printed tle step says 'too early' before the round and leaves an empty identity.key, as it warns"
      else echo "  FAIL LITERAL ($L) before the round"; show "$T/lit.log"; ok=1; fi
    done

    # ── wait for the later round (the clock, no network), then BOTH must OPEN ───────────────
    R=$(cat "$PKG/round"); [ "$(cat "$PKA/round")" -le "$R" ] || R=$(cat "$PKA/round")
    echo "  ..   waiting for round $R ($(round_iso "$R"))"; wait_round "$R"
    # ── ★ the LITERAL REHEARSAL, part 2: the printed steps 3-6 (tle through Tor under TOR_ONLY,
    #    age, tar, shasum -c) must recover the vault: every item and attachment digest says OK
    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      if lit_run "$T/lit-$L" 3 6 "$TOR_ONLY" > "$T/lit.log" 2>&1 && lit_vault_ok "$T/lit-$L" >> "$T/lit.log" 2>&1
      then echo "  OK   LITERAL ($L): after the round, its printed steps 3-6 (tle through Tor, age, tar, shasum -c) recover the vault: 3 items and 2 attachments OK"
      else echo "  FAIL LITERAL ($L) after the round"; show "$T/lit.log"; ok=1; fi
    done
    # ...and ONE altered printed step makes it fail (the arm runs what the text prints, nothing else)
    for m in "cut|s/{ f = \$2; next }/{ f = \"\"; next }/" "open|s/-o vault.tar.gz vault.tar.gz.age/-o vault.tgz vault.tar.gz.age/"; do
      sed "${m#*|}" "$PKG/SEALED.txt" > "$T/lit-mut.txt"
      if cmp -s "$PKG/SEALED.txt" "$T/lit-mut.txt"; then echo "  FAIL MUTANT literal/${m%%|*}: the alteration changed nothing"; ok=1
      elif lit_init "$T/lit-mut" "$T/lit-mut.txt" && lit_run "$T/lit-mut" 1 6 "$TOR_ONLY" > "$T/lit.log" 2>&1 && lit_vault_ok "$T/lit-mut" >> "$T/lit.log" 2>&1
      then echo "  FAIL MUTANT literal/${m%%|*} SURVIVED: the altered text still recovered the vault"; ok=1
      else echo "  OK   MUTANT literal/${m%%|*} killed: altering the printed $( [ "${m%%|*}" = cut ] && echo 'step 1 (awk)' || echo 'step 4 (age -o)' ) makes the literal rehearsal FAIL (it passes unaltered, above)"; fi
    done
    for P in "$PKG" "$PKA"; do
      if [ "$P" = "$PKA" ]; then L=armored; else L=binary; fi
      n=0   # drand may publish a little late: "locked" is retried, nothing else is
      until ( cd "$T" && TLE="$TLE" sandbox-exec -p "$TOR_ONLY" sh "$SELF" open "$P" --plaintext ) >"$T/t2" 2>&1 \
            || ! grep -q 'locked until' "$T/t2" || [ $n -ge 5 ]; do n=$((n+1)); sleep 3; done
      # (--plaintext, Task SP: after the round, the real TIME path also writes SEALED-plaintext.txt)
      if grep -q '3/3 items match' "$T/t2" && grep -q '2/2 attachments match' "$T/t2" && grep -q '^  structure ✓ ' "$T/t2" \
         && grep -q "^  plaintext  $P/SEALED-plaintext.txt  " "$T/t2" && [ "$(stat -f %Lp "$P/SEALED-plaintext.txt")" = 600 ] \
         && sed -n 3p "$P/SEALED-plaintext.txt" | grep -q '   structure: ✓$' && grep -qx '== end (3 items, 2 files) ==' "$P/SEALED-plaintext.txt"
      then echo "  OK   TIME path ($L) opens AFTER its round (drand through Tor), and all 3 item and 2 attachment digests verify; structure ✓; --plaintext wrote SEALED-plaintext.txt (mode 600, 3 items, 2 files)"
      else echo "  FAIL TIME path ($L) after the round"; sed 's/^/       /' "$T/t2"; ok=1; fi

      # ── a corrupted item must be CAUGHT by the manifest check ─────────────────────────────
      # ★ Tamper the MANIFEST, not the extraction: `open` re-extracts and would overwrite any
      #   edit to items/, so tampering there tests nothing. My first version did exactly that and
      #   reported a false PASS-shaped FAIL until this arm was corrected.
      rm -rf "$P/restored"
      sed -i '' '2s/^\([^,]*\),[0-9a-f]\{64\}/\1,0000000000000000000000000000000000000000000000000000000000000000/' "$P/MANIFEST.csv"
      if ( cd "$T" && TLE="$TLE" sh "$SELF" open "$P" --identity "$T/recovery.key" ) >"$T/c" 2>&1; then
        echo "  FAIL tampering ($L) was NOT caught"; sed 's/^/       /' "$T/c"; ok=1
      else
        grep -q 'failed verification' "$T/c" \
          && echo "  OK   a tampered item ($L) is caught by the digest check" \
          || { echo "  FAIL refused for the wrong reason ($L)"; sed 's/^/       /' "$T/c"; ok=1; }
      fi
    done
  else echo "  FAIL no packages to test"; ok=1
  fi

  # ── --armor reaches EVERY .age writer: offline seals on this script and on three mutants, each
  #    dropping --armor from ONE age/tle call (Task S1 §4)
  check "--armor (fake tle/curl, offline): every .age is armored, ARMOR says pem" arm_armor "$SELF"
  mut_arm armor-payload 's/ \$ARMOR_FLAG//' arm_armor "dropping --armor from the payload's age call" "vault.tar.gz.age is not canonical age ASCII armor"
  mut_arm armor-time 's/ \$ARMOR_FLAG//' arm_armor "dropping --armor from the TIME path's tle call" "unlock-TIME.age is not canonical age ASCII armor"
  mut_arm armor-key 's/ \$ARMOR_FLAG//' arm_armor "dropping --armor from the KEY path's age call" "unlock-KEY.age is not canonical age ASCII armor"

  # ── drand ONLY through Tor (R40, Task S1 §6): fakes log every call, offline ────────────────
  check "every curl and tle call (seal and open) went to socks5h://drand.<minute>:x@127.0.0.1:9050, NO_PROXY=* and a decoy proxy notwithstanding" arm_routes "$SELF"
  mut_arm curl-proxy 's/ --proxy "\$(drand_proxy)"//' arm_routes "dropping --proxy from curl" "curl DIRECT"
  mut_arm tle-proxy 's/ HTTPS_PROXY="\$_tp" https_proxy="\$_tp"//' arm_routes "dropping HTTPS_PROXY from tle's environment" "tle decrypt DIRECT"
  mut_arm status-proxy 's/ --proxy "\$(drand_proxy)"//' arm_routes "dropping --proxy from the HTTP 425 check" "curl DIRECT"
  mut_arm armor-time/pin 's/ --network="http:\/\/127.0.0.1:\$INFO_PORT"//' arm_routes "letting tle fetch the chain info itself again" "did NOT use the pinned loopback chain info"
  mut_arm tle-proxy/noproxy 's/ -u NO_PROXY -u no_proxy//' arm_routes "leaving NO_PROXY in tle's environment" "TOR-with-NO_PROXY"
  check "--clearnet is the one bypass: every call direct, and the banner and README say so" arm_clearnet "$SELF"
  check "Tor down (its SOCKS port unreachable): refused before any drand call and before the vault is read" arm_tor_down "$SELF"
  mut_arm tor-preflight d arm_tor_down "blanking the Tor preflight" "SEALED with Tor unreachable"
  check "quicknet pinned: a wrong hash, genesis_time, period, public_key or schemeID from a mirror is refused" arm_pin "$SELF"
  check "the REAL tle (loopback only): it refuses a hash-invalid info, but ACCEPTS a hash-valid one with another scheme; so tle is served the pinned info" arm_tle_pinning "$SELF"
  mut_arm pin 's/|| die /|| true /' arm_pin "disabling the quicknet pin" "SEALED"
  check "the LOCAL negative control refuses a round inside the 5-round margin (no drand decrypt asked)" arm_local_control "$SELF"
  mut_arm local-control 's/|| die /|| true /' arm_local_control "disabling the local round check" "SEALED"
  check "drand's control: a TIME file that OPENS NOW is refused and removed" arm_drand_control "$SELF"
  mut_arm drand-control 's/then die /then true /' arm_drand_control "disabling the 'opens now' refusal" "refused for another reason"
  check "any drand answer but 'too early' fails closed: refused, no package" arm_drand_reason "$SELF"
  mut_arm drand-reason 's/\*) die /*) true /' arm_drand_reason "accepting a non-'too early' answer" "SEALED although"
  check "the relay must answer HTTP 425 for the round: 200, 500 or no answer (000) refuses, saying which" arm_drand_425 "$SELF"
  mut_arm drand-425 's/|| die /|| true /' arm_drand_425 "accepting any HTTP status" "SEALED although drand answered HTTP 200"
  check "a network error from tle (a slow circuit) is retried, then drand's answer counts" arm_retry "$SELF"
  check "an UNRELATED key must get 'no identity matched': decrypting with it, or another answer, refuses" arm_no_identity "$SELF"
  mut_arm no-identity 's/then die /then true /' arm_no_identity "accepting a payload an unrelated key opens (the reason check below then refuses: no 'no identity matched')" "open refused for another reason"
  mut_arm no-identity-reason 's/\*) die /*) true /' arm_no_identity "accepting any failure of the unrelated key" "SEALED although an unrelated key got: header"
  check "open after the round: tle's 'too early' is reported as a fetch failure, not a lock (F-17)" arm_open_passed "$SELF"
  mut_arm open-passed d arm_open_passed "dropping the passed-round check" "reported as locked"

  # ── plaintext hygiene (Task S1 §5; audit K20, SA-N10) ──────────────────────────────────────
  check "SIGTERM during the round-trip: exit 130, NOTHING left under TMPDIR, no half package" arm_interrupt "$SELF"
  check "SIGINT during the round-trip: the same" arm_interrupt_int "$SELF"
  check "SIGHUP during the round-trip: the same (a closed terminal)" arm_interrupt_hup "$SELF"
  mut_arm trap-signal d arm_interrupt "blanking the INT/TERM trap" "not 130"
  mut_arm work-tmpdir 's/mktemp -d "[^"]*"/mktemp -d/' arm_interrupt "a bare mktemp -d (macOS ignores TMPDIR then)" "not 130"
  check "a FAILED round-trip: refused, nothing left under TMPDIR, no half package" arm_rt_failure "$SELF"
  mut_arm trap-exit d arm_rt_failure "blanking the EXIT trap" "left under TMPDIR after a failure"
  check "the package dir is 0700 under umask 022" arm_pkg_mode "$SELF"
  mut_arm pkg-mode 's/mkdir -m 700 "\$PKG"/mkdir "$PKG"/' arm_pkg_mode "creating the package dir without -m 700" "not 700"
  check "open without MANIFEST.csv beside the package verifies against restored/MANIFEST.csv and says so" arm_manifest_inside "$SELF"
  mut_arm manifest-inside d arm_manifest_inside "blanking the sealed-manifest fallback" "not verified against the sealed manifest"
  check "a data dir that is a symlink is refused; nothing is written through it" arm_out_symlink "$SELF"
  mut_arm out-symlink d arm_out_symlink "blanking the symlinked-data-dir refusal" "SEALED through a symlinked data dir"

  # ── open never follows a planted symlink (commit security review of 827e4ed) ───────────────
  check "a planted restored symlink (to a directory, or dangling): open refuses; its target is untouched" arm_restored_symlink "$SELF"
  mut_arm restored-fresh 's/mkdir -m 700 "\$DIR\/restored"/mkdir -p "$DIR\/restored"/' arm_restored_symlink "creating restored with mkdir -p again" "the directory it points at CHANGED"
  check "a vault archive with a symlink entry: refused with the reason, nothing extracted" arm_vault_tar_type "$SELF"
  mut_arm tar-type 's/|| die /|| true /' arm_vault_tar_type "blanking the listing's entry-type check (the on-disk check then refuses instead)" "refused for another reason"
  check "a vault archive with a ../x entry: refused with the reason, nothing written outside" arm_vault_tar_path "$SELF"
  mut_arm tar-path 's/|| die /|| true /' arm_vault_tar_path "blanking the path check (bsdtar's own default then refuses '..')" "refused for another reason"
  check "a vault archive with a HARDLINK entry: refused with the reason" arm_vault_tar_hard "$SELF"
  check "a vault archive with an ABSOLUTE-path entry: refused with the reason; its target untouched" arm_vault_tar_abs "$SELF"

  # ── fix round 1 (Task S1 review): untrusted package text, a missing TIME file ──────────────
  check "a round file that is not a round number is printed as '(invalid round file)', never raw" arm_round_text "$SELF"
  mut_arm round-text d arm_round_text "printing the round file raw" "printed raw"
  check "a manifest item id outside [a-z0-9]+ is refused before it becomes a path or is printed" arm_manifest_id "$SELF"
  mut_arm manifest-id d arm_manifest_id "dropping the item-id check" "refused for another reason"
  check "the TIME path with no unlock-TIME.age refuses and says why (no silent exit 1)" arm_time_file "$SELF"
  mut_arm time-file d arm_time_file "dropping the unlock-TIME.age check" "refused without saying why"

  # ── Task S2 §6: the random offset (seeded draws through the seam; offline seals) ────────────
  check "the random offset: default max min(24h, L/10); 120 seeded draws are exact and within [0, max]; rejected values are redrawn" arm_jitter_draws "$SELF"
  check "a 1h seal's round includes the drawn offset, the outputs print only its maximum; --jitter 0 warns and adds none; --jitter above the duration is refused" arm_jitter_seal "$SELF"
  mut_arm jitter 's/ + J//' arm_jitter_seal "dropping the offset from the target" "does not include the offset"

  # ── Task S2 §2: no metadata of the sealing account in the archive (offline, decrypted) ─────────
  check "the decrypted archive: gzip MTIME 0 and no name; no login name, no xattr records, no ._ entries; owner 0/0 nobody; mtimes 2000-01-01Z, modes 600/700" arm_scrub "$SELF"
  mut_arm scrub/owner 's/ --uid 0 --gid 0 --uname nobody --gname nobody//' arm_scrub "dropping the owner override" "the login name occurs"
  mut_arm scrub/xattr 's/--format ustar --no-mac-metadata --no-xattrs/--no-mac-metadata/' arm_scrub "dropping ustar and --no-xattrs" "xattr records in the archive"
  mut_arm gzip 's/gzip -n -9/gzip -9/' arm_scrub "gzip without -n" "gzip header MTIME is not 0"
  mut_arm normalize 's/touch -h -t 200001010000/true/' arm_scrub "skipping the mtime normalisation" "mtime is not 2000-01-01T00:00:00Z"
  mut_arm normalize/tz 's/env TZ=UTC0 //' arm_scrub "normalising mtimes in LOCAL time" "mtime is not 2000-01-01T00:00:00Z"

  # ── S2 safety review: extraction verified ON DISK; chain info parsed as JSON (offline) ────────
  check "an AppleDouble '._y' symlink that tar -tv lists as a regular file: open refuses on the ON-DISK check, removes the extraction, the canary untouched" arm_ad_sym "$SELF"
  mut_arm disk-type d arm_ad_sym "dropping the on-disk entry-type check" "an AppleDouble-merged symlink was EXTRACTED"
  check "AppleDouble ACL/xattr members (on a file, on the extraction root): --no-mac-metadata drops them; nothing on disk carries an xattr or ACL" arm_ad_acl "$SELF"
  mut_arm xtract 's/ --no-mac-metadata//' arm_ad_acl "extracting without --no-mac-metadata" "open refused the AppleDouble"
  check "a tar that ignores the flags and applies the ACL: the on-disk attribute check refuses and removes the extraction" arm_ad_attr "$SELF"
  mut_arm disk-attr d arm_ad_attr "dropping the on-disk xattr/ACL check" "an extraction carrying an ACL was accepted"
  check "drand chain info with a repeated key is refused (decoy first or last); a good one is stored and served as jq -cS bytes" arm_pin_dup "$SELF"
  mut_arm pin-dup 's/|| die /|| true /' arm_pin_dup "dropping the repeated-key refusal" "with a repeated key (dupfirst) was SEALED"

  # ── S2 review, fix round 1 (offline) ─────────────────────────────────────────────────────────
  check "the audit's grep failing (exit 2) refuses the seal" arm_audit_grep "$SELF"
  mut_arm audit-grep 's/|| die /|| true /' arm_audit_grep "reading a failed grep as 0 hits" "SEALED although the audit's grep failed"
  check "a 3-char login is searched (whole word), a 5-char one in the archive is found, a 2-char one refuses unless --allow-short-operator-strings" arm_audit_short "$SELF"
  mut_arm audit-short 's/|| die /|| true /' arm_audit_short "accepting a login too short to search" "SEALED with a login too short to search"
  check "an empty identifier set (a jq / JSON shape fault) refuses" arm_audit_floor "$SELF"
  mut_arm audit-floor 's/|| die /|| true /' arm_audit_floor "dropping the identifier floor" "SEALED with an empty identifier set"
  check "an item id with no pseudonym refuses (never mapped to itself)" arm_pseudo_strict "$SELF"
  mut_arm pseudo-strict 's/|| die /|| true /' arm_pseudo_strict "mapping an unknown id to nothing (the floor then refuses instead)" "refused for another reason"
  check "open: a manifest listing attachments with no ATTACHMENTS.csv does not report success" arm_open_att_missing "$SELF"
  mut_arm open-att-missing 's/|| die /|| true /' arm_open_att_missing "skipping the missing-ATTACHMENTS.csv check" "open reported success with no ATTACHMENTS.csv"
  check "open: an item whose attachment rows differ from its file_count does not report success" arm_open_att_count "$SELF"
  mut_arm open-att-count 's/|| die /|| true /' arm_open_att_count "skipping the per-item attachment count" "open reported success with an attachment row missing"
  check "an archived Document is fetched with --include-archive; an archived item's attachment refuses, saying why" arm_archived "$SELF"

  # ── S2 re-review, fix round 2 (offline; the m0 corpus through real age) ─────────────────────
  check "INFO_PINNED is canonical and its fields hash to CHAIN" arm_info_pinned "$SELF"
  check "chain info: a 2nd document, a case-variant key, a case-folding key, an unknown key refuse; reordered is fine; chain-info.json is INFO_PINNED" arm_pin_exact "$SELF"
  mut_arm pin-one 's/|| die /|| true /' arm_pin_exact "dropping the one-value check" "a chain info with multidoc was SEALED"
  mut_arm pin/fields 's/\. == \$w/.schemeID == $w.schemeID/' arm_pin_exact "comparing fields instead of the whole value" "a chain info with casekey was SEALED"
  check "a mode-000 directory hiding a merged symlink: refused on disk, the extraction gone; a mode-000 dir with a mode-000 file opens readable" arm_m0 "$SELF"
  mut_arm xv-chmod 's/find "\$2" -type d -exec chmod u+rwx {} \\; \&\& find "\$2" -type f -exec chmod u+rw {} + ||/true ||/' arm_m0 "skipping the owner rwx before the walk (the walk then fails closed)" "refused for another reason"
  check "a refused extraction that cannot be removed is reported, naming the path" arm_xv_gone "$SELF"
  mut_arm xv-gone d arm_xv_gone "dropping the removal check" "an extraction that could not be removed was not reported"
  check "shasum printing nothing, or failing: refused before encryption, no package" arm_sha_seal "$SELF"
  mut_arm sha-format 's/|| die /|| true /' arm_sha_seal "accepting an empty digest" "SEALED with shasum empty"
  check "open: an empty digest in the sealed MANIFEST refuses" arm_open_digest "$SELF"
  mut_arm open-digest 's/|| die /|| true /' arm_open_digest "accepting a malformed digest (the mismatch then refuses)" "refused for another reason"
  check "an item id that is not 26 [a-z0-9] refuses, without printing it" arm_item_id "$SELF"
  mut_arm item-id 's/|| die /|| true /' arm_item_id "dropping the item-id shape check" "refused for another reason"
  check "a 2-char vault name: the audit line says it was not searched (no value)" arm_vault_short "$SELF"
  mut_arm sanitize-meta/vault 's/del(.vault, /del(/' arm_pii_audit "keeping the vault object" "a sanitised item still carries a vault key"

  # ── Task S2 §5: SEALED.txt at seal time (offline) ──────────────────────────────────────────
  check "every seal ends with SEALED.txt (path, bytes, sha256 printed), exactly seal-text's text" arm_sealed_txt "$SELF"
  check "vt-broadcast not runnable: refused before the vault is read, with the install hint" arm_need_vtb "$SELF"
  mut_arm need-vtb 's/|| die /|| true /' arm_need_vtb "dropping the up-front vt-broadcast check" "refused for another reason"
  check "SEALED.txt cannot be written: no success reported, the package kept, the message says how to write it" arm_sealed_txt_fail "$SELF"
  mut_arm sealed-txt 's/if ! _sw=/if _sw=/' arm_sealed_txt_fail "ignoring seal-text's failure" "not refused as a kept, unfinished package"

  # ── Task S3: STRUCTURE.txt, the sealed vault's shape with every value removed (offline) ────────
  check "STRUCTURE.txt of the fake vault (unknown category and field type, empty password, sections, tags, an attachment, a Document): mode 600; no ZZCANARY and no other string of the vault; the golden text; OTHER for the unknowns; counts = MANIFEST.csv; binds to vault.tar.gz.age's SHA-256 (= SEALED.txt's); README lists it as local only; SEALED.txt never carries it" arm_structure "$SELF"
  mut_arm struct-label 's/\/\/ "custom"/\/\/ ($f.label | tostring)/' arm_structure "emitting a custom field's label instead of 'custom'" "ZZCANARY: "
  check "odd JSON shapes (seam): non-objects, non-string types/ids, an object for an array, duplicate or id-less sections, bad or missing file ids: OTHER/custom/<empty>, all counted, nothing echoed; an armored archive digested decoded; non-JSON and bad names refused with fixed text" arm_structure_shapes "$SELF"
  check "open rebuilds the structure: 'structure ✓'; a tampered row, binds-to line or last line: a warning naming the line number only, open still succeeds; no STRUCTURE.txt: not compared" arm_structure_open "$SELF"
  mut_arm open-structure 's/if cmp -s /if true || cmp -s /' arm_structure_open "dropping open's comparison" "was not reported"
  check "the audit refuses a STRUCTURE.txt holding an operator string: the seal does NOT finish; the package is kept (SEALED.txt, no STRUCTURE.txt); the message says what to do" arm_structure_audit "$SELF"
  mut_arm struct-audit d arm_structure_audit "skipping pii_audit on STRUCTURE.txt" "SEALED although"
  check "STRUCTURE.txt rows that differ from MANIFEST.csv's counts: the seal does NOT finish; the package is kept without it" arm_structure_count "$SELF"
  mut_arm struct-count 's/|| die /|| true /' arm_structure_count "dropping the MANIFEST count assertion" "SEALED although"

  # ── Task SP: SEALED-plaintext.txt, written by open --plaintext after the unlock time (offline) ──────────
  if [ -n "$PT_SRC" ]; then
    wait_round "$(cat "$PT_SRC/round")"   # (long passed, normally: it was sealed with a 30 s horizon)
    check "SEALED-plaintext.txt of the PLAIN vault (login, document, attachment, unknown category, sections, OTP, empty password, multi-line values, a note with a tab and a control character, an invalid byte, urls, tags) is the golden text" arm_plaintext_golden "$SELF"
    check "completeness: every canary value of the vault (title, category, labels, values, concealed, OTP, section, url, tag, note, file name) is there exactly once, in its item and its place; no attachment byte is inlined" arm_plaintext_complete "$SELF"
    check "mode 600 under umask 022; the TIME path; the plaintext line (path, bytes, lines, sha256) and the warning; no value printed; no temp file left" arm_plaintext_mode "$SELF"
    check "before the round, KEY path and TIME path: refused before anything is decrypted (no restored/, no drand request), no file" arm_plaintext_round "$SELF"
    check "any verification failure: a tampered item, STRUCTURE.txt differing, no manifest, an unlisted item, a SEALED.txt of another archive: no file" arm_plaintext_verify "$SELF"
    check "seal --plaintext is refused before op runs: the plaintext exists only after the unlock time" arm_plaintext_seal "$SELF"
    check "an existing SEALED-plaintext.txt is not overwritten without --force; --force replaces a regular file only (a symlink is refused, its target untouched)" arm_plaintext_force "$SELF"
    check "escaping (seam): invalid UTF-8 as \\xNN per byte, never dropped; controls and lone surrogates as \\xNN; continuation lines; (empty); JSON for other types; fixed-text refusals that echo nothing" arm_plaintext_escape "$SELF"
    check "never published: seal-text's text is byte-identical with a canary SEALED-plaintext.txt beside it; open --plaintext leaves SEALED.txt as it was; README lists it as local only" arm_plaintext_published "$SELF"
    check "created safely in a dir whose ACL is inherited by new files, under umask 022: mode 600 at creation, -rw------- with no ACL before the first write, no ACL on the file" arm_plaintext_create "$SELF"
    check "a file, directory, symlink or FIFO planted at SEALED-plaintext.txt during the open: refused, untouched, no temp left; --force replaces only a regular file; something at the temp name: refused, left alone" arm_plaintext_planted "$SELF"
    check "a temp file left by an interrupted --plaintext: refused before decrypting, named, never shown, never removed" arm_plaintext_leftover "$SELF"
    check "SIGTERM while the temp file is written: exit 130, the temp file removed, no SEALED-plaintext.txt" arm_plaintext_signal "$SELF"
    check "no SEALED.txt, an unlock-after that disagrees with the round file, two unlock-after lines: refused before decrypting" arm_plaintext_precheck "$SELF"
    check "injective rows (property): ~1500 random (label, value) pairs per row kind from an adversarial alphabet, and the reviewer's (\"colon :\", \"b\") / (\"colon\", \": b\"), decode back exactly; no two distinct pairs print the same row" arm_plaintext_injective "$SELF"
    mut_arm pt-verified d arm_plaintext_verify "skipping the verification precondition (the plaintext gate)" "written although STRUCTURE.txt differs"
    mut_arm pt-mode 's/0o600) }/0o644) }/' arm_plaintext_create "creating the temp file 0644 (fchmod 600 comes after)" "at creation, not 600"
    mut_arm pt-acl d arm_plaintext_create "not stripping the inherited ACL (the writer's own check then refuses)" "carries an ACL"
    mut_arm pt-concealed 's/=> get(f, "value")/=> (isStr(get(f, "type"), "CONCEALED") ? NONE : get(f, "value"))/' arm_plaintext_complete "omitting the concealed values" "missing or misplaced"
    mut_arm pt-attach 's/fixed], "")/fixed + data], "")/' arm_plaintext_complete "inlining an attachment's bytes" "attachment bytes are inlined"
    mut_arm pt-other 's/others(it)/[]/' arm_plaintext_complete "dropping the other values (an SSH key's OpenSSH form)" "missing or misplaced"
    mut_arm pt-round d arm_plaintext_round "dropping the unlock-time check" "written before the round"
    mut_arm pt-escape 's/(92, 92)/(92)/' arm_plaintext_escape "printing a backslash as itself in an escaped row" "not the expected text"
    mut_arm pt-marker 's/const MK = (l) => /const MK = (l) => l || /' arm_plaintext_escape "dropping the escaped row's marker in column 1" "not the expected text"
    mut_arm pt-link 's/fs.linkSync(tmp, outp)/fs.renameSync(tmp, outp)/' arm_plaintext_planted "renaming over the name instead of linking (no-clobber)" "the planted entry was replaced"
    mut_arm pt-leftover d arm_plaintext_leftover "dropping the leftover-temp check" "written although a leftover temp file"
    mut_arm pt-trap 's/ "\$PT_TMP"//g' arm_plaintext_signal "leaving the temp file out of the traps" "a temp file was left after SIGTERM"
    mut_arm pt-sealed d arm_plaintext_precheck "dropping the SEALED.txt check" "no SEALED.txt: refused for another reason"
    mut_arm pt-agree 's/|| die /|| true /' arm_plaintext_precheck "accepting an unlock-after that disagrees with the round file" "written although SEALED.txt's unlock-after disagrees"
    mut_arm pt-dash d arm_plaintext_seal "dropping seal's option-first check" "the flag first or last"
    mut_arm pt-dash-open d arm_plaintext_seal "dropping open's option-first check" "open with the flag first"
    mut_arm pt-sepedge 's/return edges(s.k, t)/return false/' arm_plaintext_injective "reverting the separator-edge trigger (a label ending in \" :\", a value starting with \":\")" "rows are not injective"
  fi

  # ── lane B: seal --list, SEALED.txt format /2 (offline; fake op/tle/curl, real age; v2-format.md) ───────────────
  # the PLAIN vault again, --keep-item-ids (the same ids, paths and order both ways), as format /1 and as --list, with a
  # 30 s horizon: its round has passed when arm_v2_plaintext opens copies of it at the end of this block (sealed HERE,
  # not beside PT_SRC: the real 60 s seals above must still be shut when their TIME path is first tried)
  # (lane B) the PLAIN vault again, --keep-item-ids (the same ids, paths and order both ways), as format /1 and as --list
  for f in v1 v2; do
    eval "PT_$f="; arm_dir "ptsrc-$f"; if [ "$f" = v2 ]; then _fl=--list; else _fl=; fi
    if offline OP_FIXTURE_PLAIN=1 TL_TEST_SECONDS=30 sh "$SELF" seal "Plain$f" 10 --keep-item-ids --recovery-recipient "$RECIP" $_fl; then eval "PT_$f=\$(pkg_in Plain$f)"
    else echo "  FAIL the PLAIN vault ($f, --keep-item-ids) did not seal"; show "$T/out.log"; ok=1; fi
  done
  check "--list: the format /2 package (layout, index, b0001..b0007, no vault.tar.gz.age) and SEALED.txt (format /2, layout per-file, blocks: 7, padding: none, unlock-TIME.age, index with gzip=, the blocks in order; no path of the vault); the index audited; the round trip through the index and every block; README per-file; STRUCTURE.txt bound to the index; open (KEY path) restores and verifies 7 blocks, 3 items, 2 attachments, structure ✓" arm_v2_seal "$SELF"
  check "--list LITERAL: SEALED.txt alone in an empty dir; its printed steps 1-4 (awk, sed, base64, shasum, age, head -c, gunzip; tle = the fake drand) recover every file, OK, and shasum -c the manifests OK: padding none, --pad, --pad --armor" arm_v2_literal "$SELF"
  if [ -f "$T/v2lit-padded.txt" ]; then
    for m in "cut|s/{ f = (\$2 == n); next }/{ f = 0; next }/" "trunc|s/| head -c \"\$g\" |/|/"; do
      sed "${m#*|}" "$T/v2lit-padded.txt" > "$T/v2lit-mut.txt"
      if cmp -s "$T/v2lit-padded.txt" "$T/v2lit-mut.txt"; then echo "  FAIL MUTANT v2-literal/${m%%|*}: the alteration changed nothing"; ok=1
      elif v2_lit "$T/v2lit-mut" "$T/v2lit-mut.txt" 1 4 > "$T/v2lit.log" 2>&1 && v2_lit_ok "$T/v2lit-mut" 7 >> "$T/v2lit.log" 2>&1
      then echo "  FAIL MUTANT v2-literal/${m%%|*} SURVIVED: the altered text still recovered the vault"; ok=1
      else echo "  OK   MUTANT v2-literal/${m%%|*} killed: altering the printed $( [ "${m%%|*}" = cut ] && echo 'cut (awk)' || echo "block step's cut at the gzip length (a --pad text)" ) makes the literal rehearsal FAIL (it passes unaltered, above)"; fi
    done
  fi
  check "--list --pad: every block and the index decrypt to exactly their size bucket, zeros after the gzip stream; without --pad to exactly the stream; no gzip name or MTIME; pad-bucket's table; --pad without --list refused" arm_v2_pad "$SELF"
  mut_arm v2-pad d arm_v2_pad "dropping the zero padding (the layout still says buckets)" "the --list --pad seal failed"
  mut_arm v2-gzip 's/gzip -n -9 -c "\$WORK\/s/gzip -9 -c "$WORK\/s/' arm_v2_pad "gzip without -n for the blocks" "its gzip header carries"
  check "--list: the block numbers follow the drawn order (a seeded TL_ORDER_SOURCE), not the paths; the banner and README say the seam is a self-test one, NOT random; repeated keys refuse" arm_v2_order "$SELF"
  mut_arm v2-order 's/ | LC_ALL=C sort | cut/ | cut/' arm_v2_order "numbering the blocks in path order" "b0001 is not the path the drawn order puts first"
  mut_arm v2-order-distinct 's/|| die /|| true /' arm_v2_order "accepting repeated order keys" "SEALED although the order's keys repeat"
  check "--list: the index is audited before encryption: an operator string only it holds refuses (category only; no package, nothing left); the same vault seals without --list" arm_v2_audit "$SELF"
  mut_arm v2-audit 's/|| die /|| true /' arm_v2_audit "accepting a hit in the index" "SEALED although the index holds"
  mut_arm v2-audit-call d arm_v2_audit "not auditing the index" "SEALED although the index holds"
  check "--list open refuses, for its reason, with no restored/ left: a changed byte in a block or the index, a missing or an extra block, two blocks swapped, a wrong index-gzip, a layout beside vault.tar.gz.age" arm_v2_tamper "$SELF"
  mut_arm v2-blockset 's/|| die /|| true /' arm_v2_tamper "ignoring a missing or extra block" "refused for another reason"
  check "--list open: a crafted index (a '..' path, a repeated block, 4 fields) refuses before anything is written; a line whose SHA-256 is not its file's refuses, restored/ removed" arm_v2_index "$SELF"
  mut_arm v2-index 's/|| die /|| true /' arm_v2_index "accepting a malformed index" "crafted index"
  mut_arm v2-digest 's/|| die /|| true /' arm_v2_index "accepting a file whose digest is not the index's" "crafted index"
  check "--list printed steps vs a HOSTILE index (fix round 1, C-1/I-1): a hostile value in every column and every structural shape refuses the whole index, writes nothing (no restored/, no canary, nothing beside), prints only printable ASCII; without its check the text does write restored/" arm_v2_hostile "$SELF"
  check "--list: an index whose last line has no trailing newline: open and the printed steps restore all 7 blocks (none skipped)" arm_v2_nonl "$SELF"
  check "--list open, the TIME path (the fake drand): locked before the round, nothing restored; then all 7 blocks restored and verified, structure ✓" arm_v2_time "$SELF"
  check "--list: a block that does not come back in the seal's round trip refuses the seal, naming the block; nothing left" arm_v2_rt "$SELF"
  mut_arm v2-rt 's/|| die /|| true /' arm_v2_rt "ignoring the per-block round trip" "refused for another reason"
  check "--list: SIGTERM while the blocks are encrypted: exit 130, nothing under TMPDIR, no half package" arm_v2_signal "$SELF"
  check "--list --armor: the index and every block (and both unlock files) are canonical age armor" arm_v2_armor "$SELF"
  mut_arm v2-armor 's/ \$ARMOR_FLAG//' arm_v2_armor "dropping --armor from the blocks" "is not canonical age ASCII armor"
  mut_arm v2-armor-index 's/ \$ARMOR_FLAG//' arm_v2_armor "dropping --armor from the index" "index is not canonical age ASCII armor"
  check "the default seal (no --list) is format /1 as before: its files, SEALED.txt (format /1; unlock-TIME.age, vault.tar.gz.age), README and STRUCTURE.txt; no format /2 output" arm_v1_unchanged "$SELF"
  check "a format /1 reader refuses a format /2 text on its format line: core's published-text parser (Open's sealedFiles) says payload.sealed-line" arm_v2_reader "$SELF"
  if [ -n "${PT_v1:-}" ] && [ -n "${PT_v2:-}" ]; then
    wait_round "$(cat "$PT_v2/round")"
    check "--list open --plaintext (after the round) writes the same SEALED-plaintext.txt as format /1 (the PLAIN vault, --keep-item-ids both ways: byte-identical body); its header names the index; a SEALED.txt saying format /1 or without its layout line refuses" arm_v2_plaintext "$SELF"
  else echo "  FAIL no PLAIN packages for the --list plaintext arm"; ok=1; fi

  # ── Task S2 §7: no operator PII, no 1Password identifier in the sealed payload (offline) ─────
  check "PII scan: the decrypted archive and the time-locked key file hold 0 occurrences of the operator's names, host, home, UTC offset, today's date, uid, or the vault's real ids/member/vault names (counts only)" arm_pii_scan "$SELF"
  mut_arm key-strip "s/ | grep '^AGE-SECRET-KEY-1'//" arm_pii_scan "re-including age-keygen's '# created:' line in the data key" "PII/ID audit: .*seal-date-local"
  check "the sanitiser + built-in audit: the audit line; no account metadata inside; consistent pseudonyms; values and built-in ids kept; the local manifest maps pseudonym -> real id" arm_pii_audit "$SELF"
  mut_arm sanitize-paths 's/del(.content_path, .reference)/del(.reference)/' arm_pii_audit "keeping content_path in the sanitised JSON" "PII/ID audit: .*content-path"
  mut_arm sanitize-meta 's/del(.vault, .last_edited_by, .version, .created_at, .updated_at)/del(.vault, .version, .created_at, .updated_at)/' arm_pii_audit "keeping last_edited_by" "PII/ID audit: .*member-id"
  check "a note holding another item's UUID: the audit refuses (category item-id), nothing sealed, no id printed" arm_pii_idinnote "$SELF"
  mut_arm pii-audit 's/|| die /|| true /' arm_pii_idinnote "blanking the audit's refusal" "SEALED a payload holding a 1Password item id"
  check "--keep-item-metadata / --keep-item-ids: each warns what it exposes, and keeps exactly that" arm_pii_keep "$SELF"

  # ── Task S2 §1: attachments (documented op forms, fake op; offline) ────────────────────────
  check "attachments: op read fetches the item attachment, op document get the Document; the round trip and open verify both (ATTACHMENTS.csv)" arm_attachments "$SELF"
  check "a failed attachment fetch refuses the seal, naming item/file ids only" arm_att_failed "$SELF"
  mut_arm failed-files d arm_att_failed "blanking the failed-files refusal" "SEALED with OP_FIXTURE_FAILFILE"
  check "an attachment op reported fetched but that is not on disk: the per-item count refuses" arm_att_count "$SELF"
  mut_arm att-count 's/|| die /|| true /' arm_att_count "blanking the per-item attachment count check" "SEALED with OP_FIXTURE_NOFILE"
  check "an attachment one byte short of the JSON's size refuses" arm_att_size "$SELF"
  mut_arm att-size 's/|| die /|| true /' arm_att_size "blanking the attachment size check" "SEALED with OP_FIXTURE_SHORTFILE"
  check "a failed Document fetch (op document get) refuses" arm_att_doc "$SELF"
  check "an archive that lost its attachments fails the round trip" arm_rt_attachments "$SELF"
  mut_arm rt-attachments 's/|| die /|| true /' arm_rt_attachments "blanking the round-trip refusal" "SEALED although the archive lost its attachments"
  check "open refuses an ATTACHMENTS.csv row whose ids are not [a-z0-9]+" arm_att_id "$SELF"
  mut_arm att-id d arm_att_id "dropping open's attachment-id check" "refused for another reason"

  # ── the --reveal failure mode must be REFUSED at seal time ────────────────────────────────
  arm_dir hollow
  if offline OP_FIXTURE_HOLLOW=1 sh "$SELF" seal Test2 10
  then echo "  FAIL a hollow item was SEALED — the --reveal arm is dead"; ok=1
  else grep -qE 'no fields and no files|ALL [0-9]+ item' "$T/out.log" \
       && echo "  OK   a hollow item is refused, naming the --reveal failure mode" \
       || { echo "  FAIL refused for the wrong reason"; sed 's/^/       /' "$T/out.log"; ok=1; }; fi

  # ── the CONCEALED-export failure mode must be REFUSED (right shape, blank values) ──────────
  arm_dir concealed
  if offline OP_FIXTURE_CONCEALED=1 sh "$SELF" seal Test3 10
  then echo "  FAIL a CONCEALED item was SEALED — the payload arm is dead"; ok=1
  else grep -qE 'ALL [0-9]+ item' "$T/out.log" \
       && echo "  OK   a concealed item is refused, naming the --reveal signature" \
       || { echo "  FAIL refused for the wrong reason"; sed 's/^/       /' "$T/out.log"; ok=1; }; fi

  # ── ★★★ THE ARM THIS SUITE NEVER HAD, and whose absence hid the per-item refusal: a MIXED vault.
  #    Every earlier fixture was fully populated or fully blank — the two EXTREMES — and at the
  #    extremes a rule about the POPULATION and a rule about each ELEMENT agree. The ordinary case
  #    is the one that tells them apart, and a user found it before the tests did.
  arm_dir mixed
  if offline OP_FIXTURE_MIXED=1 sh "$SELF" seal Test4 1y30d
  then
    grep -q 'sealed anyway' "$T/out.log" \
      && echo "  OK   MIXED vault (1 of 3 blank) SEALS, and the blank is reported not refused" \
      || { echo "  FAIL mixed vault sealed but said nothing about the blank"; ok=1; }
    B=$(pkg_in Test4)
    [ -f "$B/BLANK-AT-SEAL.txt" ] \
      && echo "  OK   BLANK-AT-SEAL.txt ships the blank UUID(s) beside the package" \
      || { echo "  FAIL no BLANK-AT-SEAL.txt"; ok=1; }
    # a unit duration is shown as typed, and nothing claims a number of years
    if grep -q "Requested: 1y30d; overridden" "$B/README.txt" && grep -q "requested: 1y30d;" "$T/out.log" \
       && ! grep -qi 'year' "$B/README.txt"
    then echo "  OK   a 1y30d seal says 'requested: 1y30d', and its README mentions no years"
    else echo "  FAIL the 1y30d horizon text"; grep -i 'year\|requested' "$B/README.txt" "$T/out.log" | sed 's/^/       /'; ok=1; fi
  else
    echo "  FAIL ★ a MIXED vault was REFUSED — this is the per-item refusal regressing"; sed 's/^/       /' "$T/out.log"; ok=1
  fi

  # ── with VAULT_TIMELOCK_DIR unset, a package lands in $XDG_DATA_HOME/vault-timelock, NOT the cwd,
  #    and `open` finds it by bare name from anywhere. XDG_DATA_HOME is pointed into $T so this arm
  #    exercises the default without touching the real ~/.local/share. (Offline: fake tle/curl.)
  #    (and the options may come BEFORE the duration)
  mkdir -p "$T/cwd"; : > "$T/do"   # exists even if the open arm never runs; set -e kills a bare sed
  if ( cd "$T/cwd" && VAULT_TIMELOCK_DIR="" XDG_DATA_HOME="$T/xdg" OP="$T/op" TLE=tle PATH="$T/fakebin:$PATH" \
       TL_TEST_SECONDS=600 sh "$SELF" seal Test5 --recovery-recipient "$RECIP" 30d ) >"$T/d" 2>&1
  then
    D=$(ls -d "$T"/xdg/vault-timelock/1password-Test5-timelock-* 2>/dev/null | head -1)
    if [ -n "$D" ] && [ -z "$(ls -A "$T/cwd")" ]; then
      echo "  OK   default output is \$XDG_DATA_HOME/vault-timelock, and nothing lands in the cwd"
    else echo "  FAIL default output dir"; ls -R "$T/xdg" "$T/cwd" | sed 's/^/       /'; ok=1; fi
    if [ "$(stat -f %Lp "$T/xdg/vault-timelock" 2>/dev/null || stat -c %a "$T/xdg/vault-timelock")" = 700 ]
    then echo "  OK   a data dir the tool creates is 0700"
    else echo "  FAIL data dir is not 0700"; ok=1; fi
    if [ -n "$D" ] && ( cd / && VAULT_TIMELOCK_DIR="" XDG_DATA_HOME="$T/xdg" TLE="$TLE" \
         sh "$SELF" open "$(basename "$D")" --identity "$T/recovery.key" ) >"$T/do" 2>&1 \
       && grep -q '3/3 items match' "$T/do"
    then echo "  OK   open resolves a bare package name against the data dir"
    else echo "  FAIL open by bare name"; sed 's/^/       /' "$T/do"; ok=1; fi
  else
    echo "  FAIL seal into the default data dir"; sed 's/^/       /' "$T/d"; ok=1
  fi

  # every seal and open above (real and offline) had TMPDIR=$T/tmp: their work dirs must all be gone
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
  # test seam for seal --list --pad (lane B): the size bucket of a gzip stream of N bytes; no network, nothing written
  pad-bucket) [ $# -eq 2 ] || die "usage: pad-bucket <BYTES>"; case $2 in ''|0|*[!0-9]*|????????????????*) die "pad-bucket: 1 to 15 digits" ;; esac; pad_bucket "$2" ;;
  # test seam for STRUCTURE.txt (Task S3): the shape text of DIR/items + DIR/files bound to ARCHIVE, on
  # stdout, built by the same function as the seal's; no network; its scratch dir (under TMPDIR) is removed
  structure) [ $# -eq 3 ] || die "usage: structure <dir> <archive.age>"
    _tmpd=${TMPDIR:-/tmp}; WORK=$(mktemp -d "${_tmpd%/}/1password-timelock.XXXXXXXX") || die "mktemp failed"
    trap 'obliterate "$WORK"' EXIT; structure_text "$2" "$3" "$WORK/STRUCTURE.txt"; cat "$WORK/STRUCTURE.txt" ;;
  # test seam for SEALED-plaintext.txt (Task SP): the items of DIR (a restored/-shaped tree) in its format,
  # on stdout, by the same renderer as open --plaintext; no network; its scratch dir is removed
  plaintext-body) [ $# -eq 2 ] || die "usage: plaintext-body <dir>"
    _tmpd=${TMPDIR:-/tmp}; WORK=$(mktemp -d "${_tmpd%/}/1password-timelock.XXXXXXXX") || die "mktemp failed"
    trap 'obliterate "$WORK"' EXIT; plaintext_body "$2" ;;
  --self-test) cmd_selftest ;;
  *) sed -n '2,25p' "$0" ;;
esac
