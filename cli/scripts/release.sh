#!/bin/sh
# cli/scripts/release.sh — PORTED (R69) from the prototype's release.sh, tag add7b-e540f8ae4d6b
# (sha256 f525ae7b1e2047c3e2214e7382e354dad0fb0c62c3091e40719e5b87939c4f14, git blob 604f0904a200f2488896e0fcf3b895ee6e223369).
# Plan Task C4; canonical vt spec §9.
#
#   sh cli/scripts/release.sh build          vt release build (the development tree's bin/vt, with the caller's VT_HOME and
#                                            VAULT_TIMELOCK_DIR), then `check` on the release it names
#   sh cli/scripts/release.sh check <dir>    the independent check only; exit 0 = the release passes, 1 = it does not
#
# What changed from the prototype. MQ's script built the release itself (vite build, cp of the relay, the page server
# and a hand-listed socks-proxy-agent closure into a temporary release directory, the no-harness check, SHA256SUMS, chmod -R a-w).
# The canonical build is `vt release build` (cli/src/ops/release.ts): it copies tracked files only, follows the whole
# production closure, and verifies. This script keeps MQ's checks as a SECOND, INDEPENDENT implementation that uses
# system tools only (shasum, find, grep, sed; no node, no vt code), so a bug in one does not pass a bad release:
#   1. SHA256SUMS: `shasum -a 256 -c` from the release dir passes (0 mismatches, nothing missing), and every regular
#      file but SHA256SUMS is listed exactly once (nothing extra); nothing but files, directories and links;
#   2. the release dir is read-only (MQ: chmod -R a-w): no file or directory has a write bit, and none carries an ACL;
#   3. no test harness (MQ R64, extended to the canonical names): no test/, tests/, __tests__/, fixtures/,
#      __fixtures__/, __mocks__/ directory (viem's runtime actions/test/ aside), no *pressure* / *harness* name, no
#      *.test.* / *.spec.* file, none of MQ's marker strings in any file, VT_TEST_ only in api/relay/relay.mjs, no
#      dev-only package under node_modules/, no state or secret file name;
#   4. the only links are the first-party workspace links (<ws>/node_modules/<first-party name>) with their exact
#      relative targets, each listed in RELEASE.json;
#   5. the build id: the directory is named by 12 hex, and RELEASE.json says that id;
#   6. no node_modules/ above the release (nor ~/.node_modules, ~/.node_libraries, nor Node's $PREFIX/lib/node) that could
#      supply a module; no empty directory (every directory holds a listed file or link).
# The dev server refusing mainnet (MQ I5) is vt's: `vt up --network mainnet` from a development tree is refused
# (vt.mainnet-dev-tree), and from a release only after `vt release verify` passes, every time.
set -eu
set -f
unset CDPATH

die() { printf 'release.sh: %s\n' "$*" >&2; exit 1; }

check() {
  [ -d "$1" ] || die "no such release directory"
  DIR=$(cd -P "$1" && pwd)
  ID=${DIR##*/}
  fail=0
  # Findings name paths from the tree: control characters are dropped before they reach the terminal (review m4).
  bad() { printf 'release check: %s\n' "$*" | LC_ALL=C tr -d '\000-\010\013-\037\177' >&2; fail=1; }
  T=$(mktemp -d "${TMPDIR:-/tmp}/vt-release-check.XXXXXX") || die "mktemp failed"
  trap 'rm -rf "$T"' EXIT
  cd "$DIR"

  # 1. SHA256SUMS
  if [ -f SHA256SUMS ]; then
    shasum -a 256 -c --quiet SHA256SUMS > "$T/sums.out" 2>&1 || bad "SHA256SUMS: $(grep -c 'FAILED' "$T/sums.out" || true) mismatched or missing file(s)"
    find . -type f ! -path ./SHA256SUMS -print | LC_ALL=C sort > "$T/files"
    sed -n 's/^[0-9a-f]\{64\}  //p' SHA256SUMS | LC_ALL=C sort > "$T/listed"
    [ "$(grep -c . SHA256SUMS || true)" = "$(grep -c . "$T/listed" || true)" ] || bad "SHA256SUMS: malformed lines"
    cmp -s "$T/files" "$T/listed" || bad "SHA256SUMS does not list exactly the regular files of the release"
  else
    bad "no SHA256SUMS"
  fi
  if find . ! -type f ! -type d ! -type l -print | grep -q .; then bad "special files (FIFO, socket, device)"; fi
  # ... and no directory that no file or link beneath it implies (an empty directory; review m6)
  find . -mindepth 1 \( -type f -o -type l \) -print | awk '{ n = split($0, a, "/"); p = a[1]; for (i = 2; i < n; i++) { p = p "/" a[i]; print p } }' | LC_ALL=C sort -u > "$T/implied"
  find . -mindepth 1 -type d -print | LC_ALL=C sort > "$T/dirs"
  if [ -n "$(LC_ALL=C comm -23 "$T/dirs" "$T/implied")" ]; then bad "an empty directory (nothing in it is listed)"; fi

  # 2. read-only
  if find . ! -type l -perm +0222 -print | grep -q .; then bad "writable files or directories (the release must be read-only)"; fi
  # ... and no ACL anywhere (a macOS ACL can grant writes the mode bits do not show; review m3)
  if ls -leRA . > "$T/acl" 2>/dev/null; then
    if grep -qE '^ [0-9]+: ' "$T/acl"; then bad "an ACL on an entry (a release carries none)"; fi
  else
    bad "the ACLs could not be read"
  fi

  # 3. no test harness, no dev-only package, no state
  find . \( -type d \( -name test -o -name tests -o -name __tests__ -o -name fixtures -o -name __fixtures__ -o -name __mocks__ \) \
    -o -iname '*pressure*' -o -iname '*harness*' -o -type f \( -name '*.test.*' -o -name '*.spec.*' \) \) -print \
    | grep -vE '^\./(.*/)?node_modules/viem/(_cjs/|_esm/|_types/)?actions/test$' > "$T/harness" || true
  if [ -s "$T/harness" ]; then bad "a test harness, test directory or test file: $(head -n 3 "$T/harness" | tr '\n' ' ')"; fi
  if grep -rlE 'sol-pressure-filter|eth-pressure-miner|anvil_dropTransaction|WITHHELD' . > "$T/markers" 2>/dev/null; then
    bad "pressure-harness markers in: $(head -n 3 "$T/markers" | tr '\n' ' ')"
  fi
  grep -rl 'VT_TEST_' . 2>/dev/null | grep -vx './api/relay/relay.mjs' > "$T/override" || true
  if [ -s "$T/override" ]; then bad "test override code (VT_TEST_) outside api/relay/relay.mjs: $(head -n 3 "$T/override" | tr '\n' ' ')"; fi
  # ... and in the relay only the reviewed hooks: at most RELAY_TEST_HOOKS occurrences (mirrors TEST_OVERRIDE_ALLOWED in release.ts)
  RELAY_TEST_HOOKS=6
  if [ -f api/relay/relay.mjs ]; then
    n=$(grep -o 'VT_TEST_' api/relay/relay.mjs | grep -c . || true)
    [ "$n" -le "$RELAY_TEST_HOOKS" ] || bad "api/relay/relay.mjs holds more VT_TEST_ hooks than were reviewed ($n > $RELAY_TEST_HOOKS)"
  fi
  find . \( -path '*/node_modules/typescript' -o -path '*/node_modules/vite' -o -path '*/node_modules/vitest' -o -path '*/node_modules/jsdom' \
    -o -path '*/node_modules/tsx' -o -path '*/node_modules/ts-node' -o -path '*/node_modules/esbuild' -o -path '*/node_modules/rolldown' \
    -o -path '*/node_modules/@types' -o -path '*/node_modules/@testing-library' -o -path '*/node_modules/@vitest' -o -path '*/node_modules/@vitejs' \) -print > "$T/dev"
  if [ -s "$T/dev" ]; then bad "dev-only packages: $(head -n 3 "$T/dev" | tr '\n' ' ')"; fi
  find . \( -name api.token -o -name relay-ticket.key -o -name api.lock -o -name up.json -o -name journal.jsonl -o -name identity.key \
    -o -name privacycash-withdrawals.jsonl -o -name privacycash-withdrawals.lock -o -name privacycash-lane-mints.jsonl \
    -o -name '*.age' -o -name .env -o -name '.env.*' -o -name .npmrc -o -name .git -o -name .superpowers -o -name .vt-dev -o -name restored \) -print > "$T/state"
  if [ -s "$T/state" ]; then bad "state or secret files: $(head -n 3 "$T/state" | tr '\n' ' ')"; fi

  # 4. links
  : > "$T/names"
  for ws in cli api packages/core broadcast; do
    [ -f "$ws/package.json" ] || { bad "$ws/package.json is missing"; continue; }
    name=$(sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$ws/package.json" | head -n 1)
    printf '%s %s\n' "$name" "$ws" >> "$T/names"
  done
  find . -type l -print > "$T/links"
  while IFS= read -r l; do
    rel=${l#./}
    want=
    for ws in cli api packages/core broadcast; do
      case $rel in
        "$ws"/node_modules/*)
          name=${rel#"$ws"/node_modules/}
          # broadcast's only first-party link is @vault-timelock/core (E6): any other is refused
          [ "$ws" != broadcast ] || [ "$name" = "@vault-timelock/core" ] || break
          target=$(awk -v n="$name" '$1 == n { print $2 }' "$T/names")
          [ -n "$target" ] || break
          ups=$(printf '%s\n' "${rel%/*}" | awk -F/ '{ s = ""; for (i = 1; i <= NF; i++) s = s "../"; print s }')
          want=$ups$target
          break ;;
      esac
    done
    got=$(readlink "$l")
    if [ -z "$want" ] || [ "$got" != "$want" ] || ! grep -qF "\"$rel\": \"$got\"" RELEASE.json; then bad "an unexpected link: $rel"; fi
  done < "$T/links"

  # 5. the build id
  case $ID in *[!0-9a-f]*) bad "the release directory is not named by a build id" ;; esac
  [ ${#ID} = 12 ] || bad "the release directory is not named by a 12-hex build id"
  grep -q "^  \"buildId\": \"$ID\",\$" RELEASE.json 2>/dev/null || bad "RELEASE.json does not name build id $ID"

  # 6. nothing above the release can supply a module
  a=$DIR
  while [ "$a" != / ]; do
    a=$(dirname "$a")
    case ${a##*/} in node_modules) ;; *) if [ -e "${a%/}/node_modules" ]; then bad "a node_modules directory above the release"; fi ;; esac
  done
  for g in "$HOME/.node_modules" "$HOME/.node_libraries"; do if [ -e "$g" ]; then bad "a global module folder in HOME"; fi; done
  # ... nor Node's own CJS global folder, $PREFIX/lib/node (review m8)
  nodebin=$(command -v node 2>/dev/null || true)
  if [ -n "$nodebin" ]; then
    nodeprefix=$(dirname "$(dirname "$nodebin")")
    if [ -e "$nodeprefix/lib/node" ]; then bad "Node's global module folder (lib/node) exists"; fi
  fi

  if [ "$fail" = 0 ]; then
    echo "release check: $ID ok ($(grep -c . SHA256SUMS) files, SHA256SUMS sha256 $(shasum -a 256 SHA256SUMS | cut -c1-16)…; read-only; no test harness)"
  fi
  return "$fail"
}

case ${1-} in
  check)
    [ $# = 2 ] || die "usage: sh cli/scripts/release.sh check <release dir>"
    check "$2" ;;
  build)
    [ $# = 1 ] || die "usage: sh cli/scripts/release.sh build"
    ROOT=$(cd -P "$(dirname "$0")/../.." && pwd)
    out=$("$ROOT/bin/vt" release build) || die "vt release build failed"
    printf '%s\n' "$out"
    id=$(printf '%s\n' "$out" | sed -n 's/^vt release build: [a-z (),]* \([0-9a-f]\{12\}\) from commit .*/\1/p')
    [ -n "$id" ] || die "vt release build named no release"
    check "${VT_HOME:-$HOME/.local/state/vt}/releases/$id" ;;
  *) die "usage: sh cli/scripts/release.sh build | check <release dir>" ;;
esac
