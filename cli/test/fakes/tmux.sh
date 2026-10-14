#!/bin/sh
# cli/test/fakes/tmux.sh — a fake tmux for the C3 tests (plan Task C3). No server, no socket, no real window: the tests
# never talk to a tmux server through this file (test/up-real.test.ts uses the real tmux on a private -L socket).
#
# The test puts a wrapper named `tmux` first on PATH that sets FAKE_TMUX_STATE and execs `/bin/sh <this file>` (bin/vt
# runs vt under env -i, so the state dir cannot come from the test's environment). In $FAKE_TMUX_STATE:
#   calls             every invocation, NUL-separated: the argument count, then each argument
#   sessions/<name>   one file per session, holding its window names
#   mode-<window>     the fake server's behaviour for that window (node-ready.sh): ready (default), mq, exit, silent, other
#   fail-<command>    when present, that tmux command fails (exit 1)
# Every call must start with `-L vt -f /dev/null` (vt's own tmux server, never the default one, and never a tmux config:
# the I3 finding); it is not part of the record.
# Only the four commands vt uses are known, and a session is accepted only as an exact target (=name or =name:).
# A window's command must be `/bin/sh -c <script> <arg0> <log> <program> <args...>` (src/ops/stack.ts): instead of
# running it, the fake runs node-ready.sh with the window name and <program> <args...>, appends what it prints to
# <log>, and when it exits non-zero appends the window script's exit marker, as the real script would.
set -eu
S=${FAKE_TMUX_STATE:?FAKE_TMUX_STATE is not set}
HERE=$(cd "$(dirname "$0")" && pwd)
[ "${1-}" = -L ] && [ "${2-}" = vt ] || { echo "fake tmux: vt must use its own server (-L vt)" >&2; exit 3; }
[ "${3-}" = -f ] && [ "${4-}" = /dev/null ] || { echo "fake tmux: vt must never load a tmux config (-f /dev/null)" >&2; exit 3; }
shift 4
printf '%s\0' "$#" "$@" >> "$S/calls"
mkdir -p "$S/sessions"
cmd=${1-}
[ $# -gt 0 ] && shift
[ ! -e "$S/fail-$cmd" ] || { echo "fake tmux: $cmd failed (fail-$cmd)" >&2; exit 1; }

name= window= target=
while [ $# -gt 0 ]; do
  case $1 in
    -d) shift ;;
    -s) name=$2; shift 2 ;;
    -n) window=$2; shift 2 ;;
    -t) target=$2; shift 2 ;;
    --) shift; break ;;
    *) echo "fake tmux: unexpected argument" >&2; exit 3 ;;
  esac
done
if [ -n "$target" ]; then
  case $target in
    =*) name=${target#=}; name=${name%:} ;;
    *) echo "fake tmux: inexact target (vt must use =<session>)" >&2; exit 3 ;;
  esac
fi
case $name in vt-local|vt-testnet|vt-mainnet) ;; *) echo "fake tmux: unexpected session name" >&2; exit 3 ;; esac

start_window() { # <window> <command...>
  w=$1; shift
  [ "${1-}" = /bin/sh ] && [ "${2-}" = -c ] && [ $# -ge 6 ] || { echo "fake tmux: a window command must be /bin/sh -c <script> <arg0> <log> <program> ..." >&2; exit 4; }
  log=$5
  shift 5
  printf '%s\n' "$w" >> "$S/sessions/$name"
  st=0
  /bin/sh "$HERE/node-ready.sh" "$S" "$w" "$@" >> "$log" 2>&1 || st=$?
  if [ "$st" != 0 ]; then printf 'vt: exited with status %s\n' "$st" >> "$log"; fi
}

case $cmd in
  has-session)
    [ -e "$S/sessions/$name" ] || { echo "can't find session: $name" >&2; exit 1; } ;;
  new-session)
    [ ! -e "$S/sessions/$name" ] || { echo "duplicate session: $name" >&2; exit 1; }
    : > "$S/sessions/$name"
    start_window "$window" "$@" ;;
  new-window)
    [ -e "$S/sessions/$name" ] || { echo "can't find session: $name" >&2; exit 1; }
    start_window "$window" "$@" ;;
  kill-session)
    [ -e "$S/sessions/$name" ] || { echo "can't find session: $name" >&2; exit 1; }
    rm -f "$S/sessions/$name" ;;
  *) echo "fake tmux: unknown command" >&2; exit 3 ;;
esac
