#!/bin/sh
# cli/test/fakes/node-ready.sh — the fake server behind test/fakes/tmux.sh (plan Task C3): prints what the window's
# server would print at startup. Called as: node-ready.sh <state dir> <window> <program> <args...>, where <args...> holds
# `--network <n>` and, for the API, `--build <b>`. Its behaviour comes from <state dir>/mode-<window>:
#   ready   (default) the canonical readiness line (vt-relay|vt-api|vt-page ready network=<n> port=<p> …; Vite's Local:)
#   mq      the MQ servers' lines (`listening on loopback :<p> (…)`, `release build on http://127.0.0.1:<p>/…`)
#   other   a readiness line with ANOTHER network's port (must not count)
#   silent  a startup line, never a readiness line, still running
#   exit    a refusal, then exit 2 (the fake tmux appends the exit marker)
# Exit 0 means "still running".
set -eu
S=$1 w=$2
shift 2
n= b=dev
while [ $# -gt 0 ]; do
  case $1 in
    --network) n=$2; shift 2 ;;
    --build) b=$2; shift 2 ;;
    *) shift ;;
  esac
done
case $n in
  local) page=5180 relay=5181 api=5182 ;;
  testnet) page=5190 relay=5191 api=5192 ;;
  mainnet) page=5200 relay=5201 api=5202 ;;
  *) n=local page=5180 relay=5181 api=5182 ;;   # the Vite window has no --network: it is local
esac
mode=ready
[ ! -f "$S/mode-$w" ] || mode=$(cat "$S/mode-$w")
echo "fake $w starting"
case $mode in
  ready|mq|other)
    [ "$mode" != other ] || { page=$((page + 1000)) relay=$((relay + 1000)) api=$((api + 1000)); }
    case $w:$mode in
      relay:mq) echo "listening on loopback :$relay (eth on, sol on, price LOCAL FIXTURE, tor none (direct loopback))" ;;
      page:mq) echo "release build on http://127.0.0.1:$page/?view=mainnet (relay proxy -> :$relay)" ;;
      relay:*) echo "vt-relay ready network=$n port=$relay" ;;
      api:*) echo "vt-api ready network=$n port=$api build=$b" ;;
      page:*) echo "vt-page ready network=$n port=$page build=$b" ;;
      vite:*) printf '\n  VITE v8.3.3  ready in 1 ms\n\n  \342\236\234  Local:   http://127.0.0.1:%s/\n' "$((5183 + page - 5180))" ;;
    esac ;;
  silent) ;;
  exit) echo "refused api.not-confined: a synthetic startup failure"; exit 2 ;;
esac
exit 0
