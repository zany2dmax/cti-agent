#!/usr/bin/env bash
# quiet-step.sh - run one step of `task ship` and say "ok", unless it fails.
#
#   scripts/quiet-step.sh NAME COMMAND [ARG...]
#
# Everything the step prints goes to a temporary file. While it runs, a dot
# every five seconds says it is still going. On success it prints one line,
#
#     test               ............................................ ok (218s)
#
# and the file is thrown away: a passing step's warnings, test names and the
# deliberate failure paths tests print are noise once you know it passed. On
# failure it prints FAIL and then EVERYTHING the step printed, unfiltered, so a
# failure loses nothing a full run would have shown. The exit status is the
# step's own, so `task` stops at the first failure exactly as it did before.
#
# A prompt (an ssh passphrase, a credential helper) reads and writes the
# terminal directly, not stdout, so it still appears.
set -uo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 NAME COMMAND [ARG...]" >&2
  exit 2
fi
name=$1
shift

log=$(mktemp "${TMPDIR:-/tmp}/ship-step.XXXXXX") || exit 2
ticker=""
cleanup() {
  [ -n "$ticker" ] && kill "$ticker" 2>/dev/null && wait "$ticker" 2>/dev/null
  ticker=""
  rm -f "$log"
}
trap cleanup EXIT
trap 'cleanup; printf " interrupted\n"; exit 130' INT TERM

start=$SECONDS
printf '  %-18s ' "$name"
# sleep gets no stdout, so a sleep orphaned by the kill below cannot hold
# task's output pipe open for another five seconds.
( while sleep 5 >/dev/null 2>&1; do printf '.'; done ) &
ticker=$!

"$@" >"$log" 2>&1
rc=$?

kill "$ticker" 2>/dev/null
wait "$ticker" 2>/dev/null
ticker=""
secs=$((SECONDS - start))

if [ "$rc" -eq 0 ]; then
  printf ' ok (%ss)\n' "$secs"
else
  printf ' FAIL (%ss, exit %s)\n\n' "$secs" "$rc"
  cat "$log"
  printf '\n%s failed; everything it printed is above.\n' "$name"
fi
exit "$rc"
