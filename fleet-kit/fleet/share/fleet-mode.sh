# shellcheck shell=bash
# fleet-mode.sh - sourced by every runner that changes something.
#
# The rule (see internal/cli/mode.go, which is the same rule for the Go
# commands): say how to run it. --dry-run, --for-real, or --to-dev where the
# command has one. No default: with none the runner prints this and exits 2
# without touching anything, whether a person, a unit or the heartbeat ran it.
#
#   . "$(dirname "${BASH_SOURCE[0]}")/../share/fleet-mode.sh"
#   fleet_require_mode run-digest "$DRY_SET" "$REAL_SET" "$DEV_SET" allow-dev
#
# Each of the three is non-empty when that flag was given. The fourth argument
# is "allow-dev" for a runner that has --to-dev. An optional sixth says where
# to point the reader for help (default: cti-agent PROG --help). Legal: one of the three, or
# --to-dev with --dry-run (rehearse the test send).
fleet_require_mode() {
  local prog="$1" dry="$2" real="$3" dev="$4" allow="${5:-}"
  # Where the usage points: a command run through cti-agent says so, a root-only
  # script like the updater names how it is actually run.
  local see="${6:-cti-agent $prog --help}"
  if [ -n "$real" ] && [ -n "$dry" ]; then
    echo "$prog: --dry-run and --for-real contradict each other - say which one" >&2; exit 2
  fi
  if [ -n "$real" ] && [ -n "$dev" ]; then
    echo "$prog: --to-dev and --for-real contradict each other - a test send is not the real one" >&2; exit 2
  fi
  if [ -z "$dry" ] && [ -z "$real" ] && [ -z "$dev" ]; then
    {
      echo "$prog: say how to run it - one of:"
      echo "  --dry-run   do everything except the change, and show what it would do"
      echo "  --for-real  do it"
      [ "$allow" = allow-dev ] && echo "  --to-dev    test send to FLEET_DEV_EMAIL only"
      echo "see: $see"
    } >&2
    exit 2
  fi
}

# ── one run of a lane at a time ─────────────────────────────────────────────
#
#   fleet_lock digest-daily real   # a real run: waits for the other run
#   fleet_lock digest-daily dry    # a dry run or test send: refuses at once
#
# A lane's runs take $FLEET_HOME/state/locks/<lane>.lock. A dry run (and a
# test send, which is a dry run except at the mailer) that finds the lock held
# prints who holds it and exits 75 without touching anything. A real run
# waits up to FLEET_LOCK_WAIT_SECONDS (default 600, under every unit's
# TimeoutStartSec) for the other run to end. If that run is still going:
#   - another REAL run: return 75, and the runner fails the way it fails for
#     anything else. Two real runs at once could send twice.
#   - a dry run or test send: go ahead without the lock, with a warning. A
#     rehearsal writes only its own files (fleet_dryrun_dir), so the overlap
#     costs shared outside sessions at worst (the PoD log session allows one
#     reader per token, and the domains lane holds when it is refused) - never
#     the timer's run. A long rehearsal must not cost the day's digest.
#
# The lock is flock(2) on file descriptor 9, which the runner and everything
# it starts hold open until they exit, so the kernel releases it on any way
# out - kill -9 included - and there is no stale lock to clear. python3 takes
# it because macOS has no flock(1).
fleet_lock() {
  local lane="$1" kind="$2" dir rc=0 wait=0 holder
  dir="${FLEET_HOME:?FLEET_HOME is not set}/state/locks"
  mkdir -p "$dir"
  chmod 0700 "$dir" 2>/dev/null || true
  exec 9>>"$dir/$lane.lock"
  chmod 0600 "$dir/$lane.lock" 2>/dev/null || true
  if [ "$kind" = real ]; then
    wait="${FLEET_LOCK_WAIT_SECONDS:-600}"
    case "$wait" in ''|*[!0-9]*) wait=600 ;; esac
  fi
  python3 -I -c '
import fcntl, os, sys, time
wait, who = int(sys.argv[1]), sys.argv[2]
deadline = time.monotonic() + wait
while True:
    try:
        fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        break
    except BlockingIOError:
        left = deadline - time.monotonic()
        if left <= 0:
            sys.exit(75)
        time.sleep(min(5.0, left))
os.ftruncate(9, 0)
os.write(9, (who + "\n").encode())
' "$wait" "pid $$, $kind run, started $(date '+%F %T')" || rc=$?
  [ "$rc" = 0 ] && return 0
  holder="$(head -n 1 "$dir/$lane.lock" 2>/dev/null || true)"
  if [ "$rc" != 75 ]; then
    echo "$lane: could not take the lane lock $dir/$lane.lock" >&2
    exit 1
  fi
  if [ "$kind" = real ]; then
    case "$holder" in
      *", dry run,"*)
        echo "$lane: WARNING: a rehearsal (${holder}) still holds the lane lock after ${wait}s;" \
             "going ahead without it - a rehearsal writes only its own files" >&2
        return 0 ;;
    esac
    echo "$lane: another run of this lane (${holder:-unknown}) still held the lane lock after ${wait}s" >&2
    return 75
  fi
  echo "$lane: another run of this lane is in progress (${holder:-unknown})." >&2
  echo "$lane: a dry run never waits for it or runs beside it - try again when it has finished." >&2
  exit 75
}

# ── where a dry run writes ──────────────────────────────────────────────────
#
#   OUT="$(fleet_dryrun_dir digest-daily)"
#
# A dry run and a test send write every file of theirs under
# $FLEET_HOME/dryrun/<lane>/, emptied at the start of each one, and never the
# real run's files in state/ or reports/: a same-day dry run used to replace
# the files a real run had written (the record of what was sent) or delete
# them while it was still using them. Nothing in the fleet reads dryrun/. The
# lane lock is held, so no other dry run of the lane is using the directory.
fleet_dryrun_dir() {
  local d="${FLEET_HOME:?FLEET_HOME is not set}/dryrun/$1"
  # Checked by hand: it runs inside $(...), where bash does not apply -e, and
  # a directory that could not be emptied would hand the runner the last
  # rehearsal's files as this one's.
  mkdir -p "$FLEET_HOME/dryrun" || return 1
  chmod 0700 "$FLEET_HOME/dryrun" 2>/dev/null || true
  if ! { rm -rf "$d" && mkdir -m 0700 "$d"; }; then
    echo "cannot make a fresh $d" >&2
    return 1
  fi
  printf '%s\n' "$d"
}
