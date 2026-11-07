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
