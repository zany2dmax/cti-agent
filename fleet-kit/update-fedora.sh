#!/usr/bin/env bash
# update-fedora.sh - bring the box up to date: pull the kit, then run the installer.
#
#   sudo cti-agent-update --dry-run     fetch, show what is incoming, change nothing
#   sudo cti-agent-update --for-real    pull the kit, then run the installer from it
#   sudo cti-agent-update --rollback --dry-run|--for-real
#                                       put back the install before the last update
#
# (After the first install, `cti-agent-update` is on the box. Before that, run
# this file by its path: sudo /root/cti-agent-kit/fleet-kit/update-fedora.sh --for-real)
#
# WHY THIS IS ITS OWN STEP, AND WHY IT PULLS FIRST
#
# There are two checkouts on the box. This is the KIT: install-fedora.sh itself,
# the runners, the units, the manifest, the man pages. The installer pulls the
# other one, the Go SOURCE under /opt/cti-agent/agent, itself, partway through.
# Nothing pulls the kit, and the installer runs FROM it, so without this step an
# update runs last release's installer over last release's files and builds this
# release's source - an install that is neither version. Pulling the kit first,
# then handing over, is the whole job.
#
# It says how to run, like every command that changes something: --dry-run or
# --for-real, no default. A dry run does not merge anything, because an installer
# run from the old checkout would describe the old install, not the update.
#
# Nothing else is accepted, and nothing is passed to the installer. The only
# options it takes are --dry-run (this script's own), --uninstall and --purge
# (not an update: run the installer for those), so passing arguments on could
# only ever fail - and it would fail after the pull, a box half-updated by a
# typo. An unknown argument stops it here, before anything is fetched.
#
# A SNAPSHOT BEFORE EVERY INSTALL, AND A WAY BACK. Before --for-real runs the
# installer it saves what that run replaces: the kit's and the Go source's
# commits, the code directory (/opt/cti-agent, without the source checkout,
# which is put back by commit), the config directory, the fleet's systemd
# units and drop-ins, and a copy of memory.db. They go in
# /var/lib/cti-agent-update/<time>/, root-only; the last three are kept. If the
# installer fails, all of it is put back at once, the database included, and
# the update exits with the installer's status. `--rollback --for-real` puts
# back the latest snapshot by hand, later, and then leaves the database as it
# is (lanes have written to it since; the snapshot's copy is named for anyone
# who needs it). Commands installed outside those directories (cti-agent-update,
# the root tools, man pages, completions) stay at the newer version until the
# next install.
#
# FLEET_UPDATE_UID exists for the tests: it stands in for `id -u` so the root
# check can be exercised without being root. install-fedora.sh checks root itself.
# CTI_UPDATE_ROOT likewise puts every path the snapshot touches under a test
# directory; on a box it is unset and the paths are the FHS ones.
set -euo pipefail

R="${CTI_UPDATE_ROOT:-}"
SNAPS="$R/var/lib/cti-agent-update"
CODE="$R/opt/cti-agent"
CONF="$R/etc/cti-agent"
UNITS="$R/etc/systemd/system"
STATE_DB="$R/var/lib/cti-agent/state/memory.db"
KEEP=3

# A release tag moved upstream with the branch history intact: only the tag
# needs replacing. Printed, never run: moving a release is a decision, and a
# moved tag can point at different code.
moved_tag_help() {
  local kit="$1"; shift
  local t
  {
    echo
    echo "Release tag(s) moved upstream after this box fetched them: $*."
    echo "The branch history is intact, so only the tag needs replacing. Delete the"
    echo "old tag in both checkouts, then run the update again:"
    echo
    for t in "$@"; do
      echo "  sudo git -C $kit tag -d $t"
      echo "  sudo git -C /opt/cti-agent/agent tag -d $t"
    done
    echo "  sudo cti-agent-update --for-real"
  } >&2
}

# snapshot KIT - save what an install replaces; print the snapshot's path.
snapshot() {
  local kit="$1" d
  d="$SNAPS/$(date -u '+%Y%m%dT%H%M%SZ')"
  mkdir -p "$SNAPS"
  chmod 0700 "$SNAPS"
  mkdir -m 0700 "$d"
  git -C "$kit" rev-parse HEAD > "$d/kit-rev"
  if [ -d "$CODE/agent/.git" ]; then git -C "$CODE/agent" rev-parse HEAD > "$d/agent-rev"; fi
  if [ -d "$CODE" ]; then tar -czf "$d/code.tgz" -C "$CODE" --exclude ./agent .; fi
  if [ -d "$CONF" ]; then tar -czf "$d/conf.tgz" -C "$CONF" .; fi
  ( cd "$UNITS" 2>/dev/null && shopt -s nullglob && set -- cti-agent-* && \
    if [ $# -gt 0 ]; then tar -czf "$d/units.tgz" "$@"; fi ) || true
  if [ -f "$STATE_DB" ]; then
    python3 -c 'import sqlite3, sys
s, d = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
s.backup(d)
d.close(); s.close()' "$STATE_DB" "$d/memory.db"
  fi
  # The newest $KEEP; older ones go.
  local all=("$SNAPS"/2*/) n i
  n=${#all[@]}
  for ((i = 0; i < n - KEEP; i++)); do rm -rf -- "${all[i]%/}"; done
  printf '%s\n' "$d"
}

# latest_snapshot - the newest snapshot's path, or nothing.
latest_snapshot() {
  local all=("$SNAPS"/2*/)
  [ -d "${all[0]}" ] || return 0
  printf '%s\n' "${all[${#all[@]} - 1]%/}"
}

# lanes_running - the fleet's services running now, one per line.
lanes_running() {
  command -v systemctl >/dev/null || return 0
  [ -z "$R" ] || return 0
  systemctl list-units --type=service --state=active,activating --no-legend 'cti-agent-*' 2>/dev/null \
    | awk '{print $1}' | grep -v '^cti-agent-alert@' || true
}

# restore SNAPSHOT KIT WITH_DB - put the snapshot back.
restore() {
  local d="$1" kit="$2" with_db="$3" running
  running="$(lanes_running)"
  if [ -n "$running" ]; then
    echo "update-fedora: not rolling back while a lane is running: $running" >&2
    echo "  Run it again when it finishes: sudo cti-agent-update --rollback --for-real" >&2
    return 1
  fi
  case "$CODE" in /|"") echo "update-fedora: refusing to restore into '$CODE'" >&2; return 1 ;; esac
  git -C "$kit" reset --quiet --hard "$(cat "$d/kit-rev")"
  if [ -f "$d/agent-rev" ] && [ -d "$CODE/agent/.git" ]; then
    git -C "$CODE/agent" reset --quiet --hard "$(cat "$d/agent-rev")"
  fi
  if [ -f "$d/code.tgz" ]; then
    find "$CODE" -mindepth 1 -maxdepth 1 ! -name agent -exec rm -rf -- {} +
    tar -xzf "$d/code.tgz" -C "$CODE"
  fi
  if [ -f "$d/conf.tgz" ]; then
    find "$CONF" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    tar -xzf "$d/conf.tgz" -C "$CONF"
  fi
  if [ -f "$d/units.tgz" ]; then
    ( cd "$UNITS" && shopt -s nullglob && set -- cti-agent-* && if [ $# -gt 0 ]; then rm -rf -- "$@"; fi )
    tar -xzf "$d/units.tgz" -C "$UNITS"
    if command -v systemctl >/dev/null && [ -z "$R" ]; then systemctl daemon-reload; fi
  fi
  if [ "$with_db" = 1 ] && [ -f "$d/memory.db" ]; then
    cp -p -- "$d/memory.db" "$STATE_DB"
  fi
  return 0
}

# rollback KIT DRY - --rollback: put back the latest snapshot, or say what it holds.
rollback() {
  local kit="$1" dry="$2" d
  d="$(latest_snapshot)"
  if [ -z "$d" ]; then
    echo "update-fedora: no snapshot to roll back to in $SNAPS (one is taken before every update)" >&2
    return 1
  fi
  echo "snapshot : $d"
  echo "kit      : $(git -C "$kit" describe --tags --always) -> $(git -C "$kit" describe --tags --always "$(cat "$d/kit-rev")")"
  echo "restores : the code in $CODE (the Go source by commit), the config in $CONF,"
  echo "           the fleet's systemd units; NOT memory.db (lanes wrote to it since; the"
  echo "           snapshot's copy is $d/memory.db)"
  if [ -n "$dry" ]; then
    echo
    echo "Dry run: nothing was restored. Config changed since the snapshot would be lost."
    return 0
  fi
  restore "$d" "$kit" 0 || return 1
  echo "Rolled back to the install from $(basename "$d")."
}

# The one-time fix after the upstream's history was rewritten (scrub-history.sh):
# both checkouts on the box - this kit and the source the installer pulls - hold
# the old history and tags, and neither a fetch nor a fast-forward will replace
# them. Printed, never run: a reset discards whatever the checkout holds, and
# that is the operator's decision after reading why.
rewritten_history_help() {
  local kit="$1"
  cat >&2 <<HELP

If the upstream's history was rewritten on purpose (for example by
scripts/scrub-history.sh), reset both checkouts on this box to it once, then
run the update again:

  sudo git -C $kit status --short          # must print nothing
  sudo git -C $kit fetch --force --tags origin
  sudo git -C $kit reset --hard '@{u}'
  sudo git -C /opt/cti-agent/agent fetch --force --tags origin
  sudo git -C /opt/cti-agent/agent reset --hard '@{u}'
  sudo cti-agent-update --dry-run

If you did not rewrite it, stop: find out who did before resetting anything.
HELP
}

main() {
  local here kit
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../fleet-kit
  kit="$(cd "$here/.." && pwd)"                          # the repository root
  # shellcheck source=fleet/share/fleet-mode.sh
  . "$here/fleet/share/fleet-mode.sh"

  local dry="" real="" back=""
  for a in "$@"; do
    case "$a" in
      --dry-run)  dry=1 ;;
      --for-real) real=1 ;;
      --rollback) back=1 ;;
      --uninstall|--purge) echo "update-fedora: $a is the installer's, run install-fedora.sh <mode> for it" >&2; exit 2 ;;
      -h|--help) echo "usage: sudo cti-agent-update [--rollback] --dry-run|--for-real   (man cti-agent-update)"; exit 0 ;;
      *) echo "update-fedora: unknown argument: $a - nothing was fetched or installed" >&2
         echo "usage: sudo cti-agent-update --dry-run|--for-real" >&2; exit 2 ;;
    esac
  done
  fleet_require_mode update-fedora "$dry" "$real" "" "" "sudo cti-agent-update --dry-run|--for-real"

  # Same refusal as the installer, for the same reason: from inside the tree the
  # installer pulls, the second half of an update would be new files driven by an
  # old script.
  case "$here" in
    /opt/cti-agent|/opt/cti-agent/*)
      echo "REFUSING: running from $here, inside the tree the installer pulls." >&2
      echo "Use the kit checkout instead: /root/cti-agent-kit/fleet-kit/update-fedora.sh" >&2
      exit 2 ;;
  esac
  if [ -n "$real" ] && [ "${FLEET_UPDATE_UID:-$(id -u)}" != 0 ]; then
    echo "update-fedora: --for-real changes the install and needs sudo" >&2; exit 1
  fi
  git -C "$kit" rev-parse --git-dir >/dev/null 2>&1 \
    || { echo "update-fedora: $kit is not a git checkout" >&2; exit 1; }
  if [ -n "$back" ]; then
    rollback "$kit" "$dry"
    exit "$?"
  fi

  # A kit with local edits cannot be fast-forwarded safely, and a box's kit should
  # have none. Say so rather than merge over them.
  if [ -n "$(git -C "$kit" status --porcelain --untracked-files=no)" ]; then
    echo "update-fedora: the kit checkout has local changes, so it will not be updated:" >&2
    git -C "$kit" status --short --untracked-files=no >&2
    echo "Discard them (git -C $kit checkout -- .) or move them, then run this again." >&2
    exit 1
  fi
  git -C "$kit" rev-parse --abbrev-ref '@{u}' >/dev/null 2>&1 \
    || { echo "update-fedora: the kit's branch has no upstream to update from" >&2; exit 1; }

  # Tags too: the installer stamps the version from the nearest tag, and a tag
  # pushed after the commit it names is how a box ends up reporting 1.5.1-2.
  #
  # Not --quiet: with it, git says nothing at all when it refuses, for example a
  # tag that now names a different commit ("would clobber existing tag", after
  # the history was rewritten), and set -e then ended this script without a
  # word. The output is kept and shown only if the fetch fails.
  local fetched
  if ! fetched="$(git -C "$kit" fetch --tags 2>&1)"; then
    echo "update-fedora: could not fetch the kit's upstream, so nothing was pulled or installed." >&2
    # Remote text: printable characters only, so it cannot drive the terminal.
    printf '%s\n' "$fetched" | LC_ALL=C tr -cd '\11\12\40-\176' | sed 's/^/  git: /' >&2
    case "$fetched" in
      *"would clobber existing tag"*)
        # Only the tag moved, or the history was rewritten? git still updated
        # the branch it could, so the kit's HEAD is an ancestor of its upstream
        # exactly when the history is intact.
        local moved
        moved="$(printf '%s\n' "$fetched" | sed -n 's/.*\[rejected\] *\([A-Za-z0-9._/-]*\) *-> .*would clobber existing tag.*/\1/p' | tr '\n' ' ')"
        if [ -n "$moved" ] && git -C "$kit" merge-base --is-ancestor HEAD '@{u}' 2>/dev/null; then
          # shellcheck disable=SC2086 # tag names, no spaces
          moved_tag_help "$kit" $moved
        else
          rewritten_history_help "$kit"
        fi ;;
    esac
    exit 1
  fi
  local before upstream incoming
  before="$(git -C "$kit" describe --tags --always)"
  upstream="$(git -C "$kit" describe --tags --always '@{u}')"
  incoming="$(git -C "$kit" rev-list --count 'HEAD..@{u}')"

  if [ -n "$dry" ]; then
    echo "kit      : $kit"
    echo "now      : $before"
    echo "available: $upstream  ($incoming new commit(s))"
    if [ "$incoming" -gt 0 ]; then
      echo
      git -C "$kit" log --oneline 'HEAD..@{u}'
      echo
      git -C "$kit" diff --stat 'HEAD' '@{u}' | tail -1
    else
      echo "The kit is already up to date; --for-real would still re-run the installer."
    fi
    echo
    echo "Dry run: nothing was pulled and nothing was installed."
    exit 0
  fi

  local prev
  prev="$(git -C "$kit" rev-parse HEAD)"
  if [ "$incoming" -gt 0 ]; then
    git -C "$kit" merge --ff-only --quiet '@{u}' \
      || { echo "update-fedora: the kit cannot be fast-forwarded (it has diverged from its upstream)" >&2
           rewritten_history_help "$kit"; exit 1; }
  fi
  local after
  after="$(git -C "$kit" describe --tags --always)"
  echo "kit      : $before -> $after ($incoming new commit(s))"
  case "$after" in
    *-[0-9]*-g*) echo "note     : this is $after, not an exact release tag. If you expected a release, check the tag was pushed." ;;
  esac
  # The snapshot names the commit the kit was on BEFORE the pull, so a failed
  # install goes back to the install that worked.
  local snap rc=0
  snap="$(snapshot "$kit")" || snap=""
  if [ -z "$snap" ] || [ ! -d "$snap" ]; then
    echo "update-fedora: could not take the snapshot an update can be rolled back to, so nothing was installed" >&2
    exit 1
  fi
  printf '%s\n' "$prev" > "$snap/kit-rev"
  echo "snapshot : $snap"
  echo "installing from the updated kit..."
  # A child, not exec, so a failure can be put back. This file may just have
  # changed on disk, which is safe: main is already read, and so is its last line.
  "$here/install-fedora.sh" --for-real || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo >&2
    echo "update-fedora: the install failed (exit $rc). Rolling back to the install before it ($before)." >&2
    if restore "$snap" "$kit" 1; then
      echo "update-fedora: rolled back. The box runs $before again; fix the cause and run the update again." >&2
    else
      echo "update-fedora: the rollback did not finish; run: sudo cti-agent-update --rollback --for-real" >&2
    fi
    exit "$rc"
  fi
  if command -v cti-agent-doctor >/dev/null; then
    echo
    cti-agent-doctor || echo "note     : cti-agent-doctor found something to look at (above). The update itself is done."
  fi
}

# One line, so bash has read all of it before main can change this file.
main "$@"; exit "$?"
