#!/usr/bin/env bash
# update-fedora.sh - bring the box up to date: pull the kit, then run the installer.
#
#   sudo cti-agent-update --dry-run     fetch, show what is incoming, change nothing
#   sudo cti-agent-update --for-real    pull the kit, then run the installer from it
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
# FLEET_UPDATE_UID exists for the tests: it stands in for `id -u` so the root
# check can be exercised without being root. install-fedora.sh checks root itself.
set -euo pipefail

main() {
  local here kit
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../fleet-kit
  kit="$(cd "$here/.." && pwd)"                          # the repository root
  # shellcheck source=fleet/share/fleet-mode.sh
  . "$here/fleet/share/fleet-mode.sh"

  local dry="" real=""
  for a in "$@"; do
    case "$a" in
      --dry-run)  dry=1 ;;
      --for-real) real=1 ;;
      --uninstall|--purge) echo "update-fedora: $a is the installer's, run install-fedora.sh for it" >&2; exit 2 ;;
      -h|--help) echo "usage: sudo cti-agent-update --dry-run|--for-real   (man cti-agent-update)"; exit 0 ;;
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
  git -C "$kit" fetch --tags --quiet
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

  if [ "$incoming" -gt 0 ]; then
    git -C "$kit" merge --ff-only --quiet '@{u}' \
      || { echo "update-fedora: the kit cannot be fast-forwarded (it has diverged from its upstream)" >&2; exit 1; }
  fi
  local after
  after="$(git -C "$kit" describe --tags --always)"
  echo "kit      : $before -> $after ($incoming new commit(s))"
  case "$after" in
    *-[0-9]*-g*) echo "note     : this is $after, not an exact release tag. If you expected a release, check the tag was pushed." ;;
  esac
  echo "installing from the updated kit..."
  # exec: the installer replaces this process. This file may just have changed on
  # disk, and a shell must not read another line of a script that was rewritten
  # under it.
  exec "$here/install-fedora.sh"
}

# One line, so bash has read all of it before main can change this file.
main "$@"; exit "$?"
