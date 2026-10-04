#!/usr/bin/env bash
#
# stop-fedora.sh - take the CTI fleet off the schedule without removing it.
#
# WHY THIS EXISTS SEPARATELY FROM install-fedora.sh --uninstall
#
#   --uninstall removes the units. --purge removes the state too. Both are the
#   wrong tool for "the host is going down for an hour" and for "this box is
#   now the test box and prod is somewhere else", because both throw away the
#   install you will want back.
#
#   This stops and disables the timers and touches nothing else. No unit files
#   removed, no config, no state, no mail. Reversible with --resume.
#
# THE CASE THIS REALLY EXISTS FOR
#
#   Two hosts running this fleet against the SAME mailbox is not "two copies of
#   an email". The cleanup lane archives advisories once a completed run has
#   read them - and a run on host A archives mail that host B has not ingested
#   yet. B then reports a quiet day it did not have. That exact collision
#   already cost three advisories, with no error anywhere; it was only noticed
#   because a human recognised two senders that should have appeared.
#
#   So when you stand up a production host, bring the old one off the schedule
#   FIRST. Not afterwards, and not "in a minute".
#
# USAGE
#   sudo ./stop-fedora.sh                 stop and disable every timer
#   sudo ./stop-fedora.sh --decommission  also mask them, so enabling needs a
#                                         deliberate unmask - for the box that
#                                         is no longer production
#   sudo ./stop-fedora.sh --resume        re-enable and start the timers
#   sudo ./stop-fedora.sh --status        report what is scheduled, change nothing
#   sudo ./stop-fedora.sh --dry-run       print what would happen
#   sudo ./stop-fedora.sh --force         do not wait for a run in flight
#
# WHAT IT DELIBERATELY DOES NOT DO
#   Nothing to /etc/cti-agent, /var/lib/cti-agent, the mailbox, or Jira. A
#   paused fleet keeps its credentials, its seen-CVE database and its ticket
#   map, so resuming is a resume and not a re-onboarding.
set -euo pipefail
set -E

UNIT_DIR=/etc/systemd/system
CONF_DIR=/etc/cti-agent
MODE=stop
DRYRUN=0
FORCE=0
WAIT_SECONDS=120

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
run()  { if [ "$DRYRUN" = 1 ]; then info "would run: $*"; else "$@"; fi; }

# Same reasoning as install-fedora.sh: `set -e` exits silently, and a half-done
# stop is worse than a failed one because the operator believes the fleet is
# off. An installer that died four lines after "daemon-reload" taught us this;
# the stakes here are higher, because the thing you are wrong about is whether
# a second host is still sending mail.
EXPECTED_EXIT=0
bail() { EXPECTED_EXIT=1; exit "${1:-1}"; }
_err_line=""; _err_rc=""
trap '_err_rc=$?; _err_line=$LINENO' ERR
_on_exit() {
  local rc=$?
  if [ "$EXPECTED_EXIT" = 1 ]; then return 0; fi
  if [ "$rc" = 0 ] && [ -z "$_err_line" ]; then return 0; fi
  printf '\n\033[31m✗ stop-fedora.sh stopped at line %s (status %s)\033[0m\n' \
    "${_err_line:-unknown}" "${_err_rc:-$rc}" >&2
  printf '    Some timers may STILL BE ACTIVE. Do not assume this host is\n' >&2
  printf '    off the schedule. Check it yourself:\n' >&2
  printf '      systemctl list-timers "cti-agent-*" --all\n' >&2
}
trap _on_exit EXIT

while [ $# -gt 0 ]; do
  case "$1" in
    --decommission) MODE=decommission ;;
    --resume)       MODE=resume ;;
    --status)       MODE=status ;;
    --dry-run)      DRYRUN=1 ;;
    --force)        FORCE=1 ;;
    -h|--help)      sed -n '2,40p' "${BASH_SOURCE[0]}"; bail 0 ;;
    *) echo "unknown option: $1" >&2; bail 2 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || { bad "run with sudo"; bail 1; }
command -v systemctl >/dev/null || { bad "systemd not found"; bail 1; }

# Derived from what is installed, never a hand-written list.
#
# The installer shipped run-mailbox-cleanup uninstalled for weeks because one
# place listed the files by hand and another asserted they existed. A stop
# script with a stale list is the same bug with a worse consequence: the timer
# it forgot is the one still sending mail.
timers=()
while IFS= read -r t; do
  [ -n "$t" ] && timers+=("$(basename "$t")")
done < <(find "$UNIT_DIR" -maxdepth 1 -name 'cti-agent-*.timer' -print 2>/dev/null | sort)

if [ ${#timers[@]} -eq 0 ]; then
  warn "no cti-agent timers found in $UNIT_DIR"
  info "nothing to do - this host may never have had the fleet installed,"
  info "or install-fedora.sh --uninstall has already removed it."
  EXPECTED_EXIT=1
  exit 0
fi

# ── report ──────────────────────────────────────────────────────────────────

report() {
  bold "Scheduled on this host"
  local any=0
  for t in "${timers[@]}"; do
    local state enabled
    state="$(systemctl is-active "$t" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$t" 2>/dev/null || true)"
    case "$state/$enabled" in
      active/enabled)  ok   "$t  active, enabled"; any=1 ;;
      active/*)        warn "$t  active but $enabled"; any=1 ;;
      */masked)        info "$t  masked"  ;;
      *)               info "$t  $state, $enabled" ;;
    esac
  done
  [ "$any" = 0 ] || return 0
  return 0
}

running_services() {
  # A service unit that is active is a lane mid-run. `|| true` on the grep
  # because "nothing is running" is the common case and exits 1, which under
  # `set -o pipefail` would end this script - the bug this project fixed in
  # four other places this week.
  systemctl list-units --type=service --state=running --no-legend 'cti-agent-*' 2>/dev/null \
    | awk '{print $1}' || true
}

if [ "$MODE" = status ]; then
  report
  busy="$(running_services)"
  if [ -n "$busy" ]; then
    bold "Running right now"
    printf '%s\n' "$busy" | sed 's/^/    /'
  fi
  EXPECTED_EXIT=1
  exit 0
fi

# ── resume ──────────────────────────────────────────────────────────────────

if [ "$MODE" = resume ]; then
  bold "Resuming"
  for t in "${timers[@]}"; do
    if [ "$(systemctl is-enabled "$t" 2>/dev/null || true)" = masked ]; then
      run systemctl unmask "$t"
    fi
    run systemctl enable --now "$t"
    ok "$t"
  done
  run systemctl daemon-reload

  bold "Verification"
  fail=0
  for t in "${timers[@]}"; do
    if [ "$DRYRUN" = 1 ]; then continue; fi
    if [ "$(systemctl is-active "$t" 2>/dev/null || true)" != active ]; then
      bad "$t did not start"; fail=1
    fi
  done
  if [ "$fail" = 1 ]; then
    info "journalctl -u <unit> -n 30 --no-pager"
    bail 1
  fi
  ok "all timers active"
  systemctl list-timers 'cti-agent-*' --all --no-pager 2>/dev/null | sed 's/^/    /' || true

  # Resuming after another host has been live is the dangerous direction.
  bold "Before you walk away"
  info "If another host has been running this fleet against the same mailbox,"
  info "stop it FIRST. Two hosts archiving the same shared mailbox will each"
  info "report quiet days the other caused, and nothing will error."
  EXPECTED_EXIT=1
  exit 0
fi

# ── stop ────────────────────────────────────────────────────────────────────

report

# Do not kill a run in flight by default.
#
# A digest that is SIGTERMed between "Graph accepted the send" and "the ledger
# recorded it" leaves no record of a mail that went out, and the duplicate-send
# guard then cannot stop the next run from sending it again. Waiting is cheap;
# the lanes are minutes at worst.
busy="$(running_services)"
if [ -n "$busy" ] && [ "$FORCE" = 0 ] && [ "$DRYRUN" = 0 ]; then
  bold "A lane is running"
  printf '%s\n' "$busy" | sed 's/^/    /'
  info "Waiting up to ${WAIT_SECONDS}s rather than interrupting it."
  info "A digest killed between sending and recording the send leaves no"
  info "record of a mail that went out, and the duplicate guard cannot then"
  info "stop the next run from sending it twice."
  waited=0
  while [ -n "$(running_services)" ] && [ "$waited" -lt "$WAIT_SECONDS" ]; do
    sleep 5
    waited=$((waited + 5))
  done
  if [ -n "$(running_services)" ]; then
    bad "still running after ${WAIT_SECONDS}s"
    info "Re-run with --force to stop it anyway, then check whether a digest"
    info "went out that the ledger does not know about:"
    info "  sudo cti-agent fleet-db recent"
    bail 1
  fi
  ok "finished after ${waited}s"
fi

bold "Stopping"
for t in "${timers[@]}"; do
  run systemctl stop "$t"
  run systemctl disable "$t" >/dev/null 2>&1 || true
  if [ "$MODE" = decommission ]; then
    run systemctl mask "$t"
    ok "$t  stopped, disabled, masked"
  else
    ok "$t  stopped and disabled"
  fi
done

# The service units too. Stopping a .timer does not stop a .service that is
# mid-run, and with --force that is exactly the situation we may be in.
for t in "${timers[@]}"; do
  s="${t%.timer}.service"
  if systemctl cat "$s" >/dev/null 2>&1; then
    run systemctl stop "$s" >/dev/null 2>&1 || true
  fi
done
run systemctl daemon-reload

# ── verification ────────────────────────────────────────────────────────────
#
# "Stopped" has to be checked, not announced. Everything else in this project
# that reported success while doing nothing did so because the report was
# written next to the intent rather than next to the result.

bold "Verification"
FAIL=0
if [ "$DRYRUN" = 1 ]; then
  info "dry run - nothing was changed, so nothing is verified"
else
  for t in "${timers[@]}"; do
    state="$(systemctl is-active "$t" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$t" 2>/dev/null || true)"
    if [ "$state" = active ]; then
      bad "$t is STILL ACTIVE"; FAIL=1
      continue
    fi
    case "$enabled" in
      enabled) bad "$t is stopped but still enabled - it will come back on reboot"
               FAIL=1 ;;
      masked)  ok "$t  stopped and masked" ;;
      *)       ok "$t  stopped and disabled" ;;
    esac
  done
  busy="$(running_services)"
  if [ -n "$busy" ]; then
    bad "service units still running:"
    printf '%s\n' "$busy" | sed 's/^/      /'
    FAIL=1
  fi
fi

if [ "$FAIL" != 0 ]; then
  bad "this host is NOT off the schedule"
  info "Do not start a second host until the above is resolved."
  bail 1
fi

EXPECTED_EXIT=1
cat <<DONE

$(printf '\033[1mOff the schedule. Nothing was removed.\033[0m')

  Config, state, the seen-CVE database and the Jira ticket map are all
  untouched at $CONF_DIR and /var/lib/cti-agent.

  Resume:        sudo ./stop-fedora.sh --resume
  Check:         sudo ./stop-fedora.sh --status
  Remove units:  sudo ./install-fedora.sh --uninstall

$(if [ "$MODE" = decommission ]; then
  printf '  The timers are MASKED. "systemctl enable --now" will refuse until\n'
  printf '  somebody unmasks them, which is the point: this box should not\n'
  printf '  quietly start sending again alongside production.\n'
fi)
  One thing this script cannot check: whether anything OTHER than systemd
  still runs these lanes. A leftover cron entry or a hand-started loop is
  invisible here and would keep this host live against the shared mailbox.

    sudo crontab -l 2>/dev/null | grep -i cti || echo "  no root crontab entries"
    ls -la /etc/cron.d/ | grep -i cti || true
DONE
