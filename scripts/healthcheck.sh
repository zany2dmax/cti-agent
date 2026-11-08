#!/usr/bin/env bash
# healthcheck.sh - is the fleet up and running properly on this box?
#
# Read-only. It sends no mail, files no tickets, moves no mail and never reads
# fleet.env's contents (only its owner and mode). Each check prints PASS, WARN
# or FAIL, and the exit status is the verdict, so it can sit behind a cron job
# or a quick `&& echo ok` after a reboot or an upgrade.
#
#   sudo scripts/healthcheck.sh          # local checks, about ten seconds
#   sudo scripts/healthcheck.sh --deep   # also logs in to Graph and Jira and
#                                        # compares the install with GitHub
#
# Exit status: 0 all PASS, 1 at least one FAIL, 2 usage or not root.
# WARNs do not fail the run: they are things a person should look at, not
# evidence the fleet is down.
#
# Written for the install-fedora.sh layout: code in /opt/cti-agent, config in
# /etc/cti-agent, state in /var/lib/cti-agent, account ctiagent.
set -uo pipefail

CODE_DIR=/opt/cti-agent
CONF_DIR=/etc/cti-agent
STATE_DIR=/var/lib/cti-agent
FLEET_USER=ctiagent
FLEET_GROUP=ctiagent
# The oldest Go that carries the standard-library fix govulncheck last failed
# the ship on (GO-2026-6809). Builds happen on this box, so its Go matters.
GO_MIN=1.26.10
REPO_URL=https://github.com/zany2dmax/cti-agent.git

DEEP=0
case "${1:-}" in
  "") ;;
  --deep) DEEP=1 ;;
  -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "usage: $0 [--deep]" >&2; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo "run it with sudo: it reads the journal and root-owned config" >&2; exit 2; }

PASSES=0 WARNS=0 FAILS=0
if [ -t 1 ]; then G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' B=$'\033[1m' N=$'\033[0m'
else G="" Y="" R="" B="" N=""; fi
pass() { PASSES=$((PASSES + 1)); printf '  %sPASS%s  %s\n' "$G" "$N" "$*"; }
warn() { WARNS=$((WARNS + 1));   printf '  %sWARN%s  %s\n' "$Y" "$N" "$*"; }
fail() { FAILS=$((FAILS + 1));   printf '  %sFAIL%s  %s\n' "$R" "$N" "$*"; }
info() { printf '        %s\n' "$*"; }
section() { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
# Indented output of a command, so it reads as evidence under its check.
show() { sed 's/^/        /'; }

# `cti-agent` is the installer's wrapper: it runs a fleet command as the
# service account with fleet.env loaded, the way the timers do.
fleet() { /usr/local/bin/cti-agent "$@"; }

# ver_ge A B: is dotted version A >= B?
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }

printf '%sCTI fleet health check%s  %s on %s\n' "$B" "$N" "$(date '+%F %T %Z')" "$(hostname)"

# ── host ─────────────────────────────────────────────────────────────────────
section "Host"
info "$(grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"')"
info "kernel $(uname -r), up $(uptime -p 2>/dev/null | sed 's/^up //')"

if [ "$(systemctl is-system-running 2>/dev/null)" = running ]; then
  pass "systemd reports the system running"
else
  warn "systemd reports: $(systemctl is-system-running 2>/dev/null) (systemctl --failed lists why)"
fi

# Graph and Jira tokens are time-stamped; a clock that drifted after a reboot
# fails every login in a way that reads like a credential problem.
if [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then
  pass "clock is NTP-synchronised"
else
  warn "clock is not NTP-synchronised - token logins fail on skew (timedatectl status)"
fi

case "$(getenforce 2>/dev/null || echo unknown)" in
  Enforcing) pass "SELinux enforcing" ;;
  Permissive) warn "SELinux permissive - install-fedora.sh is written for enforcing" ;;
  *) warn "SELinux $(getenforce 2>/dev/null || echo 'not found')" ;;
esac

# The state directory holds the findings db, reports and caches.
use="$(df -P "$STATE_DIR" 2>/dev/null | awk 'NR==2 {gsub("%","",$5); print $5}')"
if [ -z "$use" ]; then
  fail "cannot read disk usage for $STATE_DIR"
elif [ "$use" -ge 90 ]; then
  fail "disk holding $STATE_DIR is ${use}% full"
elif [ "$use" -ge 80 ]; then
  warn "disk holding $STATE_DIR is ${use}% full"
else
  pass "disk holding $STATE_DIR is ${use}% full"
fi

# ── install ──────────────────────────────────────────────────────────────────
section "Install"
if [ -f "$CONF_DIR/version" ]; then
  pass "installed: $(grep -E '^(tag|commit)=' "$CONF_DIR/version" | tr '\n' ' ')"
  info "$(grep -E '^installed_at=' "$CONF_DIR/version")"
else
  fail "$CONF_DIR/version missing - was install-fedora.sh run to completion?"
fi
[ -x /usr/local/bin/cti-agent ] && pass "/usr/local/bin/cti-agent wrapper present" \
  || fail "/usr/local/bin/cti-agent wrapper missing - rerun install-fedora.sh"

if command -v go >/dev/null 2>&1; then
  gov="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
  if ver_ge "$gov" "$GO_MIN"; then pass "go $gov (>= $GO_MIN)"
  else warn "go $gov is older than $GO_MIN - govulncheck will fail the next ship (dnf upgrade golang)"; fi
else
  warn "go not installed - the next install-fedora.sh cannot build the binaries"
fi
if command -v python3 >/dev/null 2>&1; then
  pass "$(python3 --version 2>&1) (the Python lanes and fleet-db)"
else
  fail "python3 not found - the Python lanes and fleet-db cannot run"
fi

# ── code integrity ───────────────────────────────────────────────────────────
# The heartbeat refuses to start if its code is writable by the service
# account; this is the same rule over the whole code tree, so a problem shows
# here before it shows as a refused beat.
section "Code integrity"
bad="$(find "$CODE_DIR" "$CODE_DIR/bin" "$CODE_DIR/lanes" -maxdepth 1 \
        \( ! -user root -o -perm /022 \) -print 2>/dev/null | sort -u)"
if [ ! -d "$CODE_DIR/bin" ]; then
  fail "$CODE_DIR/bin missing"
elif [ -n "$bad" ]; then
  fail "code not root-owned, or group/world-writable:"
  printf '%s\n' "$bad" | show
else
  pass "$CODE_DIR, bin/ and lanes/ root-owned, not group- or world-writable"
fi

CLAUDE_PATH=""
for c in /usr/bin/claude /usr/local/bin/claude; do
  [ -x "$c" ] && { CLAUDE_PATH="$c"; break; }
done
if [ -z "$CLAUDE_PATH" ]; then
  fail "no system-wide claude (/usr/bin or /usr/local/bin) - the heartbeat cannot run (dnf install claude-code)"
else
  owner="$(stat -L -c %U "$CLAUDE_PATH")" mode="$(stat -L -c %a "$CLAUDE_PATH")"
  if [ "$owner" = root ] && [ $(( 8#$mode & 8#022 )) -eq 0 ]; then
    pass "claude: $CLAUDE_PATH ($owner $mode, $("$CLAUDE_PATH" --version 2>/dev/null | head -1))"
  else
    fail "claude: $CLAUDE_PATH is $owner $mode - must be root-owned, not group/world-writable"
  fi
fi
if [ -e "$STATE_DIR/.local/bin/claude" ]; then
  warn "a per-account claude is still in $STATE_DIR/.local/bin - unused now, remove it"
fi

# ── config ───────────────────────────────────────────────────────────────────
section "Config"
# check_mode PATH OWNER GROUP MODE
check_mode() {
  local got
  got="$(stat -c '%U:%G %a' "$1" 2>/dev/null)" || { fail "$1 missing"; return; }
  if [ "$got" = "$2:$3 $4" ]; then pass "$1 ($got)"
  else fail "$1 is $got, expected $2:$3 $4"; fi
}
check_mode "$CONF_DIR"          root "$FLEET_GROUP" 750
check_mode "$CONF_DIR/fleet.env" root "$FLEET_GROUP" 640
if [ -f "$CONF_DIR/domains.txt" ]; then check_mode "$CONF_DIR/domains.txt" root "$FLEET_GROUP" 640; fi
if [ -f "$CONF_DIR/app-owners.txt" ]; then check_mode "$CONF_DIR/app-owners.txt" root "$FLEET_GROUP" 640; fi
got="$(stat -c %U "$STATE_DIR" 2>/dev/null || echo missing)"
[ "$got" = "$FLEET_USER" ] && pass "$STATE_DIR owned by $FLEET_USER" \
  || fail "$STATE_DIR owner is $got, expected $FLEET_USER"

# ── systemd ──────────────────────────────────────────────────────────────────
section "Units and timers"
failed="$(systemctl --failed --plain --no-legend 'cti-agent-*' 2>/dev/null)"
if [ -n "$failed" ]; then
  fail "failed units (systemctl status <unit>, then its journal):"
  printf '%s\n' "$failed" | show
else
  pass "no failed cti-agent units"
fi

timers="$(systemctl list-unit-files --plain --no-legend 'cti-agent-*.timer' 2>/dev/null | awk '{print $1}')"
if [ -z "$timers" ]; then
  fail "no cti-agent timers installed"
fi
for t in $timers; do
  enabled="$(systemctl is-enabled "$t" 2>/dev/null)"
  active="$(systemctl is-active "$t" 2>/dev/null)"
  if [ "$enabled" = enabled ] && [ "$active" = active ]; then
    pass "$t enabled, next: $(systemctl show "$t" -p NextElapseUSecRealtime --value 2>/dev/null)"
  elif [ "$t" = cti-agent-patchtuesday.timer ]; then
    # Off on purpose for now: the articles are saved into the drop folder by hand.
    warn "$t is $enabled/$active (off on purpose for now)"
  else
    fail "$t is $enabled/$active - a disabled timer is silent forever"
  fi
done
info "full schedule: systemctl list-timers 'cti-agent-*'"

# ── journal ──────────────────────────────────────────────────────────────────
section "Journal since boot"
errs="$(journalctl -b -u 'cti-agent-*' --no-pager -q 2>/dev/null \
        | grep -E 'FAILED|ERROR|REFUSING|Traceback|panic:' || true)"
if [ -n "$errs" ]; then
  warn "$(printf '%s\n' "$errs" | wc -l) error line(s) since boot; the last ten:"
  printf '%s\n' "$errs" | tail -10 | cut -c1-200 | show
else
  pass "no FAILED/ERROR lines from cti-agent units since boot"
fi

beat="$(journalctl -u cti-agent-checkin.service -n 300 --no-pager -q 2>/dev/null)"
last_rc="$(printf '%s\n' "$beat" | grep -o 'beat finished rc=[0-9]*' | tail -1 | cut -d= -f2)"
if printf '%s\n' "$beat" | tail -40 | grep -q 'REFUSING to start'; then
  fail "the heartbeat refused to start on its code-integrity check - see 'Code integrity' above"
elif [ -z "$beat" ]; then
  warn "no heartbeat in the journal yet"
elif [ -z "$last_rc" ]; then
  warn "no finished heartbeat in the last 300 journal lines"
elif [ "$last_rc" = 0 ]; then
  pass "last heartbeat finished rc=0"
else
  warn "last heartbeat finished rc=$last_rc (journalctl -u cti-agent-checkin.service -n 80)"
fi
if printf '%s\n' "$beat" | grep -q 'disallowed tools: Edit,Write,NotebookEdit'; then
  pass "heartbeat runs without file-edit tools"
elif [ -n "$beat" ]; then
  warn "no 'disallowed tools' line yet - the build predates e1821be or no beat has run since"
fi
model="$(printf '%s\n' "$beat" | grep -o '\] model: .*' | tail -1 | cut -d' ' -f3-)"
[ -n "$model" ] && info "heartbeat model: $model (CHECKIN_MODEL in fleet.env)"

# ── the fleet's own view ─────────────────────────────────────────────────────
section "Fleet"
if out="$(fleet cti-budget status 2>&1)"; then
  pass "cti-budget status"
else
  fail "cti-budget status failed"
fi
printf '%s\n' "$out" | show

if out="$(fleet fleet-board tail 20 2>&1)"; then
  n="$(printf '%s\n' "$out" | grep -c 'ERROR' || true)"
  if [ "$n" -gt 0 ]; then warn "fleet-board: $n ERROR line(s) in the last 20"
  else pass "fleet-board: no ERROR lines in the last 20"; fi
  printf '%s\n' "$out" | tail -8 | cut -c1-200 | show
else
  fail "fleet-board tail failed"
  printf '%s\n' "$out" | show
fi

if out="$(fleet fleet-db recent 2>&1)"; then
  pass "fleet-db recent (memory db opens)"
  printf '%s\n' "$out" | head -15 | cut -c1-200 | show
else
  fail "fleet-db recent failed - the memory db may be locked or damaged"
  printf '%s\n' "$out" | show
fi

# ── deep: outbound logins ────────────────────────────────────────────────────
# Opt-in because these reach Microsoft Graph, Jira and GitHub. All are checks:
# nothing is sent or written.
if [ "$DEEP" = 1 ]; then
  section "Outbound (--deep)"
  for c in "cti-mailer --check" "mailer.py --check" "cti-jira --check"; do
    # shellcheck disable=SC2086  # word-split on purpose: command plus flag
    if out="$(fleet $c 2>&1)"; then pass "$c"
    else fail "$c"; printf '%s\n' "$out" | tail -15 | show; fi
  done

  installed="$(grep -E '^commit=' "$CONF_DIR/version" 2>/dev/null | cut -d= -f2)"
  latest="$(git ls-remote "$REPO_URL" HEAD 2>/dev/null | cut -c1-${#installed})"
  if [ -z "$latest" ] || [ -z "$installed" ]; then
    warn "cannot compare the install with $REPO_URL"
  elif [ "$installed" = "$latest" ]; then
    pass "install matches the latest published commit ($installed)"
  else
    warn "installed $installed, latest published $latest - the box is behind (RUNBOOK: updating)"
  fi
fi

# ── verdict ──────────────────────────────────────────────────────────────────
printf '\n%s%d pass, %d warn, %d fail%s\n' "$B" "$PASSES" "$WARNS" "$FAILS" "$N"
[ "$DEEP" = 1 ] || info "add --deep to also check the Graph, Jira and GitHub logins"
[ "$FAILS" -eq 0 ]
