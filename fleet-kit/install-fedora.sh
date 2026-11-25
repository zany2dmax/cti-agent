#!/usr/bin/env bash
#
# install-fedora.sh - deploy the CTI fleet on Fedora / RHEL / Rocky / Alma.
#
# WHY THIS LAYOUT
#   The retired generic install.sh put everything under /home/ctiagent, owned
#   by the service account - so the account could rewrite the code it runs -
#   and hardened the units with ProtectHome=read-only plus a ReadWritePaths
#   punch-through into /home, the exact shape SELinux is most likely to deny.
#   This installer, now the only one, uses the FHS layout systemd and SELinux
#   already expect:
#
#     /opt/cti-agent      code, root-owned, read-only to the service
#     /etc/cti-agent      config; fleet.env is 0640 root:ctiagent
#     /var/lib/cti-agent  state, created and chowned by systemd StateDirectory
#
#   Nothing lives under /home, so the units can set ProtectHome=yes and hide it
#   entirely - stricter than the original and less likely to break.
#
# USAGE
#   sudo ./install-fedora.sh --for-real              install or upgrade
#   sudo ./install-fedora.sh --dry-run               print what would happen
#   sudo ./install-fedora.sh --uninstall --for-real  remove units, keep state and config
#   sudo ./install-fedora.sh --purge --for-real      remove everything including state
#   ./install-fedora.sh --help                       this text; touches nothing
#
# Say how to run it: with neither --dry-run nor --for-real it prints usage and
# exits 2 without touching anything. --uninstall and --purge with --dry-run
# only say what they would remove.
#
# It does NOT enable any timer. Enabling is a separate, deliberate step: the
# staged rollout is RUNBOOK.md section 9.
set -euo pipefail
set -E   # so the ERR trap below also fires inside functions and subshells

# ───────────────────────────────────── this script may not end quietly ───────
#
# `set -e` is right for an installer - never continue past a broken step - but
# the exit it performs is SILENT, and silent is what made it dangerous. A run
# died four lines after printing "✓ daemon-reload" with 400 lines still to go.
# It left a box with new units, no wrapper update, no version manifest and no
# verification, and the tail of its output looked exactly like a healthy
# install. The only evidence was a file that did not exist, noticed by chance
# two commands later.
#
# Every other serious bug in this project has had the same shape: something
# reported success while doing nothing. An installer is the worst place for
# it, because the whole point of the Verification block at the end is to be
# the thing that catches that - and a script that dies before reaching it
# skips its own safety net.
#
# So the exit is made to announce itself. INSTALL_DONE is set at exactly one
# place: immediately before the "Installed" banner. Any other way out, for any
# reason, prints what line it happened on and that the box is half-done.
# Deliberate exits go through bail, so the handler can tell "I decided to
# stop and said why" apart from "I fell over". Both end the script; only the
# second is a half-installed box.
EXPECTED_EXIT=0
bail() { EXPECTED_EXIT=1; exit "${1:-1}"; }

_err_line=""; _err_rc=""
_note_err() { _err_rc="$1"; _err_line="$2"; }
trap '_note_err "$?" "$LINENO"' ERR
_on_exit() {
  local rc=$?
  if [ "$EXPECTED_EXIT" = 1 ]; then return 0; fi
  if [ "$rc" = 0 ] && [ -z "$_err_line" ]; then return 0; fi
  printf '\n\033[31m✗ install-fedora.sh stopped at line %s (status %s)\033[0m\n' \
    "${_err_line:-unknown}" "${_err_rc:-$rc}" >&2
  printf '    This box is PARTIALLY installed. Do not enable timers.\n' >&2
  printf '    Nothing after that line ran, which may include the wrapper,\n' >&2
  printf '    %s/version and the whole verification block.\n' \
    "${CONF_DIR:-/etc/cti-agent}" >&2
  printf '    Fix the cause and re-run - this script is idempotent.\n' >&2
}
trap _on_exit EXIT

CODE_DIR=/opt/cti-agent
CONF_DIR=/etc/cti-agent
STATE_DIR=/var/lib/cti-agent
LOG_DIR=/var/log/cti-agent   # the audit trail (cti-audit(1)); systemd units also create it
MAN_DIR=/usr/local/share/man/man1   # every command's man page
UNIT_DIR=/etc/systemd/system
FLEET_USER=ctiagent
FLEET_GROUP=ctiagent
# Where secrets live as systemd credentials (RUNBOOK 11n); ImportCredential= reads it.
CREDSTORE_DIR=/etc/credstore.encrypted
AGENT_REPO=https://github.com/zany2dmax/cti-agent
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Refuse to run from inside the tree this script itself pulls.
#
# $CODE_DIR/agent is a clone that this installer updates mid-run with
# `git -C ... pull --ff-only`. Running from there means the second half of the
# install copies files from the freshly pulled tree while bash is still
# executing the logic it read from the old one. Nothing announces that, and the
# result is an install that is neither version.
#
# It is also the state a box lands in when it was only ever installed from the
# agent clone and never had a separate kit checkout - which is easy to do,
# because that clone does contain a working copy of this script.
# case with a path-boundary glob, not a prefix strip. "${SRC#/opt/cti-agent}"
# also matches /opt/cti-agent-kit and /opt/cti-agent-staging, which are
# perfectly good staging directories, so the first version of this guard
# refused them. A prefix is not a path.
case "$SRC" in
  /opt/cti-agent|/opt/cti-agent/*)
    echo "REFUSING: this script is running from $SRC, inside the tree it pulls." >&2
    echo "" >&2
    echo "Clone the kit somewhere outside the installed layout and run it there:" >&2
    echo "  sudo git clone https://github.com/zany2dmax/cti-agent.git /root/cti-agent-kit" >&2
    echo "  sudo /root/cti-agent-kit/fleet-kit/install-fedora.sh --for-real" >&2
    echo "" >&2
    echo "Why: this installer runs 'git -C /opt/cti-agent/agent pull' partway" >&2
    echo "through, so from here it would install files from the new tree using" >&2
    echo "logic from the old script." >&2
    echo "" >&2
    echo "Do NOT put the kit in a personal home directory. A checkout in" >&2
    echo "/home/<you> is invisible to the next admin, and on a box with" >&2
    echo "directory-based SSH logins the home may not survive a logout." >&2
    bail 2
    ;;
esac

ACTION=install; DRY=""; REAL=""
for arg in "$@"; do
  case "$arg" in
    --dry-run)   DRY=1 ;;
    --for-real)  REAL=1 ;;
    --uninstall) ACTION=uninstall ;;
    --purge)     ACTION=purge ;;
    -h|--help)   sed -n '2,32p' "${BASH_SOURCE[0]}"; bail 0 ;;
    *) echo "unknown option: $arg" >&2; bail 2 ;;
  esac
done
# No default in either direction. fleet_require_mode exits 2 itself, so mark
# the exit as deliberate first: it is not a half-done install.
# shellcheck source=fleet/share/fleet-mode.sh
. "$SRC/fleet/share/fleet-mode.sh"
EXPECTED_EXIT=1
fleet_require_mode install-fedora.sh "$DRY" "$REAL" "" "" "./install-fedora.sh --help"
EXPECTED_EXIT=0
if [ -n "$DRY" ]; then MODE=dryrun; else MODE=$ACTION; fi

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
run()  { if [ "$MODE" = dryrun ]; then info "would run: $*"; else "$@"; fi; }

# replace_file DEST MODE - write stdin to DEST by writing a temporary file in the
# same directory and renaming it over DEST.
#
# WHY NOT `cat > DEST`. That opens the existing file and truncates it in place,
# and the kernel refuses ("Text file busy") while any process is executing it. A
# wrapper that a running command, a timer's lane or another terminal is using
# made the whole update stop part-way, with the wrapper not rewritten and the
# version record not written. A rename replaces the directory entry and leaves
# the running process its old copy, so an update can run while the fleet does.
replace_file() {
  local dest="$1" mode="$2" tmp
  tmp="$(mktemp "$dest.XXXXXX")" || return 1
  if cat > "$tmp" && chmod "$mode" "$tmp" && mv -f "$tmp" "$dest"; then
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# cfgval KEY [FILE] - last value of KEY=... from fleet.env, or empty.
#
# WHY A HELPER AND NOT A grep PIPELINE
#
# `V="$(grep -E "^$1=" file | tail -1 | cut -d= -f2-)"` looks harmless and is a
# loaded gun under `set -euo pipefail`, which this script sets on line 27. grep
# exits 1 when it matches nothing; `pipefail` makes the pipeline carry that 1
# even though tail and cut succeeded; the assignment therefore fails; and
# `set -e` ends the script. No message, no non-zero visible to the operator who
# ran it interactively, just a prompt.
#
# This is not hypothetical. It is how an install ended four lines after
# printing "✓ daemon-reload" with 400 lines still to go: the wrapper, the
# version manifest and the whole Verification block never ran, and the only
# evidence was /etc/cti-agent/version not existing. It also made the "$1 is
# unset" branch in check_path unreachable - the diagnostic for a missing key
# could never fire, because a missing key killed the script before it.
#
# sed returns 0 when it substitutes nothing, so an absent key reads as empty,
# which is what every caller here already handles.
# settings_files - every file the fleet's settings live in, in load order:
# fleet.env (before the split, RUNBOOK 11o), then fleet.d/00-core.env and the
# lane files. Paths here have no spaces.
settings_files() {
  local f
  for f in "$CONF_DIR/fleet.env" "$CONF_DIR/fleet.d/00-core.env" "$CONF_DIR"/fleet.d/*.env; do
    [ -f "$f" ] && printf '%s\n' "$f"
  done | awk '!seen[$0]++'
}
# split_settings_files - only the fleet.d files, space-separated: what a
# unit's FLEET_ENV_FILES names.
split_settings_files() {
  local f
  for f in $(settings_files); do
    case "$f" in */fleet.d/*) printf '%s ' "$f" ;; esac
  done
}
cfgval() {
  local files
  if [ -n "${2:-}" ]; then files="$2"; else files="$(settings_files)"; fi
  # shellcheck disable=SC2086 # a list of paths with no spaces
  sed -n "s/^$1=//p" $files /dev/null 2>/dev/null \
    | tail -1 | tr -d '"'"'"' '
}

# ─────────────────────────────────────────────────────────── uninstall ────────
if [ "$ACTION" != install ] && [ "$MODE" = dryrun ]; then
  bold "Dry run: $ACTION"
  info "would stop and disable every $UNIT_DIR/cti-agent-*.timer, remove the units,"
  info "/usr/local/sbin/cti-agent-update, the tab completion, the man pages and $CODE_DIR"
  [ "$ACTION" = purge ] && info "and, after a typed confirmation, $CONF_DIR, $STATE_DIR and the $FLEET_USER account"
  info "Dry run: nothing was removed."
  bail 0
fi
if [ "$ACTION" != install ]; then
  [ "$(id -u)" = 0 ] || { bad "run with sudo"; bail 1; }
  bold "Stopping and disabling timers"
  # Every installed timer, not a hand-kept list: the list stopped at
  # patchtuesday, so uninstall left the mailbox, appscan and domains timers
  # enabled and firing at units that no longer existed.
  for unit in "$UNIT_DIR"/cti-agent-*.timer; do
    [ -f "$unit" ] || continue
    t="$(basename "$unit")"
    systemctl disable --now "$t" 2>/dev/null || true
    ok "$t"
  done
  bold "Removing units"
  rm -f "$UNIT_DIR"/cti-agent-*.service "$UNIT_DIR"/cti-agent-*.timer
  systemctl daemon-reload
  ok "units removed"
  rm -f /usr/local/sbin/cti-agent-update /usr/local/sbin/cti-agent-secrets /usr/local/sbin/cti-agent-settings \
        /usr/local/sbin/cti-agent-onboard
  # /etc/credstore.encrypted is left alone: it holds the fleet's secrets,
  # encrypted to this machine, and removing them is a decision, not cleanup.
  bold "Removing tab completion"
  rm -f /usr/share/bash-completion/completions/cti-agent /usr/share/zsh/site-functions/_cti-agent \
        /usr/share/bash-completion/completions/cti-agent-update /usr/share/zsh/site-functions/_cti-agent-update \
        /usr/share/bash-completion/completions/cti-agent-secrets /usr/share/zsh/site-functions/_cti-agent-secrets \
        /usr/share/bash-completion/completions/cti-agent-settings /usr/share/zsh/site-functions/_cti-agent-settings \
        /usr/share/bash-completion/completions/cti-agent-onboard /usr/share/zsh/site-functions/_cti-agent-onboard
  bold "Removing man pages"
  for page in "$SRC/../man/man1"/*.1; do
    if [ -f "$page" ]; then rm -f "/usr/local/share/man/man1/$(basename "$page")"; fi
  done
  ok "/usr/local/share/man/man1"
  bold "Removing code"
  rm -rf "$CODE_DIR"
  ok "$CODE_DIR"
  if [ "$ACTION" = purge ]; then
    bold "Purging config and state"
    warn "this deletes the client secret, the findings database and all reports"
    read -r -p "  Type 'purge' to confirm: " c
    if [ "$c" = purge ]; then
      rm -rf "$CONF_DIR" "$STATE_DIR"
      userdel "$FLEET_USER" 2>/dev/null || true
      ok "removed $CONF_DIR, $STATE_DIR and the $FLEET_USER account"
      # The audit trail is evidence. A purge of the fleet does not delete it:
      # that is a separate decision, and the retention rule (120 days) will not
      # run once the cleanup lane is gone.
      info "kept $LOG_DIR (the audit trail); delete it by hand when its retention requires"
    else
      info "aborted; config and state kept"
    fi
  else
    bold "Kept"
    info "$CONF_DIR   (config and secrets)"
    info "$STATE_DIR  (findings db, reports, caches)"
    info "$LOG_DIR  (the audit trail; kept even by --purge)"
    info "the $FLEET_USER account"
    info "--purge --for-real removes these too"
  fi
  bail 0
fi

# ──────────────────────────────────────────────────────────── preflight ───────
bold "Preflight"
[ "$(id -u)" = 0 ] || { bad "run with sudo"; bail 1; }

if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    fedora:*|rhel:*|centos:*|rocky:*|almalinux:*|*:*fedora*|*:*rhel*)
      ok "${PRETTY_NAME:-$ID}" ;;
    *)
      warn "${PRETTY_NAME:-unknown} is not Fedora/RHEL-family"
      read -r -p "  Continue anyway? [y/N] " c
      [ "${c:-n}" = y ] || bail 1 ;;
  esac
else
  warn "no /etc/os-release; assuming RHEL family"
fi

command -v systemctl >/dev/null || { bad "systemd not found"; bail 1; }
ok "systemd $(systemctl --version | head -1 | awk '{print $2}')"

# Dependencies. Python runs the SQLite tools (fleet-db, fleet-owners) and the
# root tools; Go builds every lane. dnf is only used if
# something is missing, so an air-gapped box with them preinstalled still works.
MISSING=()
command -v python3 >/dev/null || MISSING+=(python3)
command -v git     >/dev/null || MISSING+=(git)
command -v go      >/dev/null || MISSING+=(golang)
if [ ${#MISSING[@]} -gt 0 ]; then
  warn "missing: ${MISSING[*]}"
  run dnf install -y "${MISSING[@]}"
else
  ok "python3 $(python3 -V 2>&1 | awk '{print $2}'), git, go $(go version | awk '{print $3}')"
fi

# SELinux. The FHS layout below is chosen so the default policy already permits
# it, but report the mode so a later denial is not a surprise.
SEMODE=disabled
command -v getenforce >/dev/null && SEMODE=$(getenforce 2>/dev/null || echo disabled)
# Standard *IX locations (the FHS) throughout, so the default SELinux policy
# fits without a custom module and anyone who knows Linux knows where to look.
info "standard locations: code in /opt (usr_t), config in /etc (etc_t),"
info "  state in /var/lib (var_lib_t), logs in /var/log (var_log_t) and the systemd"
info "  journal (journalctl -u 'cti-agent-*'); the full list is under Layout below"
case "$SEMODE" in
  Enforcing)
    ok "SELinux: Enforcing"
    info "all standard locations, so no custom policy should be needed."
    info "If a run fails with an inexplicable permission error:"
    info "    sudo ausearch -m avc -ts recent"
    ;;
  Permissive) warn "SELinux: Permissive - denials are logged, not enforced" ;;
  *)          info "SELinux: $SEMODE" ;;
esac

# The org pack (docs/org-pack.md): this organization's notes for the prompts,
# and its extra skills, kept out of the core files so an upstream pull never
# conflicts with them. A fork commits it as org/ in its repository; a box
# installed from an upstream clone keeps it in $CONF_DIR/org. Checked here,
# before anything is installed, because it steers the beat: root-owned, no
# symlinks, nothing the layout does not name.
ORG_PACK="$("$SRC/bin/org-pack" find "$SRC/.." "$CONF_DIR")" || bail 1
ORG_TMP="$(mktemp -d)"
if [ -n "$ORG_PACK" ]; then
  "$SRC/bin/org-pack" check "$ORG_PACK" "$SRC/fleet" --root-owned || bail 1
  ok "org pack: $ORG_PACK"
else
  info "org pack: none (the core prompts and skills only; docs/org-pack.md)"
fi
# FLEET_LANES: the lanes this box runs, comma-separated, by the names in
# fleet/lanes.list (generated from fleet-kit/lanes/*.toml). Unset: every lane,
# as before. A lane not in it has its timer turned off below, its settings
# are not required, and the check-in reports it as off. A name that is no
# lane stops the install here, before anything changes.
LANE_LIST="$SRC/fleet/lanes.list"
LANES_IN_USE="$(cfgval FLEET_LANES)"
KNOWN_LANES="$(awk -F'\t' '!/^#/ && NF {print $1}' "$LANE_LIST")"
for l in ${LANES_IN_USE//,/ }; do
  if ! printf '%s\n' "$KNOWN_LANES" | grep -qx -- "$l"; then
    bad "FLEET_LANES names \"$l\", which is not a lane. The lanes: $(printf '%s' "$KNOWN_LANES" | tr '\n' ' ')"
    bail 1
  fi
done
if [ -n "$LANES_IN_USE" ]; then
  ok "lanes in use (FLEET_LANES): ${LANES_IN_USE//,/, }"
else
  info "lanes in use: all (FLEET_LANES unset)"
fi
# lane_in_use LANE - FLEET_LANES is unset or names LANE.
lane_in_use() {
  [ -z "$LANES_IN_USE" ] && return 0
  case ",$LANES_IN_USE," in *",$1,"*) return 0 ;; esac
  return 1
}
# timer_lane cti-agent-NAME.timer - the lane the timer's unit belongs to.
timer_lane() {
  local u="${1#cti-agent-}"
  u="${u%.timer}"
  awk -F'\t' -v u="$u" '!/^#/ && NF { n = split($2, us, ","); for (i = 1; i <= n; i++) if (us[i] == u) print $1 }' "$LANE_LIST"
}

# org_compose CORE NAME OUT - CORE with the pack's NAME file appended, into OUT.
org_compose() {
  "$SRC/bin/org-pack" compose "$1" "${ORG_PACK:+$ORG_PACK/$2}" > "$3"
}

# ───────────────────────────────────────────────────── service account ───────
bold "Service account: $FLEET_USER"
if id "$FLEET_USER" >/dev/null 2>&1; then
  ok "exists"
else
  # A system account with its home set to the state directory. Claude Code
  # stores credentials in $HOME/.claude, and pointing HOME at the state dir
  # keeps them inside StateDirectory instead of creating a /home path that
  # ProtectHome=yes would then have to special-case.
  run useradd --system --home-dir "$STATE_DIR" --no-create-home \
              --shell /sbin/nologin --comment "CTI agent fleet" "$FLEET_USER"
  ok "created (system account, no login shell, home=$STATE_DIR)"
fi

# ───────────────────────────────────────────────────────────── layout ────────
bold "Layout"
run install -d -m 0755 -o root -g root "$CODE_DIR" "$CODE_DIR/bin" "$CODE_DIR/share"
run install -d -m 0750 -o root -g "$FLEET_GROUP" "$CONF_DIR"
run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" \
    "$STATE_DIR" "$STATE_DIR/state" "$STATE_DIR/reports" "$STATE_DIR/archive"
info "$CODE_DIR   code   (root:root 0755, read-only to the service)"
info "$CONF_DIR   config (root:$FLEET_GROUP 0750)"
info "$STATE_DIR  state  ($FLEET_USER:$FLEET_GROUP 0750)"
# The audit trail. The units create this themselves (LogsDirectory=); it is
# made here too so a command run by hand as the service account (sudo
# cti-agent cti-jira ...) can write its events before any timer has fired.
run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$LOG_DIR"
info "$LOG_DIR  audit trail  ($FLEET_USER:$FLEET_GROUP 0750, RFC 5424 syslog lines, kept AUDIT_RETAIN_DAYS=120 days)"
# Everything else lives where a Linux admin would look for it. Listed here so
# the install says so, and RUNBOOK "Where it lives" has the same table.
info "the systemd journal  every run's output (journalctl -u 'cti-agent-*'; hand runs: -u 'cti-manual-*')"
info "$CONF_DIR/fleet.env  settings, or $CONF_DIR/fleet.d/ once split per lane (root:$FLEET_GROUP 0640)"
info "$CREDSTORE_DIR  secrets as systemd credentials (root-only; systemd-creds, TPM-bound where present)"
info "$UNIT_DIR/cti-agent-*  units and timers (root:root 0644)"
info "/usr/local/bin/cti-agent  the wrapper for hand runs (root:root 0755)"
info "/usr/local/sbin/cti-agent-{update,secrets,settings}  root tools, run with sudo (root:root 0755)"
info "$MAN_DIR  a man page for every command (root:root 0644; man -k cti)"
info "/usr/share/bash-completion/completions, /usr/share/zsh/site-functions  tab completion (root:root 0644)"

bold "Installing code"
# Everything in fleet/bin, not a hand-written list.
#
# The list used to be explicit and run-mailbox-cleanup was never on it, so the
# mailbox lane shipped a unit, a timer and a Go binary - and no runner. The
# verification block below listed the runner, which looks like coverage until
# you notice it was asserting a file the install step never copied. It failed
# at 203/EXEC the first morning the timer fired.
#
# A directory cannot drift from itself. Adding a runner to fleet/bin is now
# the whole change.
for f in "$SRC"/fleet/bin/*; do
  [ -f "$f" ] || continue
  run install -m 0755 -o root -g root "$f" "$CODE_DIR/bin/$(basename "$f")"
  info "bin/$(basename "$f")"
done
# Retired files. An update installs over the old tree and never deletes, so a
# file the repo no longer ships stays on the box, and the cti-agent wrapper
# still runs anything in lanes/. Removed after 1.7.2:
#   mailer.py      - replaced by cti-mailer in 1.6.6
#   fleet-sanitize - replaced by cti-sanitize (Go)
#   enrich.py      - replaced by cti-enrich (Go)
#   brief.py       - replaced by cti-brief (Go), with the email-tokens.json
#                    copy only it read (the Go lanes embed internal/emailkit's)
#   scout.py       - replaced by cti-scout (Go), the last Python lane; lanes/
#                    itself goes once it is empty
# Take them, and their man pages, off the box.
for f in "$CODE_DIR/lanes/mailer.py" "$MAN_DIR/mailer.py.1" \
         "$CODE_DIR/bin/fleet-sanitize" "$MAN_DIR/fleet-sanitize.1" \
         "$CODE_DIR/lanes/enrich.py" "$MAN_DIR/enrich.py.1" \
         "$CODE_DIR/lanes/brief.py" "$MAN_DIR/brief.py.1" "$CODE_DIR/lanes/email-tokens.json" \
         "$CODE_DIR/lanes/scout.py" "$MAN_DIR/scout.py.1"; do
  if [ -e "$f" ]; then
    run rm -f "$f"
    info "removed $f (retired)"
  fi
done
if [ -d "$CODE_DIR/lanes" ]; then
  run rm -rf "$CODE_DIR/lanes/__pycache__"
  if run rmdir "$CODE_DIR/lanes" 2>/dev/null; then info "removed $CODE_DIR/lanes (retired)"; fi
fi
# The supplier-request lane's standing instructions: the system prompt of the
# no-tools model that judges each request. Root-owned like the code, so the
# service account cannot rewrite what its own model is told. Data, not code: 0644.
# The advisory triage reader's instructions, root-owned for the same reason,
# and the triage judge's: the one triage model that sees our facts. Each gets
# the org pack's agents/<name>.md after it, when the pack has one.
for a in supplier triage-reader triage-judge; do
  org_compose "$SRC/fleet/agents/$a/CLAUDE.md" "agents/$a.md" "$ORG_TMP/agent-$a.md"
  run install -d -m 0755 -o root -g root "$CODE_DIR/agents/$a"
  run install -m 0644 -o root -g root "$ORG_TMP/agent-$a.md" "$CODE_DIR/agents/$a/CLAUDE.md"
  if [ -n "$ORG_PACK" ] && [ -f "$ORG_PACK/agents/$a.md" ]; then
    info "agents/$a/CLAUDE.md (with the org pack's notes)"
  else
    info "agents/$a/CLAUDE.md"
  fi
done
# The list of fleet commands and what each takes, and what answers questions
# about it: `cti-agent` with no arguments, `cti-agent CMD --help`, and the TAB
# completions all read this one file.
run install -m 0644 -o root -g root "$SRC/fleet/commands.manifest" "$CODE_DIR/commands.manifest"
# Every fleet.env setting and which program reads it: fleet-config reads it.
run install -m 0644 -o root -g root "$SRC/fleet/settings.manifest" "$CODE_DIR/settings.manifest"
# Which secrets each command needs: the wrapper gives a hand run its timer's
# grants from it. Generated with the units' ImportCredential= lines.
run install -m 0644 -o root -g root "$SRC/fleet/credentials.map" "$CODE_DIR/share/credentials.map"
# The lanes, their units and credential checks, for the tools that read
# FLEET_LANES on the box (fleet-timers, fleet-config). Generated by scripts/lanes.
run install -m 0644 -o root -g root "$SRC/fleet/lanes.list" "$CODE_DIR/share/lanes.list"
# Each lane's settings and secrets, for cti-agent-onboard. Generated by
# scripts/settings-manifest.
run install -m 0644 -o root -g root "$SRC/fleet/lane-settings.list" "$CODE_DIR/share/lane-settings.list"
# The fleet.d files a split box keeps, as examples: what cti-agent-onboard
# writes from, and what an operator reads to see where a setting goes.
run install -d -m 0755 -o root -g root "$CODE_DIR/share/fleet.d.example"
for f in "$SRC"/fleet/fleet.d.example/*.env; do
  run install -m 0644 -o root -g root "$f" "$CODE_DIR/share/fleet.d.example/$(basename "$f")"
done
# Secrets as systemd credentials (RUNBOOK 11n): the store, and the root tool
# that fills it. The folder is world-listable so fleet-config can see which
# secrets have moved; each file is root-only, and encrypted to this machine.
# Created root-only if missing, and otherwise left as systemd's tmpfiles keeps
# it (it resets the mode at boot). fleet-config learns which secrets moved
# from the names-only list cti-agent-secrets writes, not by listing here.
if [ ! -d "$CREDSTORE_DIR" ]; then run install -d -m 0700 -o root -g root "$CREDSTORE_DIR"; fi
run install -m 0755 -o root -g root "$SRC/bin/cti-agent-secrets" /usr/local/sbin/cti-agent-secrets
# Splits fleet.env into core plus one file per lane (RUNBOOK 11o).
run install -m 0755 -o root -g root "$SRC/bin/cti-agent-settings" /usr/local/sbin/cti-agent-settings
# Setting up a box: which lanes, their settings, their secrets (RUNBOOK section 9).
run install -m 0755 -o root -g root "$SRC/bin/cti-agent-onboard" /usr/local/sbin/cti-agent-onboard
if command -v systemctl >/dev/null 2>&1; then
  sdv="$(systemctl --version 2>/dev/null | awk 'NR==1 { print $2 }')"
  case "$sdv" in
    ''|*[!0-9]*) warn "could not read the systemd version: ImportCredential= needs 254 or later" ;;
    *) if [ "$sdv" -lt 254 ]; then
         warn "systemd $sdv: units cannot import credentials (needs 254); secrets stay in fleet.env"
       elif [ "$MODE" != dryrun ] && ! systemd-run --quiet --wait --collect --expand-environment=no \
              -p ImportCredential=CTI_AGENT_INSTALL_PROBE /bin/true >/dev/null 2>&1; then
         # Hand runs use exactly these options once a secret is stored.
         warn "a transient unit refused ImportCredential= - hand runs could not get credentials; keep secrets in fleet.env"
       fi ;;
  esac
fi
run install -m 0755 -o root -g root "$SRC/fleet/share/cti-agent-usage" "$CODE_DIR/share/cti-agent-usage"
# Sourced by every runner that changes something: the "say how to run it" rule.
# Not executable, and the runners fail at start without it, so it is checked.
run install -m 0644 -o root -g root "$SRC/fleet/share/fleet-mode.sh" "$CODE_DIR/share/fleet-mode.sh"
# What every model lane needs around a claude call (HARNESS H4), sourced by
# run-checkin and run-supplier. Root-owned like bin/: run-checkin refuses to
# start if the service account could change it.
run install -m 0644 -o root -g root "$SRC/fleet/share/model-lane.sh" "$CODE_DIR/share/model-lane.sh"
info "commands.manifest, settings.manifest, share/cti-agent-usage, share/fleet-mode.sh, share/model-lane.sh"
# Shell completion: bash-completion's directory and zsh's site-functions. The
# CODE_DIR in each is filled in, so a relocated install still completes.
if [ "$MODE" != dryrun ]; then
  install -d -m 0755 /usr/share/bash-completion/completions /usr/share/zsh/site-functions
  sed "s#@CODE_DIR@#$CODE_DIR#g" "$SRC/fleet/share/cti-agent.bash" > /usr/share/bash-completion/completions/cti-agent
  sed "s#@CODE_DIR@#$CODE_DIR#g" "$SRC/fleet/share/_cti-agent" > /usr/share/zsh/site-functions/_cti-agent
  # cti-agent-update gets files of its own: bash-completion loads by command name.
  install -m 0644 "$SRC/fleet/share/cti-agent-update.bash" /usr/share/bash-completion/completions/cti-agent-update
  install -m 0644 "$SRC/fleet/share/_cti-agent-update" /usr/share/zsh/site-functions/_cti-agent-update
  # The root tools for secrets and settings (RUNBOOK 11n, 11o), likewise; their
  # completion reads the installed manifest and the names-only stored list.
  for t in cti-agent-secrets cti-agent-settings cti-agent-onboard; do
    sed -e "s#@CODE_DIR@#$CODE_DIR#g" -e "s#@CONF_DIR@#$CONF_DIR#g" "$SRC/fleet/share/$t.bash" \
      > /usr/share/bash-completion/completions/$t
    sed -e "s#@CODE_DIR@#$CODE_DIR#g" -e "s#@CONF_DIR@#$CONF_DIR#g" "$SRC/fleet/share/_$t" \
      > /usr/share/zsh/site-functions/_$t
    chmod 0644 /usr/share/bash-completion/completions/$t /usr/share/zsh/site-functions/_$t
  done
  chmod 0644 /usr/share/bash-completion/completions/cti-agent /usr/share/zsh/site-functions/_cti-agent
  if command -v restorecon >/dev/null; then
    restorecon -F /usr/share/bash-completion/completions/cti-agent /usr/share/zsh/site-functions/_cti-agent \
      /usr/share/bash-completion/completions/cti-agent-update /usr/share/zsh/site-functions/_cti-agent-update \
      /usr/share/bash-completion/completions/cti-agent-secrets /usr/share/zsh/site-functions/_cti-agent-secrets \
      /usr/share/bash-completion/completions/cti-agent-settings /usr/share/zsh/site-functions/_cti-agent-settings \
      /usr/share/bash-completion/completions/cti-agent-onboard /usr/share/zsh/site-functions/_cti-agent-onboard \
      2>/dev/null || true
  fi
  ok "tab completion for bash and zsh: cti-agent, cti-agent-update, cti-agent-secrets, cti-agent-settings, cti-agent-onboard (open a new shell to pick it up)"
else
  info "would install bash and zsh tab completion"
fi
if [ -f "$CONF_DIR/feeds.txt" ]; then
  ok "feeds.txt exists in $CONF_DIR, not overwriting your edits"
else
  run install -m 0640 -o root -g "$FLEET_GROUP" "$SRC/fleet/lanes/feeds.txt" "$CONF_DIR/feeds.txt"
  info "feeds.txt -> $CONF_DIR (edit it: trim to vendors you actually run)"
fi
run install -m 0644 -o root -g root "$SRC/README.md" "$CODE_DIR/README.md"

# THE ORCHESTRATOR'S INSTRUCTIONS ARE CODE, AND ARE INSTALLED LIKE CODE.
#
# CLAUDE.md and the skills tell the heartbeat what to do, and Claude Code loads
# them - plus settings, hooks and MCP servers - from its working directory.
# They used to be installed into $STATE_DIR owned by the service account, so a
# beat steered once by a hostile advisory could rewrite the instructions every
# later beat follows. Root-owned files in a directory the account owns would
# not fix that (it can rename them away), so they live in a root-owned
# directory under $CODE_DIR and the beat starts there. run-checkin refuses to
# start if any of it is writable by the service.
AGENT_DIR="$CODE_DIR/orchestrator"
bold "Orchestrator instructions ($AGENT_DIR, root-owned)"
run install -d -m 0755 -o root -g root "$AGENT_DIR" "$AGENT_DIR/.claude" \
    "$AGENT_DIR/.claude/skills"

# "Not overwriting your edits" was protecting a file nobody had edited.
#
# The orchestrator's standing instructions were frozen at first install, so a
# deploy could never change them. That is not a hypothetical: the allowlist
# grant for cti-alert reached the box while the instruction telling the agent
# to use it did not, and the agent went on reporting that it could not reach
# a human while holding the capability to do so.
#
# So: remember the hash of what we install. Unmodified since last time means
# it is ours to update. Modified means an operator changed it (only root can,
# now), and THAT is worth preserving - but loudly, with the diff named.
#
# What we install is the shipped CLAUDE.md with the org pack's orchestrator.md
# after it. An organization's own notes belong in the pack, where an update
# keeps them; an edit to the installed copy freezes the whole file instead.
CLAUDE_MD_HASH="$CODE_DIR/.orchestrator-CLAUDE.md.sha256"
org_compose "$SRC/fleet/CLAUDE.md" orchestrator.md "$ORG_TMP/CLAUDE.md"
claude_md_unmodified() {
  # Identical to what we ship counts as unmodified even with no hash on
  # record, so the first run does not cry wolf.
  cmp -s "$AGENT_DIR/CLAUDE.md" "$ORG_TMP/CLAUDE.md" && return 0
  [ -f "$CLAUDE_MD_HASH" ] || return 1
  [ "$(sha256sum "$AGENT_DIR/CLAUDE.md" | cut -d" " -f1)" = "$(cat "$CLAUDE_MD_HASH")" ]
}
if [ -f "$AGENT_DIR/CLAUDE.md" ] && ! claude_md_unmodified; then
  warn "CLAUDE.md differs from the shipped version and was NOT updated"
  info "  yours:    $AGENT_DIR/CLAUDE.md"
  info "  shipped:  $SRC/fleet/CLAUDE.md"
  info "  diff:     sudo diff -u $AGENT_DIR/CLAUDE.md $SRC/fleet/CLAUDE.md"
  info "  The agent follows YOUR copy. If the shipped one changed how it"
  info "  escalates or what it may run, your copy will not know."
  info "  Move your changes into the org pack's orchestrator.md"
  info "  (docs/org-pack.md), delete this copy, and re-run: updates keep the pack."
  run chown root:root "$AGENT_DIR/CLAUDE.md"
  run chmod 0644 "$AGENT_DIR/CLAUDE.md"
else
  run install -m 0644 -o root -g root "$ORG_TMP/CLAUDE.md" "$AGENT_DIR/CLAUDE.md"
  if [ -n "$ORG_PACK" ] && [ -f "$ORG_PACK/orchestrator.md" ]; then
    info "CLAUDE.md -> $AGENT_DIR (the orchestrator's standing instructions, with the org pack's notes)"
  else
    info "CLAUDE.md -> $AGENT_DIR (the orchestrator's standing instructions)"
  fi
  if [ "$MODE" != dryrun ]; then
    sha256sum "$AGENT_DIR/CLAUDE.md" | cut -d" " -f1 > "$CLAUDE_MD_HASH"
    chmod 0644 "$CLAUDE_MD_HASH"
  fi
fi

bold "Skills"
for s in checkin cti-digest scout-sweep patch-tuesday; do
  run install -d -m 0755 -o root -g root "$AGENT_DIR/.claude/skills/$s"
  run install -m 0644 -o root -g root \
      "$SRC/fleet/skills/$s/SKILL.md" "$AGENT_DIR/.claude/skills/$s/SKILL.md"
  info "/$s"
done
# The org pack's own skills, beside the core ones (org-pack check refused any
# that reuses a core skill's name). A skill the pack no longer has is removed,
# so dropping one from the pack drops it from the box; the core skills are
# never touched by this.
ORG_SKILLS=" "
if [ -n "$ORG_PACK" ] && [ -d "$ORG_PACK/skills" ]; then
  for d in "$ORG_PACK"/skills/*/; do
    [ -d "$d" ] || continue
    s="$(basename "$d")"
    ORG_SKILLS="$ORG_SKILLS$s "
    run install -d -m 0755 -o root -g root "$AGENT_DIR/.claude/skills/$s"
    run install -m 0644 -o root -g root "$d/SKILL.md" "$AGENT_DIR/.claude/skills/$s/SKILL.md"
    info "/$s (org pack)"
  done
fi
for d in "$AGENT_DIR"/.claude/skills/*/; do
  [ -d "$d" ] || continue
  s="$(basename "$d")"
  case " checkin cti-digest scout-sweep patch-tuesday$ORG_SKILLS" in *" $s "*) continue ;; esac
  run rm -rf "$AGENT_DIR/.claude/skills/$s"
  info "removed /$s (no longer in the org pack)"
done
rm -rf "$ORG_TMP"

# The beat's --settings file: one hook (bin/checkin-bash-guard, which refuses
# shell syntax on every Bash call), no project MCP servers, edit and web
# tools denied. The hook path is /opt/cti-agent, so CODE_DIR must be too.
# Root-owned beside the code; run-checkin refuses without it.
run install -m 0644 -o root -g root "$SRC/fleet/checkin-settings.json" \
    "$CODE_DIR/checkin-settings.json"
info "checkin-settings.json -> $CODE_DIR"

# ── AUDIT: what the service account could have planted ──────────────────────
#
# Everything Claude Code would load from the account's HOME ($STATE_DIR) or
# its config dir, which this fleet no longer installs there. On a box upgraded
# from the old layout that includes the old CLAUDE.md and skills; anywhere,
# it may include something a steered beat left behind. Nothing is deleted: it
# is moved to a root-only quarantine folder and named, so the operator can
# read it. run-checkin refuses to beat while any of it is present, and the
# verification block below runs run-checkin --audit to prove it is gone.
bold "Audit: Claude Code files in the service account's reach"
QUARANTINE="$CONF_DIR/quarantine/$(date +%Y%m%d-%H%M%S)"
LEGACY_HASH="$STATE_DIR/.claude/CLAUDE.md.installed-sha256"
found_any=0
# A symlinked .claude would aim the moves below at whatever it points to -
# the root-owned orchestrator files just installed, say - so the link itself
# goes first, and the loop then sees nothing under it.
if [ -L "$STATE_DIR/.claude" ]; then
  found_any=1
  warn "$STATE_DIR/.claude is a symlink (to $(readlink "$STATE_DIR/.claude")) - moved aside"
  run install -d -m 0700 -o root -g root "$QUARANTINE"
  run mv "$STATE_DIR/.claude" "$QUARANTINE/dot-claude.symlink"
fi
for p in "$STATE_DIR/CLAUDE.md" "$STATE_DIR/CLAUDE.local.md" "$STATE_DIR/.mcp.json" \
         "$STATE_DIR/.claude/skills" "$STATE_DIR/.claude/CLAUDE.md" \
         "$STATE_DIR/.claude/settings.json" "$STATE_DIR/.claude/settings.local.json" \
         "$STATE_DIR/.claude/commands" "$STATE_DIR/.claude/agents" \
         "$STATE_DIR/.claude/hooks" "$STATE_DIR/.claude/rules" \
         "$STATE_DIR/.claude/output-styles" "$STATE_DIR/.claude/workflows" \
         "$STATE_DIR/.claude/projects"/*/memory "$LEGACY_HASH"; do
  [ -e "$p" ] || [ -L "$p" ] || continue
  # Only paths that really are in the state dir: never follow a link out.
  case "$(realpath -m "$(dirname "$p")" 2>/dev/null)" in
    "$STATE_DIR"|"$STATE_DIR/.claude") ;;
    # realpath is canonical, so this cannot be a ../ out of projects/.
    "$STATE_DIR/.claude/projects/"*) ;;
    *) warn "$p resolves outside $STATE_DIR - not moved; inspect it"; found_any=1; continue ;;
  esac
  found_any=1
  case "$p" in
    "$STATE_DIR/CLAUDE.md"|"$STATE_DIR/.claude/skills"|"$LEGACY_HASH")
      warn "$p - the old installer's copy; no longer loaded, moved aside" ;;
    "$STATE_DIR/.claude/projects/"*/memory)
      # Claude Code's auto-memory: notes a beat wrote for itself, loaded into
      # the next session. Beats ran with it on before run-checkin turned it
      # off, so a box upgraded from then has one. Read it: if a beat was ever
      # steered, this is where it would have left instructions for the next.
      warn "$p - auto-memory an earlier beat wrote; no longer used, moved aside. Read it." ;;
    *)
      warn "$p - NOT installed by this kit. Read it before deleting it:"
      info "  a file here is how a steered beat would make itself permanent." ;;
  esac
  rel="${p#"$STATE_DIR"/}"
  run install -d -m 0700 -o root -g root "$QUARANTINE/$(dirname "$rel")"
  run mv "$p" "$QUARANTINE/$rel"
done
if [ "$found_any" = 1 ]; then
  info "moved to $QUARANTINE (root only; a dry run moves nothing). If the old CLAUDE.md held your own"
  info "edits, compare and apply them to $AGENT_DIR/CLAUDE.md:"
  info "  sudo diff -u $QUARANTINE/CLAUDE.md $AGENT_DIR/CLAUDE.md"
else
  ok "nothing in $STATE_DIR that Claude Code would load"
fi
# ~/.claude.json is Claude Code's own state file, so it is not moved; what it
# would mean to a beat is checked by run-checkin --audit below.

# ───────────────────────────────────────────────────────────── config ────────
# check_layout_paths - the path settings, wherever they live (fleet.env, or the
# fleet.d files it was split into: cfgval reads them all).
check_layout_paths() {
  # Path settings are layout, not secrets - and an existing fleet.env skips the
  # rewrite below, so a file copied from a developer's laptop keeps that
  # laptop's paths. run-digest then fails with "CTI_AGENT_DIR not found", which
  # names the variable but not the reason. Validate and print the right value;
  # do not rewrite, because the operator's file is theirs.
  if [ "$MODE" != dryrun ]; then
    PATHFAIL=0
    check_path() { # name expected
      local cur; cur="$(cfgval "$1")"
      if [ -z "$cur" ]; then
        bad "$1 is unset - should be $2"; PATHFAIL=1
      elif [ "${cur#/}" = "$cur" ]; then
        # Relative paths resolve against the caller's working directory, which
        # for a systemd unit is not where anyone expects. ./qualys_kb_cache.json
        # passed the existence check purely because "." always exists, and would
        # then have written a 17MB cache wherever the service happened to start.
        bad "$1=$cur is relative - it must be an absolute path"
        info "expected: $2"; PATHFAIL=1
      elif [ ! -e "$cur" ] && [ ! -d "$(dirname "$cur")" ]; then
        bad "$1=$cur does not exist on this box"
        info "expected: $2"; PATHFAIL=1
      else
        ok "$1=$cur"
      fi
    }
    check_path FLEET_HOME      "$STATE_DIR"
    check_path CTI_AGENT_DIR   "$CODE_DIR/agent"
    check_path QUALYS_KB_CACHE "$STATE_DIR/state/qualys_kb_cache.json"
    check_path REPORT_PATH     "$STATE_DIR/reports/raw-latest.md"
    check_path FLEET_FEEDS     "$CONF_DIR/feeds.txt"
    if [ "$PATHFAIL" != 0 ]; then
      bad "fix the paths above in the settings files - every one of them is a"
      info "guaranteed runtime failure, several minutes into a run rather than"
      info "at startup. This blocks the install deliberately."
      info "The cti-agent wrapper is already installed; re-run when fixed."
    fi
  fi
}

bold "Config"
if [ ! -f "$CONF_DIR/fleet.env" ] && [ -f "$CONF_DIR/fleet.d/00-core.env" ]; then
  # Split into per-lane files (RUNBOOK 11o): keep them, and own them as
  # fleet.env was owned - root writes, the service account reads.
  ok "$CONF_DIR/fleet.d exists (settings split per lane), keeping its contents"
  run chown root:"$FLEET_GROUP" "$CONF_DIR/fleet.d"
  run chmod 0750 "$CONF_DIR/fleet.d"
  for f in "$CONF_DIR"/fleet.d/*.env; do
    [ -f "$f" ] || continue
    run chown root:"$FLEET_GROUP" "$f"
    run chmod 0640 "$f"
  done
  check_layout_paths
elif [ -f "$CONF_DIR/fleet.env" ]; then
  ok "$CONF_DIR/fleet.env exists, keeping its contents"
  # Contents are the operator's; ownership and mode are this installer's job.
  # A file staged by hand arrives owned by whoever ran the editor, often 0400,
  # which root can still read - so nothing appears wrong until the service
  # account tries and the verification step fails with no obvious cause.
  # Correcting it here is safe: it changes no secret, only who may read one.
  before="$(stat -c '%a %U:%G' "$CONF_DIR/fleet.env")"
  run chown root:"$FLEET_GROUP" "$CONF_DIR/fleet.env"
  run chmod 0640 "$CONF_DIR/fleet.env"
  after="$(stat -c '%a %U:%G' "$CONF_DIR/fleet.env" 2>/dev/null || echo "$before")"
  [ "$before" = "$after" ] || warn "corrected $before -> $after"

  check_layout_paths
else
  run install -m 0640 -o root -g "$FLEET_GROUP" \
      "$SRC/fleet/fleet.env.example" "$CONF_DIR/fleet.env"
  # Rewrite the example's /home/ctiagent defaults to the FHS layout.
  if [ "$MODE" != dryrun ]; then
    sed -i \
      -e "s#^FLEET_HOME=.*#FLEET_HOME=$STATE_DIR#" \
      -e "s#^QUALYS_KB_CACHE=.*#QUALYS_KB_CACHE=$STATE_DIR/state/qualys_kb_cache.json#" \
      -e "s#^REPORT_PATH=.*#REPORT_PATH=$STATE_DIR/reports/raw-latest.md#" \
      -e "s#^CTI_AGENT_DIR=.*#CTI_AGENT_DIR=$CODE_DIR/agent#" \
      "$CONF_DIR/fleet.env"
  fi
  warn "created $CONF_DIR/fleet.env with PLACEHOLDER secrets - edit it now"
fi

# The organisation profile belonged to the first advisory-triage design (one
# agent judging relevance against a hand-written description of the estate).
# 1.7's triage judges against facts from Falcon instead, and the profile and
# its template were removed. Nothing reads the file any more; it is left in
# place, because it is the operator's and may still be wanted for reference.
if [ -f "$CONF_DIR/ORG-PROFILE.md" ]; then
  info "$CONF_DIR/ORG-PROFILE.md is no longer used (advisory triage reads Falcon);"
  info "  delete it when you no longer need it: sudo rm $CONF_DIR/ORG-PROFILE.md"
fi

# The domain inventory, same rule as the profile: it is a list of everything
# the organisation owns, so it lives only in $CONF_DIR and is never created
# from the repository. Reported, not created - cti-domains refuses to run on
# an absent or empty file rather than mailing "no issues across 0 domains".
if [ -f "$CONF_DIR/domains.txt" ]; then
  ok "$CONF_DIR/domains.txt exists ($(awk '!/^[[:space:]]*(#|$)/{n++} END{print n+0}' "$CONF_DIR/domains.txt" 2>/dev/null) domain line(s))"
else
  info "$CONF_DIR/domains.txt not present - the domains lane will not run until it is"
  info "  one domain per line, 'send' after those that send mail; root:$FLEET_GROUP 0640"
fi
info "mode $(stat -c '%a %U:%G' "$CONF_DIR/fleet.env" 2>/dev/null || echo '0640 root:ctiagent')"

# ────────────────────────────────────────────────────── outbound connectivity ───
# Every connectivity check in one place, after config so the hosts fleet.env
# names can be checked beside the fixed ones. firewalld does not filter egress
# by default, so a failure here is almost always an Azure NSG or a proxy.
#
# reach HOST [PORT] - one TCP connect, 6 seconds. The host is passed to bash as
# an argument, never spliced into the -c string: the second set of hosts comes
# from fleet.env, and this script runs as root.
reach() {
  if timeout 6 bash -c '</dev/tcp/$1/$2' _ "$1" "${2:-443}" 2>/dev/null; then
    ok "$1:${2:-443}"
  else
    warn "$1:${2:-443} unreachable - check the Azure NSG or proxy"
  fi
}
bold "Outbound connectivity"
# The fixed hosts every install needs: Microsoft (mail), NVD, FIRST (EPSS),
# CISA (KEV), MSRC and the two Patch Tuesday write-ups.
for host in login.microsoftonline.com graph.microsoft.com \
            services.nvd.nist.gov api.first.org www.cisa.gov \
            api.msrc.microsoft.com www.bleepingcomputer.com blog.qualys.com; do
  reach "$host"
done
# Then the hosts that depend on settings: the Qualys pod, Jira, and the
# optional services, each only when its setting is filled in. A value that is
# not a plain host name (an edit gone wrong, or a template placeholder) is
# reported and never dialled.
# urlhost URL - the host part of https://host[:port]/path, or empty.
urlhost() {
  local h="${1#*://}"
  h="${h%%/*}"; h="${h%%\?*}"; h="${h%%:*}"
  printf '%s' "$h"
}
# reach_cfg WHAT HOST [PORT] - reach a host taken from fleet.env.
reach_cfg() {
  case "$2" in
    "")  return ;;
    *example*|yourorg.*|*'<'*) info "$1: $2 is still a placeholder - not checked" ;;
    *[!A-Za-z0-9.-]*|-*) warn "$1: '$2' is not a host name - fix it in fleet.env" ;;
    *) reach "$2" "${3:-443}" ;;
  esac
}
if [ -n "$(settings_files)" ]; then
  checked=0
  if [ "$(cfgval LOOKUP_PROVIDER)" != none ]; then
    if [ -n "$(cfgval QUALYS_BASE_URL)" ]; then
      reach_cfg "Qualys pod" "$(urlhost "$(cfgval QUALYS_BASE_URL)")"; checked=1
    else
      warn "QUALYS_BASE_URL is unset - the Qualys lanes cannot run"
    fi
  fi
  # Scoped tokens go through api.atlassian.com whatever JIRA_BASE_URL says.
  if [ -n "$(cfgval JIRA_CLOUD_ID)" ]; then
    reach_cfg "Jira" api.atlassian.com; checked=1
  elif [ -n "$(cfgval JIRA_API_TOKEN)" ]; then
    reach_cfg "Jira" "$(urlhost "$(cfgval JIRA_BASE_URL)")"; checked=1
  fi
  if [ -n "$(cfgval FALCON_BASE_URL)" ]; then
    reach_cfg "CrowdStrike" "$(urlhost "$(cfgval FALCON_BASE_URL)")"; checked=1
  fi
  if [ -n "$(cfgval GODADDY_PAT)" ]; then
    reach_cfg "GoDaddy" api.godaddy.com; checked=1
  fi
  if [ -n "$(cfgval POD_CLUSTER_ID)" ]; then
    reach_cfg "Proofpoint on Demand log" logstream.proofpoint.com; checked=1
  fi
  if [ -n "$(cfgval ANTHROPIC_API_KEY)$(cfgval ANTHROPIC_AUTH_TOKEN)$(cfgval CLAUDE_CODE_OAUTH_TOKEN)" ]; then
    reach_cfg "Claude (check-in)" api.anthropic.com; checked=1
  fi
  [ "$checked" = 1 ] || info "nothing in fleet.env names a further host to check yet"
  info "port 25 for the domains lane's SMTP probe: RUNBOOK section 4b"
else
  info "no readable $CONF_DIR/fleet.env - the hosts it names were not checked"
fi

# ────────────────────────────────────────────────────────── the Go agent ─────
bold "Go agent"
AGENT_SRC="$CODE_DIR/agent"
if [ -d "$AGENT_SRC/.git" ]; then
  ok "already cloned at $AGENT_SRC"
  run git -C "$AGENT_SRC" pull --ff-only
else
  run git clone --depth 1 "$AGENT_REPO" "$AGENT_SRC"
fi
# WHAT IS THIS BOX RUNNING?
#
# Until now the answer was "whatever the checkout happened to be on", recorded
# nowhere. That is how a stale checkout installed binaries predating a feature
# while this script printed "Installed" - success reported about code the box
# did not have, discoverable only by noticing a command that should exist and
# did not.
#
# Stamped into every binary AND written to $CONF_DIR/version, so the two can
# be compared: a binary that disagrees with the manifest was not replaced by
# the last install, which is exactly what a partial install leaves behind.
VERSION_PKG="github.com/zany2dmax/cti-agent/internal/version"
if [ "$MODE" != dryrun ]; then
  BUILD_TAG="$( cd "$AGENT_SRC" && git describe --tags --always --dirty 2>/dev/null || echo unknown )"
  BUILD_COMMIT="$( cd "$AGENT_SRC" && git rev-parse HEAD 2>/dev/null || echo unknown )"
  BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  LDFLAGS="-X $VERSION_PKG.Tag=$BUILD_TAG -X $VERSION_PKG.Commit=$BUILD_COMMIT -X $VERSION_PKG.Built=$BUILD_TIME"
  info "building $BUILD_TAG ($(printf '%.12s' "$BUILD_COMMIT"))"
  case "$BUILD_TAG" in
    *-dirty)
      # Not fatal - this is how a fix gets tested on the box that has the
      # problem. But a dirty build cannot be reproduced from its commit, so
      # "prod matches the tag" stops meaning anything, and that must be said
      # out loud rather than discovered later.
      warn "building from a DIRTY working tree - this build is not reproducible" ;;
  esac
fi

if [ "$MODE" != dryrun ]; then
  # A Go command that took over a script's name (checkin-bash-guard and
  # fleet-trace were Python until 2.0) finds the old script in bin/, and
  # `go build -o` refuses to write over a file that is not a program it
  # built: "already exists and is not an object file". The 2.0-rc1 update
  # stopped here. A script named after a Go command is the old version, so
  # it goes before the build; a compiled binary is left for go build to
  # replace.
  for d in "$AGENT_SRC"/cmd/*/; do
    name="$(basename "$d")"
    old="$CODE_DIR/bin/$name"
    if [ -f "$old" ] && [ "$(head -c 2 "$old")" = '#!' ]; then
      rm -f "$old"
      info "removed the old script $old (now the Go $name)"
    fi
  done
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$AGENT_SRC/cti-agent" ./cmd/cti-agent )
  chmod 0755 "$AGENT_SRC/cti-agent"
  ok "built $AGENT_SRC/cti-agent"
  # The failure alerter. It lives in bin/ next to the shell helpers because
  # the alert units invoke it by absolute path, and it must exist before any
  # timer is enabled - an OnFailure pointing at a missing binary means the
  # failure is silent, which is the thing this is here to prevent.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-alert" ./cmd/cti-alert )
  chmod 0755 "$CODE_DIR/bin/cti-alert"
  ok "built $CODE_DIR/bin/cti-alert"

  # The quota governor. The heartbeat and its operator share one subscription,
  # so the fleet rations itself rather than competing. run-checkin skips the
  # gate if this is missing, which keeps an older install beating - but then
  # nothing is stopping it, so build it here.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-budget" ./cmd/cti-budget )
  chmod 0755 "$CODE_DIR/bin/cti-budget"
  ok "built $CODE_DIR/bin/cti-budget"

  # KEV deadline reporting. Reads the enrich lane's output; no credentials and
  # no network of its own, so it cannot fail in a way that affects the digest.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-kev" ./cmd/cti-kev )
  chmod 0755 "$CODE_DIR/bin/cti-kev"
  ok "built $CODE_DIR/bin/cti-kev"

  # The check-in's verdict checker (HARNESS H3). run-checkin calls it after each
  # beat; without it the beat still runs and the journal says it was not checked.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-checkin-verdict" ./cmd/cti-checkin-verdict )
  chmod 0755 "$CODE_DIR/bin/cti-checkin-verdict"
  ok "built $CODE_DIR/bin/cti-checkin-verdict"

  # The heartbeat's Bash guard (the PreToolUse hook checkin-settings.json
  # names at this path) and its trace recorder, Go after 1.7.2; the Python
  # scripts of the same names were removed above. run-checkin refuses a
  # beat whose guard does not refuse a redirect.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/checkin-bash-guard" ./cmd/checkin-bash-guard )
  chmod 0755 "$CODE_DIR/bin/checkin-bash-guard"
  ok "built $CODE_DIR/bin/checkin-bash-guard"
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/fleet-trace" ./cmd/fleet-trace )
  chmod 0755 "$CODE_DIR/bin/fleet-trace"
  ok "built $CODE_DIR/bin/fleet-trace"

  # The runners' lane lock: share/fleet-mode.sh's fleet_lock calls it, and a
  # runner without it does not start. Built first of the helpers so a timer
  # that fires during the build finds it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-lock" ./cmd/cti-lock )
  chmod 0755 "$CODE_DIR/bin/cti-lock"
  ok "built $CODE_DIR/bin/cti-lock"

  # run-checkin's file checks: the beat's settings run the guard, no config
  # file can steer it, which limits it hit. run-checkin refuses a beat
  # without it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-checkin-check" ./cmd/cti-checkin-check )
  chmod 0755 "$CODE_DIR/bin/cti-checkin-check"
  ok "built $CODE_DIR/bin/cti-checkin-check"

  # The heartbeat's output cleaner (Scenario-222). fleet-board, fleet-journal
  # and fleet-db pipe what a beat reads through it, and print nothing if it
  # is missing, so a beat without it reads no board, journal or memory.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-sanitize" ./cmd/cti-sanitize )
  chmod 0755 "$CODE_DIR/bin/cti-sanitize"
  ok "built $CODE_DIR/bin/cti-sanitize"

  # The @enrich lane: NVD, EPSS and CISA KEV, then the Sev5-Sev1 bands.
  # run-digest runs it between ingest and brief. It writes memory.db through
  # fleet-db, so it holds no SQL itself.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-enrich" ./cmd/cti-enrich )
  chmod 0755 "$CODE_DIR/bin/cti-enrich"
  ok "built $CODE_DIR/bin/cti-enrich"

  # The @brief lane: renders the digest from the enriched file. run-digest
  # runs it after cti-jira, so the ticket map beside the enriched file exists.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-brief" ./cmd/cti-brief )
  chmod 0755 "$CODE_DIR/bin/cti-brief"
  ok "built $CODE_DIR/bin/cti-brief"

  # The @scout lane: polls the advisory feeds for CVE IDs the fleet has not
  # seen. cti-agent-scout.timer runs it every four hours. It reads and writes
  # memory.db through fleet-db, so it holds no SQL itself.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-scout" ./cmd/cti-scout )
  chmod 0755 "$CODE_DIR/bin/cti-scout"
  ok "built $CODE_DIR/bin/cti-scout"

  # Read-only probe of the Proofpoint on Demand Log API: prints counts only.
  # Needs outbound 443 to logstream.proofpoint.com and POD_* in fleet.env.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-podprobe" ./cmd/cti-podprobe )
  chmod 0755 "$CODE_DIR/bin/cti-podprobe"
  ok "built $CODE_DIR/bin/cti-podprobe"

  # Read-only check of the CrowdStrike Falcon API client (advisory triage,
  # phase 1). Needs outbound 443 to the FALCON_BASE_URL host and FALCON_* in
  # fleet.env; nothing runs it on a timer.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-falcon" ./cmd/cti-falcon )
  chmod 0755 "$CODE_DIR/bin/cti-falcon"
  ok "built $CODE_DIR/bin/cti-falcon"

  # Advisory triage by hand (phase 3): the no-tools reader model, then Falcon
  # lookups. Needs TRIAGE_MODEL and the FALCON_* settings; nothing runs it on
  # a timer yet.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-triage" ./cmd/cti-triage )
  chmod 0755 "$CODE_DIR/bin/cti-triage"
  ok "built $CODE_DIR/bin/cti-triage"

  # Monthly Patch Tuesday synopsis. Reads two public wrap-ups and correlates
  # against Qualys, so it needs outbound 443 to two more hosts - checked under
  # Outbound connectivity above.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-patchtuesday" ./cmd/cti-patchtuesday )
  chmod 0755 "$CODE_DIR/bin/cti-patchtuesday"
  ok "built $CODE_DIR/bin/cti-patchtuesday"

  # Mailbox cleanup. The ONLY binary here that modifies the mailbox, so it is
  # also the only one whose app-registration requirement is Mail.ReadWrite
  # rather than Mail.Read. It dry-runs unless given --for-real; the unit
  # passes that flag explicitly so the decision is visible in the unit.
  # The audit trail's writer and retention tool: scripts (fleet-owners) write
  # events through it, the mailbox cleanup prunes with it, and `cti-audit
  # --check` says whether the trail is writable and the collector reachable.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-audit" ./cmd/cti-audit )
  chmod 0755 "$CODE_DIR/bin/cti-audit"
  ok "built $CODE_DIR/bin/cti-audit"

  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-mailbox" ./cmd/cti-mailbox )
  chmod 0755 "$CODE_DIR/bin/cti-mailbox"
  ok "built $CODE_DIR/bin/cti-mailbox"

  # The fleet's only mailer: every runner sends through it (since 1.6.6).
  # The Go port of the old mailer.py, which was removed after 1.7.2.
  #
  # The chmod is not decorative. This script runs as root, the wrapper runs
  # the binary as $FLEET_USER, and root's umask decides whether that is
  # possible. Built without it under a restrictive umask the file lands 0700
  # root-owned, and the failure surfaces as "permission denied" from
  # `sudo cti-agent cti-mailer --check` - which reads like a sudo or Graph
  # problem rather than a file mode.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-mailer" ./cmd/cti-mailer )
  chmod 0755 "$CODE_DIR/bin/cti-mailer"
  ok "built $CODE_DIR/bin/cti-mailer"

  # Jira ticketing. Creates nothing without --for-real AND a project key in
  # JIRA_ALLOW_CREATE, so installing it does not arm it. No timer either: it
  # is driven by hand until the digest integration exists.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-jira" ./cmd/cti-jira )
  chmod 0755 "$CODE_DIR/bin/cti-jira"
  ok "built $CODE_DIR/bin/cti-jira"

  # Weekly application-security report. Sends through cti-mailer --lane was,
  # which refuses unless WAS_TO and WAS_ALLOW_TO are both set, so installing
  # it does not arm it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-appscan" ./cmd/cti-appscan )
  chmod 0755 "$CODE_DIR/bin/cti-appscan"
  ok "built $CODE_DIR/bin/cti-appscan"

  # Weekly Qualys VM scan report: the two scheduled scans combined. Sends
  # through cti-mailer --lane vmscan, which refuses unless VMSCAN_TO and
  # VMSCAN_ALLOW_TO are both set, so installing it does not arm it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-vmscan" ./cmd/cti-vmscan )
  chmod 0755 "$CODE_DIR/bin/cti-vmscan"
  ok "built $CODE_DIR/bin/cti-vmscan"

  # Supplier-request lane: judge each new supplier request, file a Kanban item
  # for the critical or unsure ones, and email one digest. Sends through
  # cti-mailer --lane supplier, which refuses unless SUPPLIER_TO and
  # SUPPLIER_ALLOW_TO are both set, and does nothing at all until
  # SUPPLIER_ADDRESS is set, so installing it does not arm it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-supplier" ./cmd/cti-supplier )
  chmod 0755 "$CODE_DIR/bin/cti-supplier"
  ok "built $CODE_DIR/bin/cti-supplier"

  # The scanner's own report per application, for the AppSec tickets. Writes
  # files only; run-appscan calls it when WAS_ATTACH_REPORT=1.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-appreport" ./cmd/cti-appreport )
  chmod 0755 "$CODE_DIR/bin/cti-appreport"
  ok "built $CODE_DIR/bin/cti-appreport"

  # Weekly domains check. Sends through cti-mailer --lane dom, which refuses
  # unless DOM_TO and DOM_ALLOW_TO are both set, so installing it does not arm it.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-domains" ./cmd/cti-domains )
  chmod 0755 "$CODE_DIR/bin/cti-domains"
  ok "built $CODE_DIR/bin/cti-domains"
else
  info "would build $AGENT_SRC/cti-agent"
fi

# ──────────────────────────────────────────────────────────── man pages ─────
# One page per operator command, so `man cti-domains` works on the box. Same
# checkout as everything else installed here. /usr/local/share/man is on the
# default MANPATH on Fedora, so nothing needs configuring.
bold "Man pages"
MAN_SRC="$SRC/../man/man1"
if [ -d "$MAN_SRC" ]; then
  run install -d -m 0755 "$MAN_DIR"
  n=0
  for page in "$MAN_SRC"/*.1; do
    [ -f "$page" ] || continue
    run install -m 0644 "$page" "$MAN_DIR/"
    n=$((n + 1))
  done
  if command -v mandb >/dev/null 2>&1; then
    run mandb -q "/usr/local/share/man" >/dev/null 2>&1 || true
  fi
  ok "$n man page(s) -> $MAN_DIR"
else
  warn "no man pages at $MAN_SRC - skipped"
fi

# ──────────────────────────────────────────────────────────── systemd ───────
bold "systemd units"
for u in "$SRC"/fleet/systemd-fedora/*; do
  run install -m 0644 -o root -g root "$u" "$UNIT_DIR/$(basename "$u")"
  info "$(basename "$u")"
done
run systemctl daemon-reload
ok "daemon-reload"

# ──────────────────────────────────────────────────── schedule timezone ──────
# OnCalendar= uses the SYSTEM timezone, and servers are conventionally UTC. A
# digest timed for 06:00 then lands at 02:00 for an operator on US Eastern -
# six hours stale by the time anyone reads it, which defeats the point of a
# morning digest. This was shipped that way and only surfaced once a real
# timer fired.
#
# Drop-ins rather than editing the units, so an upgrade that reinstalls the
# units does not silently revert the schedule.
# Own flag, not FAIL: this block runs before Verification, which initialises
# FAIL from PATHFAIL and would overwrite anything set here. Setting FAIL early
# looked correct and silently did nothing.
TZFAIL=0
FLEET_TZ=""; DIGEST_AT="06:00:00"; WEEKLY_AT="07:00:00"; PATCHTUE_AT="07:30:00"; MAILBOX_AT="07:00:00"
APPOWNERS_AT="07:15:00"; APPSCAN_AT="07:30:00"; DOMAINS_AT="08:00:00"; VMSCAN_AT="08:00:00"; SUPPLIER_AT="07:45:00"
VMSCAN_DAY="Mon"
if [ -n "$(settings_files)" ]; then
  # cfgval, not a grep pipeline - see the comment on cfgval for what the grep
  # version did to a real install. An absent key must read as empty here: every
  # one of these is optional and falls back to the default set just above.
  FLEET_TZ="$(cfgval FLEET_TIMEZONE)"
  PATCHTUE_AT="$(cfgval FLEET_PATCHTUESDAY_TIME)"; PATCHTUE_AT="${PATCHTUE_AT:-07:30:00}"
  DIGEST_AT="$(cfgval FLEET_DIGEST_TIME)";         DIGEST_AT="${DIGEST_AT:-06:00:00}"
  WEEKLY_AT="$(cfgval FLEET_WEEKLY_TIME)";         WEEKLY_AT="${WEEKLY_AT:-07:00:00}"
  MAILBOX_AT="$(cfgval FLEET_MAILBOX_TIME)";       MAILBOX_AT="${MAILBOX_AT:-07:00:00}"
  APPOWNERS_AT="$(cfgval FLEET_APPOWNERS_TIME)";   APPOWNERS_AT="${APPOWNERS_AT:-07:15:00}"
  APPSCAN_AT="$(cfgval FLEET_APPSCAN_TIME)";       APPSCAN_AT="${APPSCAN_AT:-07:30:00}"
  DOMAINS_AT="$(cfgval FLEET_DOMAINS_TIME)";       DOMAINS_AT="${DOMAINS_AT:-08:00:00}"
  VMSCAN_AT="$(cfgval FLEET_VMSCAN_TIME)";         VMSCAN_AT="${VMSCAN_AT:-08:00:00}"
  # The VM scan report's day is a setting too: when the report can run
  # depends on when the scheduled scans finish, which is the operator's to
  # know. Day names only (Mon..Sun, or a comma list), so nothing else can be
  # slipped into the OnCalendar line; anything else fails the install.
  VMSCAN_DAY="$(cfgval FLEET_VMSCAN_DAY)";         VMSCAN_DAY="${VMSCAN_DAY:-Mon}"
  _dayre='(Mon|Tue|Wed|Thu|Fri|Sat|Sun)'
  if ! printf '%s' "$VMSCAN_DAY" | grep -Eqx "${_dayre}(,${_dayre})*"; then
    bad "FLEET_VMSCAN_DAY=$VMSCAN_DAY is not a day (Mon, Tue, Wed, Thu, Fri, Sat or Sun; a comma list for more than one)"
    TZFAIL=1
    VMSCAN_DAY="Mon"
  fi
  SUPPLIER_AT="$(cfgval FLEET_SUPPLIER_TIME)";     SUPPLIER_AT="${SUPPLIER_AT:-07:45:00}"
fi

if [ -n "$FLEET_TZ" ]; then
  bold "Schedule timezone: $FLEET_TZ"
  if [ ! -e "/usr/share/zoneinfo/$FLEET_TZ" ]; then
    bad "$FLEET_TZ is not a known timezone"
    info "list them:  timedatectl list-timezones"
    TZFAIL=1
  else
    # The bare OnCalendar= is required: it is a LIST, so without clearing it
    # first the drop-in ADDS a schedule and the digest sends twice.
    for pair in "cti-agent-digest.timer:*-*-* $DIGEST_AT" \
                "cti-agent-mailbox.timer:*-*-* $MAILBOX_AT" \
                "cti-agent-weekly.timer:Mon *-*-* $WEEKLY_AT" \
                "cti-agent-appowners.timer:*-*-* $APPOWNERS_AT" \
                "cti-agent-appscan.timer:Fri *-*-* $APPSCAN_AT" \
                "cti-agent-domains.timer:Tue *-*-* $DOMAINS_AT" \
                "cti-agent-vmscan.timer:$VMSCAN_DAY *-*-* $VMSCAN_AT" \
                "cti-agent-supplier.timer:*-*-* $SUPPLIER_AT" \
                "cti-agent-patchtuesday.timer:Wed *-*-09..15 $PATCHTUE_AT"; do
      unit="${pair%%:*}"; cal="${pair#*:}"
      # Parse every schedule before writing it: a typo in one time must fail
      # the install now, not leave a timer that never fires.
      if ! systemd-analyze calendar "$cal $FLEET_TZ" >/dev/null 2>&1; then
        bad "$unit: \"$cal $FLEET_TZ\" is not a valid schedule (check its FLEET_*_TIME)"
        TZFAIL=1
        continue
      fi
      if [ "$MODE" != dryrun ]; then
        install -d -m 0755 "$UNIT_DIR/$unit.d"
        cat > "$UNIT_DIR/$unit.d/timezone.conf" <<DROPIN
# Written by install-fedora.sh from FLEET_TIMEZONE in fleet.env.
# The empty OnCalendar= clears the inherited schedule; OnCalendar is a list,
# and appending without clearing would run the job twice.
[Timer]
OnCalendar=
OnCalendar=$cal $FLEET_TZ
DROPIN
        ok "$unit -> $cal $FLEET_TZ"
      else
        info "would pin $unit to $cal $FLEET_TZ"
      fi
    done
    run systemctl daemon-reload
    if [ "$MODE" != dryrun ]; then
      # Prove the schedule parses and show the resolved next run, so a typo in
      # the time does not wait until tomorrow to reveal itself.
      if systemd-analyze calendar "*-*-* $DIGEST_AT $FLEET_TZ" >/dev/null 2>&1; then
        ok "next digest: $(systemd-analyze calendar "*-*-* $DIGEST_AT $FLEET_TZ" \
             2>/dev/null | awk -F': +' '/Next elapse/{print $2}')"
      else
        bad "FLEET_DIGEST_TIME=$DIGEST_AT is not a valid time"; TZFAIL=1
      fi
    fi
  fi
else
  info "FLEET_TIMEZONE unset - timers use the system timezone ($(date +%Z))"
  info "On a UTC server a 06:00 digest arrives at 02:00 US Eastern. Set"
  info "FLEET_TIMEZONE in $CONF_DIR/fleet.env to pin it to local time."
  if [ "$VMSCAN_DAY" != Mon ] || [ "$VMSCAN_AT" != 08:00:00 ]; then
    # The FLEET_*_TIME and _DAY settings are applied only with a timezone.
    warn "FLEET_VMSCAN_DAY/FLEET_VMSCAN_TIME are not applied without FLEET_TIMEZONE:"
    info "the VM scan report stays on Monday 08:00 system time until it is set."
  fi
fi

# ───────────────────────────────────────────────────────── SELinux labels ────
# The FHS layout was chosen so the default policy already permits everything,
# and it does - but only for files that carry the label their location implies.
# A fleet.env staged in a home directory and moved into /etc keeps its
# original context, because mv preserves labels. systemd then refuses to read
# it with "Failed to load environment files: Permission denied", as PID 1,
# as root - which reads like an impossible error and sends you looking at
# file modes that are already correct.
#
# The manual path hides this completely: the cti-agent wrapper uses
# sudo -u ctiagent, which is plain DAC and never involves init_t. So the
# pipeline works by hand and every timer fails.
if [ "$SEMODE" = Enforcing ] || [ "$SEMODE" = Permissive ]; then
  bold "SELinux labels"
  if command -v restorecon >/dev/null; then
    run restorecon -RF "$CONF_DIR" "$CODE_DIR" "$STATE_DIR"
    run restorecon -F "$UNIT_DIR"/cti-agent-*.service "$UNIT_DIR"/cti-agent-*.timer
    ok "relabelled config, code, state and units to policy defaults"
  else
    warn "restorecon not found - install policycoreutils to relabel"
  fi
fi

# ─────────────────────────────────────────────────────────── Claude Code ─────
bold "Claude Code"
CLAUDE_BIN=""
for c in /usr/bin/claude /usr/local/bin/claude; do
  [ -x "$c" ] && { CLAUDE_BIN="$c"; break; }
done
if [ -n "$CLAUDE_BIN" ]; then
  ok "found $CLAUDE_BIN"
elif [ -x "$STATE_DIR/.local/bin/claude" ]; then
  # The service account can replace a binary in its own HOME, and the
  # heartbeat would run the replacement every beat. run-checkin refuses it.
  warn "claude is only in $STATE_DIR/.local/bin - the heartbeat will NOT use it"
  info "Install it system-wide from the signed dnf repo: sudo dnf install claude-code"
  info "then remove the per-account copy: sudo rm $STATE_DIR/.local/bin/claude"
else
  warn "not installed - the digest timers do not need it, only the heartbeat does"
  info "Install from the signed dnf repo, then authenticate as $FLEET_USER:"
  info "  sudo tee /etc/yum.repos.d/claude-code.repo <<'REPO'"
  info "  [claude-code]"
  info "  name=Claude Code"
  info "  baseurl=https://downloads.claude.ai/claude-code/rpm/stable"
  info "  enabled=1"
  info "  gpgcheck=1"
  info "  gpgkey=https://downloads.claude.ai/keys/claude-code.asc"
  info "  REPO"
  info "  sudo dnf install claude-code"
  info ""
  info "Then, because the account has no login shell:"
  info "  sudo -u $FLEET_USER HOME=$STATE_DIR claude   # browser login, once"
  info "Paste the printed URL into a browser on your laptop and return the code."
fi

# Installed BEFORE verification, deliberately. Verification can fail - a
# hand-staged fleet.env with the wrong ownership is the common case - and
# the wrapper is the tool an operator needs to diagnose and re-check. When
# it was written after the gate, a failed verification left the box with no
# way to run a fleet command except by retyping four environment variables.

# ───────────────────────────────────────────────────── convenience wrapper ───
# Four environment variables is three too many to retype. This wrapper is the
# single supported way to run a fleet command by hand on this layout.
bold "Wrapper: /usr/local/bin/cti-agent"
if [ "$MODE" != dryrun ]; then
  replace_file /usr/local/bin/cti-agent 0755 <<WRAP
#!/usr/bin/env bash
# cti-agent - run a fleet command by hand with the FHS paths already set.
#
#   cti-agent run-digest daily --dry-run     (rehearse; nothing is sent)
#   cti-agent run-digest daily --for-real    (send)
#   cti-agent run-checkin --for-real
#
# Every command that changes something needs --dry-run or --for-real; with
# neither it prints usage and exits 2. \`cti-agent\` alone lists the commands.
#
#   cti-agent cti-mailer --check
#   cti-agent fleet-db recent
#   cti-agent fleet-board tail 30
#   cti-agent cti-alert --unit cti-agent-digest.service --dry-run
#   cti-agent cti-budget status
#   cti-agent cti-kev --horizon 30
#   cti-agent run-patchtuesday --dry-run
#   cti-agent run-patchtuesday --month 2026-08 --dry-run   (replay, never sends)
#
# Runs as $FLEET_USER via sudo, so invoke it with sudo yourself.
set -euo pipefail
export FLEET_HOME=$STATE_DIR
export FLEET_CODE=$CODE_DIR
export FLEET_ENV=$CONF_DIR/fleet.env
export FLEET_FEEDS=$CONF_DIR/feeds.txt
export HOME=$STATE_DIR
# Run from the state directory, as the systemd units do (WorkingDirectory=).
# Without this a relative path in fleet.env - QUALYS_KB_CACHE's old default,
# ./qualys_kb_cache.json - resolved against whatever directory the operator
# typed the command in, so a hand run and the timer read different files and
# the hand run failed where the timer did not.
cd "$STATE_DIR"
# No command, or a request for help: say what can be run, from the manifest the
# completions use, rather than a hand-kept list that drifts. Nothing is run.
USAGE=$CODE_DIR/share/cti-agent-usage
case "\${1:-}" in
  '') echo "usage: cti-agent <command> [flags]   (press TAB after cti-agent for the list)" >&2
      "\$USAGE" list >&2; exit 2 ;;
  -h|--help|help) echo "usage: cti-agent <command> [flags]"; "\$USAGE" list; exit 0 ;;
esac
cmd="\$1"
shift
# \`cti-agent CMD --help\` shows that command's flags and what it needs.
if [ \$# -eq 1 ]; then
  case "\$1" in -h|--help|help) exec "\$USAGE" show "\$cmd" ;; esac
fi
# A fleet command by NAME, nothing else. \$cmd used to be joined onto bin/
# as given, so "cti-agent ../../../usr/bin/env" ran env as the service
# account with fleet.env loaded - every secret printed - and ../../bin/bash
# was a shell as an account that is meant to have none. A name is letters,
# digits, dots and dashes with no slash, and it must be a regular file this
# installer put in bin/: not a symlink. (There is no lanes/ any more: the
# last Python lane, scout.py, is the Go cti-scout.)
case "\$cmd" in
  *[!a-z0-9.-]*|.*|'') echo "cti-agent: '\$cmd' is not a fleet command" >&2; exit 2 ;;
esac
target="$CODE_DIR/bin/\$cmd"
if [ ! -f "\$target" ] || [ -L "\$target" ]; then
  echo "cti-agent: '\$cmd' is not a fleet command (no \$target)" >&2
  exit 2
fi
# fleet.env is loaded as $FLEET_USER, the way every runner loads it, before
# the command starts. Without this a hand run saw only the five layout
# variables: cti-kev, the lanes, fleet-db and cti-budget ran on their
# built-in defaults, and a hand run could disagree with the timer it was
# meant to reproduce. The layout set here is restored afterwards, so a stale
# FLEET_HOME in fleet.env cannot point a hand run at different files.
LOADENV='_h="\$FLEET_HOME" _c="\$FLEET_CODE" _e="\$FLEET_ENV" _f="\$FLEET_FEEDS"
set -a; if [ -r "\$FLEET_ENV" ]; then . "\$FLEET_ENV"; fi; for f in \${FLEET_ENV_FILES:-}; do if [ -r "\$f" ]; then . "\$f"; fi; done; set +a
if [ -n "\${CREDENTIALS_DIRECTORY:-}" ]; then for f in "\$CREDENTIALS_DIRECTORY"/*; do n="\${f##*/}"; case "\$n" in *[!A-Z0-9_]*|[!A-Z]*) continue ;; esac; [ -f "\$f" ] && unset "\$n"; done; fi
export FLEET_HOME="\$_h" FLEET_CODE="\$_c" FLEET_ENV="\$_e" FLEET_FEEDS="\$_f" HOME="\$_h"
exec "\$@"'
# fleet-owners is the one command that runs as ROOT, not as $FLEET_USER: it
# writes owners.db and owners.json, which decide who outside the company is
# mailed our vulnerability reports, and the service account must be able to
# read them and not change them. No fleet.env: it needs none. SUDO_USER
# reaches it, so the change history names the person and not "root".
if [ "\$cmd" = fleet-owners ]; then
  [ "\$(id -u)" = 0 ] || { echo "cti-agent: fleet-owners runs as root - sudo cti-agent fleet-owners ..." >&2; exit 2; }
  # Out of the state directory, which the service account can write: root must
  # not resolve a relative path, or follow a planted link, in there.
  cd /
  exec env -i PATH=/usr/bin:/bin FLEET_GROUP=$FLEET_GROUP SUDO_USER="\${SUDO_USER:-}" \\
       /usr/bin/python3 -I "\$target" "\$@"
fi
# SETTINGS PER LANE (step 3, RUNBOOK 11o). A runner gets exactly the fleet.d
# files its unit loads, read from the installed unit's FLEET_ENV_FILES line;
# any other command (a check, a probe) gets every file. fleet.env is still
# sourced first while it exists.
FLEET_ENV_FILES=""
case "\$cmd" in
  run-*)
    for u in $UNIT_DIR/cti-agent-*.service; do
      if grep -q "^ExecStart=$CODE_DIR/bin/\$cmd\\b" "\$u" 2>/dev/null; then
        FLEET_ENV_FILES="\$(sed -n 's/^Environment="FLEET_ENV_FILES=\\(.*\\)"\$/\\1/p' "\$u" | head -1)"
        break
      fi
    done ;;
esac
if [ -z "\$FLEET_ENV_FILES" ]; then
  for f in $CONF_DIR/fleet.d/00-core.env $CONF_DIR/fleet.d/*.env; do
    case " \$FLEET_ENV_FILES " in *" \$f "*) ;; *) if [ -f "\$f" ]; then FLEET_ENV_FILES="\$FLEET_ENV_FILES \$f"; fi ;; esac
  done
fi
export FLEET_ENV_FILES
# SECRETS AS CREDENTIALS (step 2 of splitting fleet.env, RUNBOOK 11n). Once a
# secret this command needs is stored in /etc/credstore.encrypted, the hand
# run becomes a transient systemd unit with the grants its timer has
# (share/credentials.map, generated with the units' ImportCredential= lines):
# systemd decrypts only those secrets, for this run only, and removes them
# when it ends - however it ends. --pipe keeps the terminal; --wait returns
# the command's exit code; the journal records it as cti-manual-*, with who
# ran it. Until a needed secret is stored, the plain sudo path below runs, as
# it always has. Not copied from the unit: PrivateTmp, ProtectHome and
# ProtectSystem, so a file you pass a hand run (an advisory in /tmp, say)
# stays readable.
CREDMAP=$CODE_DIR/share/credentials.map
CREDSTORE=$CREDSTORE_DIR
secrets=""
if [ -r "\$CREDMAP" ]; then
  secrets="\$(awk -v c="\$cmd" '\$1 == c { \$1 = ""; print; exit }' "\$CREDMAP")"
fi
use_creds=0
for s in \$secrets; do
  if [ -f "\$CREDSTORE/\$s" ]; then use_creds=1; fi
done
if [ "\$use_creds" = 1 ] && command -v systemd-run >/dev/null 2>&1; then
  run=(/bin/bash -c "\$LOADENV" cti-agent)
  case "\$cmd" in *.py) run+=(/usr/bin/python3) ;; esac
  props=(-p User=$FLEET_USER -p Group=$FLEET_GROUP -p SupplementaryGroups=systemd-journal
         -p WorkingDirectory=$STATE_DIR -p UMask=0077 -p NoNewPrivileges=yes
         -p ProtectKernelTunables=yes -p ProtectKernelModules=yes -p ProtectControlGroups=yes
         -p RestrictSUIDSGID=yes -p LockPersonality=yes)
  for s in \$secrets; do props+=(-p "ImportCredential=\$s"); done
  # --expand-environment=no: systemd-run would otherwise expand \${...} in
  # the arguments - LOADENV's own loop, and anything the operator typed.
  # Not exec'd: on Ctrl-C (or a kill) the unit is stopped too, so a --for-real
  # run cannot carry on after the operator has cancelled it.
  unit="cti-manual-\${cmd//./-}-\$\$"
  trap 'systemctl stop "\$unit" 2>/dev/null; exit 130' INT
  trap 'systemctl stop "\$unit" 2>/dev/null; exit 143' TERM HUP
  rc=0
  systemd-run --quiet --wait --pipe --collect --expand-environment=no \\
       --unit="\$unit" --description="manual: \$cmd (by \${SUDO_USER:-root})" \\
       --setenv=FLEET_HOME=$STATE_DIR --setenv=FLEET_CODE=$CODE_DIR --setenv=FLEET_ENV=$CONF_DIR/fleet.env \\
       --setenv=FLEET_FEEDS=$CONF_DIR/feeds.txt --setenv=HOME=$STATE_DIR --setenv=SUDO_USER="\${SUDO_USER:-}" \\
       --setenv=FLEET_ENV_FILES="\$FLEET_ENV_FILES" \\
       "\${props[@]}" "\${run[@]}" "\$target" "\$@" || rc=\$?
  exit "\$rc"
fi
case "\$cmd" in
  *.py) exec sudo -u $FLEET_USER --preserve-env=FLEET_HOME,FLEET_CODE,FLEET_ENV,FLEET_ENV_FILES,FLEET_FEEDS,HOME \\
              /bin/bash -c "\$LOADENV" cti-agent /usr/bin/python3 "\$target" "\$@" ;;
  *)    exec sudo -u $FLEET_USER --preserve-env=FLEET_HOME,FLEET_CODE,FLEET_ENV,FLEET_ENV_FILES,FLEET_FEEDS,HOME \\
              /bin/bash -c "\$LOADENV" cti-agent "\$target" "\$@" ;;
esac
WRAP
  chmod 0755 /usr/local/bin/cti-agent
  ok "installed - try: sudo cti-agent fleet-db recent"
  # The updater: pull this kit, then run the installer from it. A fixed path to
  # the kit it was installed from, so `sudo cti-agent-update --for-real` is the
  # whole update. In /usr/local/sbin, which sudo's secure_path includes.
  install -d -m 0755 /usr/local/sbin
  replace_file /usr/local/sbin/cti-agent-update 0755 <<UPDATER
#!/usr/bin/env bash
# cti-agent-update - pull the kit and run the installer from it. Written by
# install-fedora.sh. Say how: --dry-run (look) or --for-real (update).
exec "$SRC/update-fedora.sh" "\$@"
UPDATER
  chmod 0755 /usr/local/sbin/cti-agent-update
  ok "installed - update the box with: sudo cti-agent-update --for-real"
else
  info "would write /usr/local/bin/cti-agent and /usr/local/sbin/cti-agent-update"
fi

# ────────────────────────────────────────────────────────── verification ─────
# The manifest. Readable by the service account so cti-mailer --check can
# compare itself against it; writable only by root, because a version record
# the fleet can edit is a version record that cannot be trusted.
if [ "$MODE" != dryrun ]; then
  umask 0027
  cat > "$CONF_DIR/version" <<VERSIONEOF
tag=$BUILD_TAG
commit=$BUILD_COMMIT
built=$BUILD_TIME
installed_by=$(id -un)
installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source=$AGENT_SRC
VERSIONEOF
  chown root:"$FLEET_GROUP" "$CONF_DIR/version"
  chmod 0640 "$CONF_DIR/version"
  ok "recorded $CONF_DIR/version"
fi

bold "Verification"
# Settings: fleet.env, or the per-lane files it was split into.
# A path that cannot work is not a warning. The previous run reported three
# wrong paths, printed "Installed", and the next command failed on the first
# of them - so the install said success about a box that could not run.
FAIL=0
[ "${PATHFAIL:-0}" = 0 ] || { FAIL=1; bad "config paths above must be fixed"; }
[ "${TZFAIL:-0}" = 0 ]   || { FAIL=1; bad "schedule timezone above must be fixed"; }
for p in "$CODE_DIR/bin/cti-alert" "$CODE_DIR/bin/cti-budget" \
         "$CODE_DIR/bin/cti-kev" "$CODE_DIR/bin/cti-sanitize" "$CODE_DIR/bin/cti-podprobe" "$CODE_DIR/bin/cti-falcon" "$CODE_DIR/bin/cti-triage" \
         "$CODE_DIR/bin/cti-patchtuesday" \
         "$CODE_DIR/bin/cti-mailbox" "$CODE_DIR/bin/cti-mailer" "$CODE_DIR/bin/cti-audit" \
         "$CODE_DIR/bin/cti-jira" "$CODE_DIR/bin/cti-appscan" "$CODE_DIR/bin/cti-vmscan" "$CODE_DIR/bin/cti-supplier" \
         "$CODE_DIR/bin/cti-appreport" "$CODE_DIR/bin/cti-domains" \
         "$CODE_DIR/bin/cti-enrich" "$CODE_DIR/bin/cti-brief" "$CODE_DIR/bin/cti-scout" "$CODE_DIR/bin/cti-lock" "$CODE_DIR/bin/cti-checkin-check" \
         "$CODE_DIR/bin/checkin-bash-guard" "$CODE_DIR/bin/fleet-trace"; do
  if [ -e "$p" ] || [ "$MODE" = dryrun ]; then ok "$p"; else bad "missing $p"; FAIL=1; fi
done

# EVERY ExecStart IN EVERY INSTALLED UNIT MUST EXIST AND BE EXECUTABLE.
#
# This is the check that was missing. A hand-written list of paths is a claim
# about the units, maintained separately from the units, and it was wrong:
# cti-agent-mailbox.service pointed at a runner nothing installed, and the
# first anyone knew was 203/EXEC in the journal at 07:04 - after OnFailure had
# already mailed about it.
#
# systemd cannot tell you this in advance. It resolves ExecStart at start
# time, so a unit with a missing binary installs, enables and arms without
# complaint, and fails only when the timer fires. Deriving the check from the
# units themselves means a new lane cannot be half-installed.
for u in "$UNIT_DIR"/cti-agent-*.service; do
  [ -f "$u" ] || continue
  exe=$(awk -F= '/^ExecStart=/{print $2; exit}' "$u" | awk '{print $1}')
  case "$exe" in
    ""|-*) continue ;;        # no ExecStart, or a "-" prefixed optional one
  esac
  if [ -x "$exe" ] || [ "$MODE" = dryrun ]; then
    ok "$(basename "$u") -> $exe"
  else
    bad "$(basename "$u") points at $exe which is missing or not executable"
    FAIL=1
  fi
done
if [ "$MODE" != dryrun ]; then
  # Prove the service account can actually write where systemd will point it.
  if sudo -u "$FLEET_USER" test -w "$STATE_DIR"; then
    ok "$FLEET_USER can write $STATE_DIR"
  else
    bad "$FLEET_USER cannot write $STATE_DIR"; FAIL=1
  fi
  # The heartbeat's own fail-closed checks, run as the account they guard
  # against: code and orchestrator files root-owned and unwritable by it, and
  # nothing in its HOME or config dir that would steer a beat. As root, -w
  # is always true, so this must run as $FLEET_USER.
  if audit_out="$(sudo -u "$FLEET_USER" env HOME="$STATE_DIR" FLEET_HOME="$STATE_DIR" \
        FLEET_CODE="$CODE_DIR" FLEET_ENV="$CONF_DIR/fleet.env" FLEET_ENV_FILES="$(split_settings_files)" \
        "$CODE_DIR/bin/run-checkin" --audit 2>&1)"; then
    ok "run-checkin --audit: orchestrator files root-owned, no steering files"
  else
    bad "run-checkin --audit refused - the heartbeat will not start:"
    printf '%s\n' "$audit_out" | sed 's/^/      /'
    FAIL=1
  fi
  # And that it can read the secret but not the world.
  # Prove SYSTEMD can read the env file, not just the service account. Those
  # are different subjects under SELinux: ctiagent reading it is DAC only,
  # while systemd reads it as init_t and a mislabelled file denies only the
  # latter. Testing the easy one and shipping is how a box passes install and
  # then fails every timer.
  # Every settings file: fleet.env, or the fleet.d files it was split into.
  if [ -z "$(settings_files)" ] && [ "$MODE" != dryrun ]; then
    bad "no settings: neither $CONF_DIR/fleet.env nor $CONF_DIR/fleet.d/00-core.env exists"
    FAIL=1
  fi
  for envf in $(settings_files); do
    envn="${envf#"$CONF_DIR"/}"
    if [ "$MODE" != dryrun ] && command -v matchpathcon >/dev/null 2>&1; then
      if matchpathcon -V "$envf" >/dev/null 2>&1; then
        ok "$envn SELinux label matches policy"
      else
        bad "$envn has the wrong SELinux label - systemd will be denied"
        info "$(matchpathcon -V "$envf" 2>&1 | head -1)"
        info "fix: sudo restorecon -RFv $CONF_DIR"
        FAIL=1
      fi
    fi
    if sudo -u "$FLEET_USER" test -r "$envf"; then
      ok "$FLEET_USER can read $envn"
    else
      envmode="$(stat -c '%a %U:%G' "$envf")"
      bad "$FLEET_USER cannot read $envf (it is $envmode)"
      info "root can read it regardless of the mode, which is why this is the"
      info "first thing to notice. Fix:"
      info "    sudo chown root:$FLEET_GROUP $envf"
      info "    sudo chmod 0640 $envf"
      FAIL=1
    fi
    # Test the world bits, not the number. The previous check compared an
    # octal mode as a decimal integer, so 0604 - which grants world read -
    # sorted below 640 and passed. Anything other than 0 in the last digit is
    # a finding.
    envmode="$(stat -c %a "$envf")"
    if [ "${envmode: -1}" = 0 ]; then
      ok "$envn is not world-readable (mode $envmode)"
    else
      bad "$envn is world-accessible (mode $envmode)"
      FAIL=1
    fi
  done
  for u in cti-agent-digest cti-agent-checkin cti-agent-scout cti-agent-weekly \
         cti-agent-patchtuesday; do
    if systemd-analyze verify "$UNIT_DIR/$u.service" 2>&1 | grep -q .; then
      warn "$u.service: systemd-analyze reported warnings (see below)"
      systemd-analyze verify "$UNIT_DIR/$u.service" 2>&1 | sed 's/^/      /'
    else
      ok "$u.service verifies"
    fi
  done

  # The alert template was never verified, because a template needs an
  # instance name before systemd will resolve it. That omission is why a unit
  # which could not start at all passed every install: the one unit whose job
  # is to report failure was the one unit nobody checked.
  if systemd-analyze verify 'cti-agent-alert@verify.service' 2>&1 | grep -q .; then
    bad "cti-agent-alert@.service does not verify:"
    systemd-analyze verify 'cti-agent-alert@verify.service' 2>&1 | sed 's/^/      /'
    FAIL=1
  else
    ok "cti-agent-alert@.service verifies"
  fi

  # SupplementaryGroups names a group that must exist, and systemd fails the
  # whole unit with "Result: resources" when it does not - before ExecStart,
  # so nothing appears in the service's own log.
  for g in $(grep -h '^SupplementaryGroups=' "$UNIT_DIR"/cti-agent-*.service 2>/dev/null \
             | cut -d= -f2 | tr ' ' '\n' | sort -u); do
    if getent group "$g" >/dev/null; then
      ok "group $g exists"
    else
      bad "group $g does not exist - units referencing it cannot start"
      info "remove the SupplementaryGroups line, or create the group"
      FAIL=1
    fi
  done
fi
# Which timers are actually running.
#
# This installer deliberately enables nothing - that is the operator's call -
# but it never said which of the timers it had just written were live, and a
# timer that was installed and never enabled is invisible: systemd reports no
# error because nothing asked it to run anything.
#
# It happened. Five of six timers sat unenabled on the production box for
# weeks. The digest ran every morning, so the fleet looked healthy, while the
# orchestrator had never taken a beat, the scout never swept a feed, the Patch
# Tuesday lane would have missed its month, and - worst of the five - the
# weekly never sent. Sev1 findings are suppressed from the daily digest
# specifically because the weekly carries them, so with the weekly disabled
# they were being dropped from human view entirely by a config gap rather than
# a bug.
# A unit's enabled state, as one word. `systemctl is-enabled` prints the state
# AND exits non-zero for anything but enabled, so an echo fallback after ||
# printed "disabled" twice (on two lines) for every disabled timer. Empty
# output - the unit is not installed - reads as "not-found".
unit_state() {
  local s
  s="$(systemctl is-enabled "$1" 2>/dev/null)" || true
  printf '%s' "${s:-not-found}"
}

# A lane not in FLEET_LANES has its timer turned off: a box that does not run
# the lane must not start it, and a timer left on for a lane nobody configured
# fails every run. Turning it back on is adding the lane to FLEET_LANES and
# enabling the timer (RUNBOOK section 9).
if [ -n "$LANES_IN_USE" ] && command -v systemctl >/dev/null; then
  for t in "$SRC"/fleet/systemd-fedora/*.timer; do
    unit="$(basename "$t")"
    lane="$(timer_lane "$unit")"
    if [ -n "$lane" ] && ! lane_in_use "$lane" && [ "$(unit_state "$unit")" = enabled ]; then
      warn "$unit: lane $lane is not in FLEET_LANES, so its timer is turned off"
      run systemctl disable --now "$unit"
    fi
  done
fi

if [ "$MODE" != dryrun ] && command -v systemctl >/dev/null; then
  bold "Timer status"
  _enabled_any=0
  for t in "$SRC"/fleet/systemd-fedora/*.timer; do
    unit="$(basename "$t")"
    lane="$(timer_lane "$unit")"
    if [ -n "$lane" ] && ! lane_in_use "$lane"; then
      info "$unit off: lane $lane is not in FLEET_LANES"
      continue
    fi
    state="$(unit_state "$unit")"
    if [ "$state" = enabled ]; then
      nxt="$(systemctl list-timers --all --no-legend "$unit" 2>/dev/null \
             | awk '{print $1, $2, $3}')"
      ok "$unit enabled${nxt:+ - next $nxt}"
      _enabled_any=1
    else
      info "$unit NOT enabled ($state)"
    fi
  done
  if [ "$_enabled_any" = 0 ]; then
    info "Nothing is scheduled yet. RUNBOOK.md section 9 has the steps, in order."
  fi
  # Named specifically, because this pair loses information silently rather
  # than failing.
  if lane_in_use digest && [ "$(unit_state cti-agent-weekly.timer)" != enabled ]; then
    info "cti-agent-weekly.timer is off: Sev1 findings are suppressed from the"
    info "daily digest on the assumption the weekly carries them, so right now"
    info "they reach nobody. Enable it or raise the daily Sev1 limit."
  fi
fi

if [ "$FAIL" != 0 ]; then
  bad "fix the above before enabling anything"
  # The wrapper is already installed by this point, so say so: the natural
  # next move after a failed verification is to inspect something, and
  # discovering the tool is missing sends people hunting for a second bug.
  info "sudo cti-agent <cmd> works already - the wrapper is installed."
  info "Re-run this script after fixing; it is idempotent."
  bail 1
fi
# ──────────────────────────────────────────────────────────── next steps ─────
# The one place this is set. Reaching it means the config checks, the binaries,
# the units, the wrapper, the version manifest and the whole Verification block
# all ran. Anything that ends the script before here is a partial install and
# the EXIT trap will say so.
EXPECTED_EXIT=1
# An upgrade or a new box? A box with any fleet timer enabled is a running
# fleet, and the first-deployment steps would only be noise there: say it is
# running and stop. A new box gets one line pointing at the steps, which live
# in RUNBOOK.md section 9 so there is one copy of them.
_enabled=0
if command -v systemctl >/dev/null; then
  for t in "$SRC"/fleet/systemd-fedora/*.timer; do
    if [ "$(unit_state "$(basename "$t")")" = enabled ]; then
      _enabled=$((_enabled + 1))
    fi
  done
fi
if [ "$_enabled" -gt 0 ]; then
  printf '\n\033[1mUpdated. The fleet is running: %d timer(s) enabled - nothing else to do.\033[0m\n' "$_enabled"
  info "To enable another lane, follow RUNBOOK.md section 9 (the gate for each timer)."
else
  printf '\n\033[1mInstalled. No timer is enabled yet - that is deliberate.\033[0m\n'
  info "Next: sudo cti-agent-onboard --for-real  (which lanes, their settings, their secrets)."
  info "Then enable the lanes: RUNBOOK.md section 9, \"On a new deployment\"."
fi
