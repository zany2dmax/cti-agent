#!/usr/bin/env bash
#
# install-fedora.sh - deploy the CTI fleet on Fedora / RHEL / Rocky / Alma.
#
# WHY A SEPARATE INSTALLER
#   install.sh puts everything under /home/ctiagent and hardens the units with
#   ProtectHome=read-only plus a ReadWritePaths punch-through into /home. That
#   combination is order-dependent in systemd and is the exact shape SELinux is
#   most likely to deny on a Fedora box running enforcing. Rather than fight it,
#   this installer uses the FHS layout systemd and SELinux already expect:
#
#     /opt/cti-agent      code, root-owned, read-only to the service
#     /etc/cti-agent      config; fleet.env is 0640 root:ctiagent
#     /var/lib/cti-agent  state, created and chowned by systemd StateDirectory
#
#   Nothing lives under /home, so the units can set ProtectHome=yes and hide it
#   entirely - stricter than the original and less likely to break.
#
# USAGE
#   sudo ./install-fedora.sh                 install or upgrade
#   sudo ./install-fedora.sh --dry-run       print what would happen
#   sudo ./install-fedora.sh --uninstall     remove units, keep state and config
#   sudo ./install-fedora.sh --purge         remove everything including state
#
# It does NOT enable any timer. Enabling is a separate, deliberate step; see the
# staged rollout it prints at the end.
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
UNIT_DIR=/etc/systemd/system
FLEET_USER=ctiagent
FLEET_GROUP=ctiagent
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
    echo "  sudo /root/cti-agent-kit/fleet-kit/install-fedora.sh" >&2
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

MODE=install
for arg in "$@"; do
  case "$arg" in
    --dry-run)   MODE=dryrun ;;
    --uninstall) MODE=uninstall ;;
    --purge)     MODE=purge ;;
    -h|--help)   sed -n '2,30p' "${BASH_SOURCE[0]}"; bail 0 ;;
    *) echo "unknown option: $arg" >&2; bail 2 ;;
  esac
done

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
run()  { if [ "$MODE" = dryrun ]; then info "would run: $*"; else "$@"; fi; }

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
cfgval() {
  sed -n "s/^$1=//p" "${2:-$CONF_DIR/fleet.env}" 2>/dev/null \
    | tail -1 | tr -d '"'"'"' '
}

# ─────────────────────────────────────────────────────────── uninstall ────────
if [ "$MODE" = uninstall ] || [ "$MODE" = purge ]; then
  [ "$(id -u)" = 0 ] || { bad "run with sudo"; bail 1; }
  bold "Stopping and disabling timers"
  for t in digest weekly checkin scout patchtuesday; do
    systemctl disable --now "cti-agent-$t.timer" 2>/dev/null || true
    ok "cti-agent-$t.timer"
  done
  bold "Removing units"
  rm -f "$UNIT_DIR"/cti-agent-*.service "$UNIT_DIR"/cti-agent-*.timer
  systemctl daemon-reload
  ok "units removed"
  bold "Removing code"
  rm -rf "$CODE_DIR"
  ok "$CODE_DIR"
  if [ "$MODE" = purge ]; then
    bold "Purging config and state"
    warn "this deletes the client secret, the findings database and all reports"
    read -r -p "  Type 'purge' to confirm: " c
    if [ "$c" = purge ]; then
      rm -rf "$CONF_DIR" "$STATE_DIR"
      userdel "$FLEET_USER" 2>/dev/null || true
      ok "removed $CONF_DIR, $STATE_DIR and the $FLEET_USER account"
    else
      info "aborted; config and state kept"
    fi
  else
    bold "Kept"
    info "$CONF_DIR   (config and secrets)"
    info "$STATE_DIR  (findings db, reports, caches)"
    info "the $FLEET_USER account"
    info "--purge removes these too"
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
      info "install.sh is the Debian/Ubuntu-oriented variant"
      read -r -p "  Continue anyway? [y/N] " c
      [ "${c:-n}" = y ] || bail 1 ;;
  esac
else
  warn "no /etc/os-release; assuming RHEL family"
fi

command -v systemctl >/dev/null || { bad "systemd not found"; bail 1; }
ok "systemd $(systemctl --version | head -1 | awk '{print $2}')"

# Dependencies. Python is the lanes; Go builds the agent. dnf is only used if
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
case "$SEMODE" in
  Enforcing)
    ok "SELinux: Enforcing"
    info "state lives in /var/lib (var_lib_t), config in /etc (etc_t), code in"
    info "/opt - all standard locations, so no custom policy should be needed."
    info "If a run fails with an inexplicable permission error:"
    info "    sudo ausearch -m avc -ts recent"
    ;;
  Permissive) warn "SELinux: Permissive - denials are logged, not enforced" ;;
  *)          info "SELinux: $SEMODE" ;;
esac

# Outbound reachability. firewalld does not filter egress by default, so a
# failure here is almost always an Azure NSG or a proxy.
bold "Outbound connectivity"
for host in login.microsoftonline.com graph.microsoft.com \
            services.nvd.nist.gov api.first.org www.cisa.gov \
            blog.qualys.com www.bleepingcomputer.com; do
  if timeout 6 bash -c "</dev/tcp/$host/443" 2>/dev/null; then
    ok "$host:443"
  else
    warn "$host:443 unreachable - check the Azure NSG or proxy"
  fi
done
info "also needed: your Qualys pod (QUALYS_BASE_URL) - checked after config"

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
run install -d -m 0755 -o root -g root "$CODE_DIR" "$CODE_DIR/bin" "$CODE_DIR/lanes"
run install -d -m 0750 -o root -g "$FLEET_GROUP" "$CONF_DIR"
run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" \
    "$STATE_DIR" "$STATE_DIR/state" "$STATE_DIR/reports" "$STATE_DIR/archive"
info "$CODE_DIR   code   (root:root 0755, read-only to the service)"
info "$CONF_DIR   config (root:$FLEET_GROUP 0750)"
info "$STATE_DIR  state  ($FLEET_USER:$FLEET_GROUP 0750)"

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
for f in enrich.py scout.py brief.py mailer.py; do
  run install -m 0755 -o root -g root "$SRC/fleet/lanes/$f" "$CODE_DIR/lanes/$f"
  info "lanes/$f"
done
if [ -f "$CONF_DIR/feeds.txt" ]; then
  ok "feeds.txt exists in $CONF_DIR, not overwriting your edits"
else
  run install -m 0640 -o root -g "$FLEET_GROUP" "$SRC/fleet/lanes/feeds.txt" "$CONF_DIR/feeds.txt"
  info "feeds.txt -> $CONF_DIR (edit it: trim to vendors you actually run)"
fi
run install -m 0644 -o root -g root "$SRC/README.md" "$CODE_DIR/README.md"

# CLAUDE.md must sit in the orchestrator's working directory so it loads on
# every session. That is the state dir, since WorkingDirectory points there.
#
# "Not overwriting your edits" was protecting a file nobody had edited.
#
# The orchestrator's standing instructions were frozen at first install, so a
# deploy could never change them. That is not a hypothetical: the allowlist
# grant for cti-alert reached the box while the instruction telling the agent
# to use it did not, and the agent went on reporting that it could not reach
# a human while holding the capability to do so.
#
# So: remember the hash of what we install. Unmodified since last time means
# it is ours to update. Modified means an operator changed it, and THAT is
# worth preserving - but loudly, with the diff named, rather than with a
# cheerful ok that hides a stale file.
CLAUDE_MD_HASH="$STATE_DIR/.claude/CLAUDE.md.installed-sha256"
claude_md_unmodified() {
  # Identical to what we ship counts as unmodified even with no hash on
  # record. Without this, the FIRST run after this change always warns -
  # including for an operator who just copied the shipped file across by hand,
  # which is exactly what the warning would be telling them to do. A guard
  # whose first act is to cry wolf is a guard people learn to scroll past.
  cmp -s "$STATE_DIR/CLAUDE.md" "$SRC/fleet/CLAUDE.md" && return 0
  [ -f "$CLAUDE_MD_HASH" ] || return 1
  [ "$(sha256sum "$STATE_DIR/CLAUDE.md" | cut -d" " -f1)" = "$(cat "$CLAUDE_MD_HASH")" ]
}

if [ -f "$STATE_DIR/CLAUDE.md" ] && ! claude_md_unmodified; then
  warn "CLAUDE.md differs from the shipped version and was NOT updated"
  info "  yours:    $STATE_DIR/CLAUDE.md"
  info "  shipped:  $SRC/fleet/CLAUDE.md"
  info "  diff:     sudo diff -u $STATE_DIR/CLAUDE.md $SRC/fleet/CLAUDE.md"
  info "  The agent follows YOUR copy. If the shipped one changed how it"
  info "  escalates or what it may run, your copy will not know."
else
  run install -m 0640 -o "$FLEET_USER" -g "$FLEET_GROUP" \
      "$SRC/fleet/CLAUDE.md" "$STATE_DIR/CLAUDE.md"
  info "CLAUDE.md -> $STATE_DIR (the orchestrator's standing instructions)"
  if [ "$MODE" != dryrun ]; then
    install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$STATE_DIR/.claude"
    sha256sum "$STATE_DIR/CLAUDE.md" | cut -d" " -f1 > "$CLAUDE_MD_HASH"
    chmod 0640 "$CLAUDE_MD_HASH"
  fi
fi

bold "Skills"
SKILLS="$STATE_DIR/.claude/skills"
run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$STATE_DIR/.claude" "$SKILLS"
for s in checkin cti-digest scout-sweep patch-tuesday; do
  run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$SKILLS/$s"
  run install -m 0640 -o "$FLEET_USER" -g "$FLEET_GROUP" \
      "$SRC/fleet/skills/$s/SKILL.md" "$SKILLS/$s/SKILL.md"
  info "/$s"
done

# ───────────────────────────────────────────────────────────── config ────────
bold "Config"
if [ -f "$CONF_DIR/fleet.env" ]; then
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
      bad "fix the paths above in $CONF_DIR/fleet.env - every one of them is a"
      info "guaranteed runtime failure, several minutes into a run rather than"
      info "at startup. This blocks the install deliberately."
      info "The cti-agent wrapper is already installed; re-run when fixed."
    fi
  fi
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

# The organisation profile is NOT installed from the repo, and not created
# here either. It describes what this organisation runs, so the filled-in copy
# is gitignored and lives only in $CONF_DIR.
#
# Reported rather than created, because an empty profile is worse than an
# absent one: the triage agent would read it, find nothing, and return
# "unlikely" for everything instead of the honest "unknown". A file that makes
# an agent confidently wrong is not a safe default.
if [ -f "$CONF_DIR/ORG-PROFILE.md" ]; then
  if grep -q '^PROFILE-STATUS: TEMPLATE' "$CONF_DIR/ORG-PROFILE.md" 2>/dev/null; then
    warn "$CONF_DIR/ORG-PROFILE.md is still the unfilled template"
    info "  The triage lane will answer 'unknown' for everything until the"
    info "  PROFILE-STATUS line is removed. Edit it: sudo \$EDITOR $CONF_DIR/ORG-PROFILE.md"
  else
    ok "$CONF_DIR/ORG-PROFILE.md exists, not overwriting your edits"
  fi
else
  run install -m 0640 -o root -g "$FLEET_GROUP" \
      "$SRC/fleet/agents/triage/ORG-PROFILE-TEMPLATE.md" "$CONF_DIR/ORG-PROFILE.md"
  warn "created $CONF_DIR/ORG-PROFILE.md from the template - fill it in"
  info "  It carries a PROFILE-STATUS: TEMPLATE line. While that line is there"
  info "  the triage lane treats the profile as absent and says 'unknown'"
  info "  rather than reasoning from empty headings - placeholder prose fails"
  info "  silently in a way placeholder credentials do not."
fi
info "mode $(stat -c '%a %U:%G' "$CONF_DIR/fleet.env" 2>/dev/null || echo '0640 root:ctiagent')"

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

  # Monthly Patch Tuesday synopsis. Reads two public wrap-ups and correlates
  # against Qualys, so it needs outbound 443 to two more hosts - checked in
  # the preflight above.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-patchtuesday" ./cmd/cti-patchtuesday )
  chmod 0755 "$CODE_DIR/bin/cti-patchtuesday"
  ok "built $CODE_DIR/bin/cti-patchtuesday"

  # Mailbox cleanup. The ONLY binary here that modifies the mailbox, so it is
  # also the only one whose app-registration requirement is Mail.ReadWrite
  # rather than Mail.Read. It dry-runs unless given --for-real; the unit
  # passes that flag explicitly so the decision is visible in the unit.
  ( cd "$AGENT_SRC" && go build -ldflags "$LDFLAGS" -o "$CODE_DIR/bin/cti-mailbox" ./cmd/cti-mailbox )
  chmod 0755 "$CODE_DIR/bin/cti-mailbox"
  ok "built $CODE_DIR/bin/cti-mailbox"

  # The Go port of mailer.py. Built and installed, but nothing calls it yet -
  # the runners still use the Python one until RUNBOOK 11b says otherwise.
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
else
  info "would build $AGENT_SRC/cti-agent"
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
FLEET_TZ=""; DIGEST_AT="06:00:00"; WEEKLY_AT="07:00:00"; PATCHTUE_AT="07:30:00"
if [ -r "$CONF_DIR/fleet.env" ]; then
  # cfgval, not a grep pipeline - see the comment on cfgval for what the grep
  # version did to a real install. An absent key must read as empty here: every
  # one of these is optional and falls back to the default set just above.
  FLEET_TZ="$(cfgval FLEET_TIMEZONE)"
  PATCHTUE_AT="$(cfgval FLEET_PATCHTUESDAY_TIME)"; PATCHTUE_AT="${PATCHTUE_AT:-07:30:00}"
  DIGEST_AT="$(cfgval FLEET_DIGEST_TIME)";         DIGEST_AT="${DIGEST_AT:-06:00:00}"
  WEEKLY_AT="$(cfgval FLEET_WEEKLY_TIME)";         WEEKLY_AT="${WEEKLY_AT:-07:00:00}"
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
                "cti-agent-weekly.timer:Mon *-*-* $WEEKLY_AT" \
                "cti-agent-patchtuesday.timer:Wed *-*-09..15 $PATCHTUE_AT"; do
      unit="${pair%%:*}"; cal="${pair#*:}"
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
for c in /usr/bin/claude /usr/local/bin/claude "$STATE_DIR/.local/bin/claude"; do
  [ -x "$c" ] && { CLAUDE_BIN="$c"; break; }
done
if [ -n "$CLAUDE_BIN" ]; then
  ok "found $CLAUDE_BIN"
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
  cat > /usr/local/bin/cti-agent <<WRAP
#!/usr/bin/env bash
# cti-agent - run a fleet command by hand with the FHS paths already set.
#
#   cti-agent run-digest daily --dry-run
#   cti-agent run-digest daily
#   cti-agent run-checkin
#   cti-agent mailer.py --check
#   cti-agent fleet-db recent
#   cti-agent fleet-board tail 30
#   cti-agent cti-alert --unit cti-agent-digest.service --dry-run
#   cti-agent cti-budget status
#   cti-agent cti-kev --horizon 30
#   cti-agent run-patchtuesday --dry-run
#   cti-agent run-patchtuesday --month 2026-08   (replay, never sends)
#
# Runs as $FLEET_USER via sudo, so invoke it with sudo yourself.
set -euo pipefail
export FLEET_HOME=$STATE_DIR
export FLEET_CODE=$CODE_DIR
export FLEET_ENV=$CONF_DIR/fleet.env
export FLEET_FEEDS=$CONF_DIR/feeds.txt
export HOME=$STATE_DIR
cmd="\${1:?usage: cti-agent <run-digest|run-checkin|run-patchtuesday|cti-alert|cti-budget|cti-kev|cti-patchtuesday|cti-mailbox|cti-mailer|cti-jira|fleet-db|fleet-board|mailer.py|enrich.py|scout.py|brief.py> [args]}"
shift
case "\$cmd" in
  *.py) exec sudo -u $FLEET_USER --preserve-env=FLEET_HOME,FLEET_CODE,FLEET_ENV,FLEET_FEEDS,HOME \\
              /usr/bin/python3 "$CODE_DIR/lanes/\$cmd" "\$@" ;;
  *)    exec sudo -u $FLEET_USER --preserve-env=FLEET_HOME,FLEET_CODE,FLEET_ENV,FLEET_FEEDS,HOME \\
              "$CODE_DIR/bin/\$cmd" "\$@" ;;
esac
WRAP
  chmod 0755 /usr/local/bin/cti-agent
  ok "installed - try: sudo cti-agent fleet-db recent"
else
  info "would write /usr/local/bin/cti-agent"
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
# A path that cannot work is not a warning. The previous run reported three
# wrong paths, printed "Installed", and the next command failed on the first
# of them - so the install said success about a box that could not run.
FAIL=0
[ "${PATHFAIL:-0}" = 0 ] || { FAIL=1; bad "config paths above must be fixed"; }
[ "${TZFAIL:-0}" = 0 ]   || { FAIL=1; bad "schedule timezone above must be fixed"; }
for p in "$CODE_DIR/bin/cti-alert" "$CODE_DIR/bin/cti-budget" \
         "$CODE_DIR/bin/cti-kev" "$CODE_DIR/bin/cti-patchtuesday" \
         "$CODE_DIR/bin/cti-mailbox" "$CODE_DIR/bin/cti-mailer" \
         "$CODE_DIR/bin/cti-jira" \
         "$CODE_DIR/lanes/enrich.py" "$CONF_DIR/fleet.env"; do
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
  # And that it can read the secret but not the world.
  # Prove SYSTEMD can read the env file, not just the service account. Those
  # are different subjects under SELinux: ctiagent reading it is DAC only,
  # while systemd reads it as init_t and a mislabelled file denies only the
  # latter. Testing the easy one and shipping is how a box passes install and
  # then fails every timer.
  if [ "$MODE" != dryrun ] && command -v matchpathcon >/dev/null 2>&1; then
    if matchpathcon -V "$CONF_DIR/fleet.env" >/dev/null 2>&1; then
      ok "fleet.env SELinux label matches policy"
    else
      bad "fleet.env has the wrong SELinux label - systemd will be denied"
      info "$(matchpathcon -V "$CONF_DIR/fleet.env" 2>&1 | head -1)"
      info "fix: sudo restorecon -RFv $CONF_DIR"
      FAIL=1
    fi
  fi
  if sudo -u "$FLEET_USER" test -r "$CONF_DIR/fleet.env"; then
    ok "$FLEET_USER can read fleet.env"
  else
    envmode="$(stat -c '%a %U:%G' "$CONF_DIR/fleet.env")"
    bad "$FLEET_USER cannot read $CONF_DIR/fleet.env (it is $envmode)"
    info "root can read it regardless of the mode, which is why this is the"
    info "first thing to notice. Fix:"
    info "    sudo chown root:$FLEET_GROUP $CONF_DIR/fleet.env"
    info "    sudo chmod 0640 $CONF_DIR/fleet.env"
    FAIL=1
  fi
  # Test the world bits, not the number. The previous check compared an octal
  # mode as a decimal integer, so 0604 - which grants world read - sorted below
  # 640 and passed. Anything other than 0 in the last digit is a finding.
  envmode="$(stat -c %a "$CONF_DIR/fleet.env")"
  if [ "${envmode: -1}" = 0 ]; then
    ok "fleet.env is not world-readable (mode $envmode)"
  else
    bad "fleet.env is world-accessible (mode $envmode) - it holds the client secret"
    FAIL=1
  fi
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
if [ "$MODE" != dryrun ] && command -v systemctl >/dev/null; then
  bold "Timer status"
  _enabled_any=0
  for t in "$SRC"/fleet/systemd-fedora/*.timer; do
    unit="$(basename "$t")"
    state="$(systemctl is-enabled "$unit" 2>/dev/null || echo disabled)"
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
    info "Nothing is scheduled yet. See the numbered steps below."
  fi
  # Named specifically, because this pair loses information silently rather
  # than failing.
  if [ "$(systemctl is-enabled cti-agent-weekly.timer 2>/dev/null || echo disabled)" != enabled ]; then
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
cat <<NEXT

$(printf '\033[1mInstalled. No timer is enabled yet - that is deliberate.\033[0m')

1. Fill in the config, then confirm Graph can see the mailbox:

     sudo vi $CONF_DIR/fleet.env
     sudo cti-agent mailer.py --check

   Mail.Read is required. Mail.Send is required to send the digest.
   Missing "grant admin consent" is the usual cause of a 403.

2. Dry run the whole pipeline by hand. Sends nothing:

     sudo cti-agent run-digest daily --dry-run

   First run downloads the Qualys KnowledgeBase - several minutes.

3. Enable ONLY the daily digest. Live with it for a few days:

     sudo systemctl enable --now cti-agent-digest.timer
     systemctl list-timers 'cti-agent-*'
     journalctl -u cti-agent-digest -f

4. Once the digest is trustworthy, add the orchestrator heartbeat. This is the
   part that needs Claude Code authenticated as $FLEET_USER:

     sudo systemctl enable --now cti-agent-checkin.timer

5. Trim $CONF_DIR/feeds.txt to vendors you run, then:

     sudo systemctl enable --now cti-agent-scout.timer cti-agent-weekly.timer

6. The monthly Patch Tuesday synopsis. Replay a month you already sent by hand
   and compare before enabling it - a replay cannot send:

     sudo cti-agent run-patchtuesday --dry-run --month 2026-08
     sudo systemctl enable --now cti-agent-patchtuesday.timer

   Needs outbound 443 to blog.qualys.com and www.bleepingcomputer.com.

7. LAST, and only when the digest has been running for a few days: mailbox
   cleanup. It moves mail in a shared mailbox, so it is the one lane whose
   mistakes other people see.

   It needs Mail.ReadWrite as an APPLICATION permission with admin consent -
   Mail.Read cannot move a message. Apply the Application Access Policy first
   if you have not: without it that role is tenant-wide.

     sudo cti-agent mailer.py --check          # expect OK Mail.ReadWrite
     sudo cti-agent cti-mailbox                # dry run, moves nothing
     sudo systemctl enable --now cti-agent-mailbox.timer

   The first dry run reports everything as "leave". That is correct: the lane
   only touches messages a completed digest recorded, and the log starts
   filling from the next digest. Run the dry run again tomorrow before
   enabling the timer.

$(printf '\033[1mIf something is denied for no visible reason\033[0m')

   sudo ausearch -m avc -ts recent          # SELinux denials
   systemd-analyze security cti-agent-digest.service
   journalctl -u cti-agent-digest -n 50 --no-pager

NEXT
