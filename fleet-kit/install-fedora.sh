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

CODE_DIR=/opt/cti-agent
CONF_DIR=/etc/cti-agent
STATE_DIR=/var/lib/cti-agent
UNIT_DIR=/etc/systemd/system
FLEET_USER=ctiagent
FLEET_GROUP=ctiagent
AGENT_REPO=https://github.com/zany2dmax/cti-agent
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE=install
for arg in "$@"; do
  case "$arg" in
    --dry-run)   MODE=dryrun ;;
    --uninstall) MODE=uninstall ;;
    --purge)     MODE=purge ;;
    -h|--help)   sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
run()  { if [ "$MODE" = dryrun ]; then info "would run: $*"; else "$@"; fi; }

# ─────────────────────────────────────────────────────────── uninstall ────────
if [ "$MODE" = uninstall ] || [ "$MODE" = purge ]; then
  [ "$(id -u)" = 0 ] || { bad "run with sudo"; exit 1; }
  bold "Stopping and disabling timers"
  for t in digest weekly checkin scout; do
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
  exit 0
fi

# ──────────────────────────────────────────────────────────── preflight ───────
bold "Preflight"
[ "$(id -u)" = 0 ] || { bad "run with sudo"; exit 1; }

if [ -r /etc/os-release ]; then
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    fedora:*|rhel:*|centos:*|rocky:*|almalinux:*|*:*fedora*|*:*rhel*)
      ok "${PRETTY_NAME:-$ID}" ;;
    *)
      warn "${PRETTY_NAME:-unknown} is not Fedora/RHEL-family"
      info "install.sh is the Debian/Ubuntu-oriented variant"
      read -r -p "  Continue anyway? [y/N] " c
      [ "${c:-n}" = y ] || exit 1 ;;
  esac
else
  warn "no /etc/os-release; assuming RHEL family"
fi

command -v systemctl >/dev/null || { bad "systemd not found"; exit 1; }
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
            services.nvd.nist.gov api.first.org www.cisa.gov; do
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
for f in fleet-board fleet-db run-digest run-checkin; do
  run install -m 0755 -o root -g root "$SRC/fleet/bin/$f" "$CODE_DIR/bin/$f"
  info "bin/$f"
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
if [ -f "$STATE_DIR/CLAUDE.md" ]; then
  ok "CLAUDE.md exists, not overwriting your edits"
else
  run install -m 0640 -o "$FLEET_USER" -g "$FLEET_GROUP" \
      "$SRC/fleet/CLAUDE.md" "$STATE_DIR/CLAUDE.md"
  info "CLAUDE.md -> $STATE_DIR (the orchestrator's standing instructions)"
fi

bold "Skills"
SKILLS="$STATE_DIR/.claude/skills"
run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$STATE_DIR/.claude" "$SKILLS"
for s in checkin cti-digest scout-sweep; do
  run install -d -m 0750 -o "$FLEET_USER" -g "$FLEET_GROUP" "$SKILLS/$s"
  run install -m 0640 -o "$FLEET_USER" -g "$FLEET_GROUP" \
      "$SRC/fleet/skills/$s/SKILL.md" "$SKILLS/$s/SKILL.md"
  info "/$s"
done

# ───────────────────────────────────────────────────────────── config ────────
bold "Config"
if [ -f "$CONF_DIR/fleet.env" ]; then
  ok "$CONF_DIR/fleet.env exists, leaving it alone"
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
if [ "$MODE" != dryrun ]; then
  ( cd "$AGENT_SRC" && go build -o "$AGENT_SRC/cti-agent" ./cmd/cti-agent )
  chmod 0755 "$AGENT_SRC/cti-agent"
  ok "built $AGENT_SRC/cti-agent"
  # The failure alerter. It lives in bin/ next to the shell helpers because
  # the alert units invoke it by absolute path, and it must exist before any
  # timer is enabled - an OnFailure pointing at a missing binary means the
  # failure is silent, which is the thing this is here to prevent.
  ( cd "$AGENT_SRC" && go build -o "$CODE_DIR/bin/cti-alert" ./cmd/cti-alert )
  chmod 0755 "$CODE_DIR/bin/cti-alert"
  ok "built $CODE_DIR/bin/cti-alert"

  # The quota governor. The heartbeat and its operator share one subscription,
  # so the fleet rations itself rather than competing. run-checkin skips the
  # gate if this is missing, which keeps an older install beating - but then
  # nothing is stopping it, so build it here.
  ( cd "$AGENT_SRC" && go build -o "$CODE_DIR/bin/cti-budget" ./cmd/cti-budget )
  chmod 0755 "$CODE_DIR/bin/cti-budget"
  ok "built $CODE_DIR/bin/cti-budget"
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

# ────────────────────────────────────────────────────────── verification ─────
bold "Verification"
FAIL=0
for p in "$CODE_DIR/bin/run-digest" "$CODE_DIR/bin/cti-alert" \
         "$CODE_DIR/bin/cti-budget" \
         "$CODE_DIR/lanes/enrich.py" "$CONF_DIR/fleet.env"; do
  if [ -e "$p" ] || [ "$MODE" = dryrun ]; then ok "$p"; else bad "missing $p"; FAIL=1; fi
done
if [ "$MODE" != dryrun ]; then
  # Prove the service account can actually write where systemd will point it.
  if sudo -u "$FLEET_USER" test -w "$STATE_DIR"; then
    ok "$FLEET_USER can write $STATE_DIR"
  else
    bad "$FLEET_USER cannot write $STATE_DIR"; FAIL=1
  fi
  # And that it can read the secret but not the world.
  if sudo -u "$FLEET_USER" test -r "$CONF_DIR/fleet.env"; then
    ok "$FLEET_USER can read fleet.env"
  else
    bad "$FLEET_USER cannot read $CONF_DIR/fleet.env"; FAIL=1
  fi
  if [ "$(stat -c %a "$CONF_DIR/fleet.env")" -le 640 ]; then
    ok "fleet.env is not world-readable"
  else
    bad "fleet.env is too permissive"; FAIL=1
  fi
  for u in cti-agent-digest cti-agent-checkin cti-agent-scout cti-agent-weekly; do
    if systemd-analyze verify "$UNIT_DIR/$u.service" 2>&1 | grep -q .; then
      warn "$u.service: systemd-analyze reported warnings (see below)"
      systemd-analyze verify "$UNIT_DIR/$u.service" 2>&1 | sed 's/^/      /'
    else
      ok "$u.service verifies"
    fi
  done
fi
[ "$FAIL" = 0 ] || { bad "fix the above before enabling anything"; exit 1; }

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
#
# Runs as $FLEET_USER via sudo, so invoke it with sudo yourself.
set -euo pipefail
export FLEET_HOME=$STATE_DIR
export FLEET_CODE=$CODE_DIR
export FLEET_ENV=$CONF_DIR/fleet.env
export FLEET_FEEDS=$CONF_DIR/feeds.txt
export HOME=$STATE_DIR
cmd="\${1:?usage: cti-agent <run-digest|run-checkin|cti-alert|cti-budget|fleet-db|fleet-board|mailer.py|enrich.py|scout.py|brief.py> [args]}"
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

# ──────────────────────────────────────────────────────────── next steps ─────
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

$(printf '\033[1mIf something is denied for no visible reason\033[0m')

   sudo ausearch -m avc -ts recent          # SELinux denials
   systemd-analyze security cti-agent-digest.service
   journalctl -u cti-agent-digest -n 50 --no-pager

NEXT
