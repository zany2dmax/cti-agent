#!/usr/bin/env bash
# install.sh - stand up the CTI agent fleet on a Linux server.
# Idempotent. Run as root (it creates the service account) or as ctifleet
# itself with SKIP_USER=1.
set -euo pipefail

FLEET_USER="${FLEET_USER:-ctifleet}"
FLEET_HOME="${FLEET_HOME:-/home/$FLEET_USER/fleet}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# ── 1. service account ───────────────────────────────────────────────────────
if [ "${SKIP_USER:-0}" != "1" ]; then
  say "Service account: $FLEET_USER"
  if ! id "$FLEET_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$FLEET_USER"
    echo "created $FLEET_USER"
  else
    echo "$FLEET_USER already exists"
  fi
fi

# ── 2. layout ────────────────────────────────────────────────────────────────
say "Layout under $FLEET_HOME"
install -d -m 750 "$FLEET_HOME"/{bin,lanes,state,reports,logs,archive,templates}
install -d -m 750 "$FLEET_HOME/../.claude/skills" 2>/dev/null || true

install -m 750 "$SRC/fleet/bin/fleet-board"  "$FLEET_HOME/bin/"
install -m 750 "$SRC/fleet/bin/fleet-db"     "$FLEET_HOME/bin/"
install -m 750 "$SRC/fleet/bin/run-digest"   "$FLEET_HOME/bin/"
install -m 750 "$SRC/fleet/bin/run-checkin"  "$FLEET_HOME/bin/"
install -m 750 "$SRC/fleet/lanes/enrich.py"  "$FLEET_HOME/lanes/"
install -m 750 "$SRC/fleet/lanes/scout.py"   "$FLEET_HOME/lanes/"
install -m 750 "$SRC/fleet/lanes/brief.py"   "$FLEET_HOME/lanes/"
install -m 750 "$SRC/fleet/lanes/mailer.py"  "$FLEET_HOME/lanes/"
[ -f "$FLEET_HOME/lanes/feeds.txt" ] \
  || install -m 640 "$SRC/fleet/lanes/feeds.txt" "$FLEET_HOME/lanes/"

# CLAUDE.md goes in the ORCHESTRATOR's working directory so it loads every session.
install -m 640 "$SRC/fleet/CLAUDE.md" "$FLEET_HOME/CLAUDE.md"

# ── 3. skills ────────────────────────────────────────────────────────────────
say "Skills"
SKILLS="$(dirname "$FLEET_HOME")/.claude/skills"
for s in checkin cti-digest scout-sweep; do
  install -d -m 750 "$SKILLS/$s"
  install -m 640 "$SRC/fleet/skills/$s/SKILL.md" "$SKILLS/$s/SKILL.md"
  echo "  /$s"
done

# ── 4. secrets ───────────────────────────────────────────────────────────────
say "Config"
if [ ! -f "$FLEET_HOME/fleet.env" ]; then
  install -m 600 "$SRC/fleet/fleet.env.example" "$FLEET_HOME/fleet.env"
  echo "created $FLEET_HOME/fleet.env - EDIT IT, it has placeholder secrets"
else
  echo "$FLEET_HOME/fleet.env exists, leaving it alone"
fi
chmod 600 "$FLEET_HOME/fleet.env"

# ── 4b. claude binary ────────────────────────────────────────────────────────
say "Claude Code"
CLAUDE_FOUND=""
for c in "/home/$FLEET_USER/.local/bin/claude" /usr/bin/claude \
         /usr/local/bin/claude /opt/homebrew/bin/claude; do
  [ -x "$c" ] && { CLAUDE_FOUND="$c"; break; }
done
[ -z "$CLAUDE_FOUND" ] && CLAUDE_FOUND="$(command -v claude 2>/dev/null || true)"
if [ -n "$CLAUDE_FOUND" ]; then
  echo "found: $CLAUDE_FOUND ($("$CLAUDE_FOUND" --version 2>/dev/null || echo 'version unknown'))"
  echo "the heartbeat resolves this at runtime; pin it with CLAUDE_BIN if you have several"
else
  echo "NOT FOUND. The digest timers will still work - they do not need Claude."
  echo "The /checkin heartbeat does. Install it as $FLEET_USER, then authenticate:"
  echo "    sudo -u $FLEET_USER bash -lc 'curl -fsSL https://claude.ai/install.sh | bash'"
  echo "    sudo -u $FLEET_USER bash -lc 'claude'   # interactive browser login, once"
fi

# ── 5. database ──────────────────────────────────────────────────────────────
say "Memory"
touch "$FLEET_HOME/board.md" "$FLEET_HOME/archive/board-archive.md"
FLEET_HOME="$FLEET_HOME" "$FLEET_HOME/bin/fleet-db" init

# ── 6. ownership ─────────────────────────────────────────────────────────────
if [ "${SKIP_USER:-0}" != "1" ]; then
  chown -R "$FLEET_USER:$FLEET_USER" "$(dirname "$FLEET_HOME")"
fi

# ── 7. systemd ───────────────────────────────────────────────────────────────
if [ "$(id -u)" = "0" ]; then
  say "systemd timers"
  for u in "$SRC"/fleet/systemd/*; do
    sed "s#/home/ctifleet#$(dirname "$FLEET_HOME")#g; s#\bctifleet\b#$FLEET_USER#g" \
      "$u" > "/etc/systemd/system/$(basename "$u")"
  done
  systemctl daemon-reload
  echo "installed. enable them when fleet.env is filled in:"
  echo "  systemctl enable --now cti-fleet-checkin.timer cti-fleet-digest.timer \\"
  echo "                          cti-fleet-weekly.timer cti-fleet-scout.timer"
else
  say "systemd (skipped - not root)"
  echo "copy $SRC/fleet/systemd/* to /etc/systemd/system/ as root"
fi

cat <<DONE

$(printf '\033[1mNext steps\033[0m')

  1. Edit  $FLEET_HOME/fleet.env      (tenant, client secret, Qualys, NVD key)
  2. Grant Mail.Send (Application) to the app registration in Entra + admin consent
  3. Verify:  python3 $FLEET_HOME/lanes/mailer.py --check
  4. Dry run: $FLEET_HOME/bin/run-digest daily --dry-run
  5. Enable the timers, then watch: journalctl -fu cti-fleet-digest.service

DONE
