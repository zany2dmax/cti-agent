#!/usr/bin/env bash
#
# dev-setup.sh - developer-machine conveniences. Touches nothing in the fleet.
#
#   ./scripts/dev-setup.sh            install the git hooks
#   ./scripts/dev-setup.sh --status   report what is installed
#
# Git does not version .git/hooks, so the hook lives in scripts/hooks/ and this
# copies it. That also means a hook silently stops existing after a fresh
# clone, which is why --status exists and why this prints what it did.
set -euo pipefail

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }

ROOT=$(git rev-parse --show-toplevel 2>/dev/null || true)
[ -n "$ROOT" ] || { bad "not inside a git checkout"; exit 1; }
cd "$ROOT"

if [ "${1:-}" = "--status" ]; then
  bold "Developer setup"
  for h in pre-commit; do
    if [ -x ".git/hooks/$h" ]; then
      if cmp -s ".git/hooks/$h" "scripts/hooks/$h"; then
        ok "$h installed and current"
      else
        bad "$h installed but DIFFERS from scripts/hooks/$h - re-run without --status"
      fi
    else
      bad "$h not installed"
    fi
  done
  printf '  %s\n' "gofmt: $(command -v gofmt || echo 'NOT FOUND')"
  exit 0
fi

bold "Git hooks"
mkdir -p .git/hooks
for h in pre-commit; do
  install -m 0755 "scripts/hooks/$h" ".git/hooks/$h"
  ok "$h"
done

if ! command -v gofmt >/dev/null 2>&1; then
  bad "gofmt is not in PATH - the hook will refuse the commit rather than"
  info "format silently. Install Go, or remove the hook."
fi

bold "Terminal capture (optional)"
cat <<'HOWTO'
    Claude can read anything under this checkout, including .logs/, which is
    gitignored. `task log -- <target>` already tees to .logs/last-run.log, so
    after running it you can just say "done" rather than pasting output.

    To capture a whole shell session instead of one task run:

        script -q -a .logs/term.log

    That records EVERY keystroke and all output until you exit, including
    anything you paste. .logs/ is gitignored and the file below is 0600, but
    treat it as sensitive: do not paste a credential into a captured session,
    and delete the file when you are done with it.

        : > .logs/term.log && chmod 600 .logs/term.log   # start clean
        rm -f .logs/term.log                             # when finished
HOWTO
mkdir -p .logs && chmod 0700 .logs
ok "'.logs/' ready (gitignored, 0700)"
