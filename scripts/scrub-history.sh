#!/usr/bin/env bash
#
# scrub-history.sh - purge the CTI vulnerability reports from ALL git history.
#
# WHAT AND WHY
#   cti-vuln-report.md (and the fleet-kit sample fixtures) pair exploitable CVEs
#   with real hostnames, and were committed to a PUBLIC repository. Deleting
#   them from HEAD is not enough: GitHub serves old blobs by SHA, so every
#   historical version stays reachable until history is rewritten.
#
# WHAT THIS DOES
#   1. Makes a full backup clone next to the repo (nothing destructive first).
#   2. Runs git filter-repo to remove the report paths from every commit.
#   3. Applies text replacements for hostnames referenced inline elsewhere.
#   4. Verifies nothing sensitive survives, then STOPS.
#
# WHAT THIS DOES NOT DO
#   It does not force-push. Rewriting published history changes every commit
#   SHA, so read the checklist this prints before you push.
#
# REQUIREMENTS
#   git filter-repo   (brew install git-filter-repo, or pip install git-filter-repo)
#
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
cd "$REPO"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="${REPO}.backup-${STAMP}"

bold() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }

# ── preflight ────────────────────────────────────────────────────────────────
bold "Preflight"
command -v git-filter-repo >/dev/null 2>&1 || {
  echo "  git-filter-repo not found. Install it first:"
  echo "    brew install git-filter-repo     # macOS"
  echo "    pip3 install git-filter-repo     # or via pip"
  exit 1
}
if [ -n "$(git status --porcelain)" ]; then
  echo "  Working tree is dirty. Commit or stash first - filter-repo refuses to"
  echo "  run otherwise, and you do not want an uncommitted change in the mix."
  git status --short | sed 's/^/    /'
  exit 1
fi
echo "  repo:   $REPO"
echo "  branch: $(git rev-parse --abbrev-ref HEAD)"
echo "  commits: $(git rev-list --all --count)"

# ── 1. backup ────────────────────────────────────────────────────────────────
bold "Backup (mirror clone, keeps every ref)"
git clone --mirror "$REPO" "$BACKUP/.git" >/dev/null 2>&1
echo "  wrote $BACKUP"
echo "  to restore: git -C \"$BACKUP\" push --mirror <remote>"

# ── 2. what we are removing ──────────────────────────────────────────────────
PATHS=(
  "cti-vuln-report.md"
  "fleet-kit/sample-report.md"
  "fleet-kit/sample-digest.html"
)
bold "Paths to purge from all history"
for p in "${PATHS[@]}"; do
  n=$(git log --oneline --all -- "$p" | wc -l | tr -d ' ')
  echo "  $p  (in $n commit(s))"
done

# ── 3. inline replacements for files we KEEP ─────────────────────────────────
# Patterns live in scripts/scrub-patterns.txt, which is GITIGNORED on purpose.
#
# Two reasons they are not inline here:
#   1. A committed script listing your internal domains discloses those
#      domains. Less severe than a host inventory, but still a disclosure,
#      and it would survive the very scrub it performs.
#   2. --replace-text rewrites every blob including this script, so inline
#      patterns mangle themselves on the first run and the verification pass
#      then checks the wrong strings.
PATTERNS="$REPO/scripts/scrub-patterns.txt"
bold "Inline text replacements"
if [ ! -f "$PATTERNS" ]; then
  echo "  No $PATTERNS - copy the example and fill in your own values:"
  echo "    cp scripts/scrub-patterns.txt.example scripts/scrub-patterns.txt"
  echo "  Continuing with path deletion only (no text replacement)."
  REPLACE_ARGS=()
else
  grep -vE '^\s*(#|$)' "$PATTERNS" > /tmp/scrub-replacements.txt
  n=$(wc -l < /tmp/scrub-replacements.txt | tr -d ' ')
  echo "  $n rule(s) from scripts/scrub-patterns.txt"
  # Show only the replacement side, so running this in a shared terminal or
  # pasting the output somewhere does not re-disclose what you are scrubbing.
  awk -F'==>' '{print "    <pattern> ==> " $2}' /tmp/scrub-replacements.txt | sort -u
  REPLACE_ARGS=(--replace-text /tmp/scrub-replacements.txt)
fi

read -r -p "
Proceed? This rewrites every commit in $REPO. Backup is at
$BACKUP
Type 'scrub' to continue: " CONFIRM
[ "$CONFIRM" = "scrub" ] || { echo "aborted - nothing changed"; exit 1; }

# ── 4. rewrite ───────────────────────────────────────────────────────────────
bold "Rewriting history"
ARGS=()
for p in "${PATHS[@]}"; do ARGS+=(--path "$p"); done
git filter-repo --invert-paths "${ARGS[@]}" "${REPLACE_ARGS[@]}" --force

# ── 5. verify ────────────────────────────────────────────────────────────────
bold "Verification"
FAIL=0
for p in "${PATHS[@]}"; do
  if git log --oneline --all -- "$p" | grep -q .; then
    warn "STILL PRESENT in history: $p"; FAIL=1
  else
    echo "  gone: $p"
  fi
done
# Verify against the same rules we just applied, derived from the pattern file
# rather than hardcoded - so this list can never drift from the rules, and no
# internal name is baked into a tracked file.
if [ -s /tmp/scrub-replacements.txt ]; then
  ALL_COMMITS=$(git rev-list --all)
  while IFS= read -r rule; do
    pat="${rule%%==>*}"
    pat="${pat#regex:}"
    hits=$(git grep -l -E "$pat" $ALL_COMMITS -- 2>/dev/null | wc -l | tr -d ' ')
    if [ "$hits" != "0" ]; then
      # This script itself will match its own rules if the pattern file was
      # ever committed. It is gitignored, so a hit here is a real finding.
      warn "a pattern still matches $hits blob(s) - inspect before pushing"
      FAIL=1
    fi
  done < /tmp/scrub-replacements.txt
  [ "$FAIL" = "0" ] && echo "  clean: all $(wc -l < /tmp/scrub-replacements.txt | tr -d ' ') replacement rule(s)"
fi
echo "  commits after rewrite: $(git rev-list --all --count)"
[ "$FAIL" = "0" ] || { echo; warn "Verification FAILED - do not push. Restore from $BACKUP."; exit 1; }

# ── 6. next steps ────────────────────────────────────────────────────────────
cat <<NEXT

$(printf '\033[1mVerified clean. Nothing has been pushed.\033[0m')

filter-repo removed the 'origin' remote on purpose, so you cannot force-push by
accident. When you are ready:

  git remote add origin git@github.com:zany2dmax/cti-qualys-agent.git
  git push --force --all
  git push --force --tags

Then finish the job - the rewrite alone is not remediation:

  1. GitHub still caches old blobs. Open a Support ticket asking them to purge
     cached views and stale refs for this repo, citing the SHAs you removed.
  2. Check for forks and network clones before you assume it is contained:
     https://github.com/zany2dmax/cti-qualys-agent/network/members
  3. Anyone who cloned before the rewrite still has the data. Treat the 65
     hostnames and 16 PRESENT CVEs as disclosed, not recalled.
  4. Prioritize patching what was public - CVE-2020-1472 (Zerologon, 4 hosts)
     and the high-host-count items first.
  5. Rotate anything that leaked alongside it. Check for a committed .env or
     client secret:  git log --all --diff-filter=A --name-only | sort -u | grep -i env
  6. Consider making the repo private until the fleet code stabilizes.

Reports will not come back: internal/report/markdown.go now redacts hostnames
unless REPORT_HOSTNAMES=full, and .gitignore excludes generated reports.

NEXT
