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
#   3. Applies the replacements in scripts/scrub-patterns.txt to every file,
#      and to every commit and tag message.
#   4. Verifies nothing sensitive survives, then STOPS.
#
#   Each rule is checked with Perl-compatible regexes (git grep -P, perl), the
#   same flavour filter-repo applies, so (?i) and \b mean what they say. The
#   check used to be git grep -E: on macOS that has no \b and rejects (?i), the
#   error was discarded, and such a rule always counted zero hits.
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
# The verification below depends on PCRE. A git built without it would make
# every rule count zero hits, so refuse rather than report a false "clean".
# The probe must match (this script says "scrub"); 1 would mean \b or (?i) is
# not understood, and anything higher that -P is not supported at all.
probe=0
git grep -q -P '(?i)\bscrub\b' HEAD -- "scripts/scrub-history.sh" 2>/dev/null || probe=$?
if [ "$probe" != "0" ]; then
  echo "  git grep -P does not work here (exit $probe); the check could not see"
  printf '%s\n' '  (?i) or \b rules. Install a git built with PCRE (brew install git).'
  exit 1
fi
command -v perl >/dev/null 2>&1 || { echo "  perl not found; it checks commit messages."; exit 1; }

# Remember where the rewrite will go, before filter-repo removes 'origin', and
# which branches are already published there: only those are pushed back.
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
ORIGIN_HEADS="$(git ls-remote --heads origin 2>/dev/null | sed 's#.*refs/heads/##' | tr '\n' ' ' || true)"
echo "  repo:   $REPO"
echo "  origin: ${ORIGIN_URL:-none}"
echo "  published branches: ${ORIGIN_HEADS:-unknown (could not reach origin)}"
echo "  branch: $(git rev-parse --abbrev-ref HEAD)"
echo "  commits: $(git rev-list --all --count)"

# ── 1. backup ────────────────────────────────────────────────────────────────
# The backup is a full mirror of pre-scrub history, which means it CONTAINS the
# very data you are scrubbing. Treat it as sensitive: keep it out of synced
# folders, and delete it once the rewrite is pushed and verified.
bold "Backup (mirror clone, keeps every ref)"

# || true because ls exits non-zero with no matches, and set -e would abort.
# Timestamps are YYYYMMDD-HHMMSS, so alphabetical order is chronological and
# head -1 is genuinely the oldest - the only true pre-scrub restore point.
EXISTING=$(ls -d "${REPO}".backup-* 2>/dev/null | head -20 || true)
if [ -n "$EXISTING" ]; then
  echo "  Existing backups found:"
  echo "$EXISTING" | while read -r b; do
    echo "    $(basename "$b")  ($(du -sh "$b" 2>/dev/null | cut -f1))"
  done
  echo
  warn "Each of these holds a full copy of the UNSCRUBBED history."
  warn "The oldest is your real restore point; later ones are snapshots of"
  warn "already-partly-scrubbed history and are mostly clutter."
  read -r -p "  Take another backup anyway? [y/N] " ANOTHER
  case "$ANOTHER" in
    [yY]*) : ;;
    *) REUSE_BACKUP="$(echo "$EXISTING" | head -1)"
       echo "  Reusing $(basename "$REUSE_BACKUP") as the restore point."
       SKIP_BACKUP=1 ;;
  esac
fi

case "$(dirname "$REPO")" in
  *CloudStorage*|*OneDrive*|*Dropbox*|*"Google Drive"*|*iCloud*)
    warn "This repo lives in a cloud-synced folder. Backups written here will"
    warn "sync to that provider, replicating the data you are trying to"
    warn "contain - and most providers keep their own version history."
    warn "Consider: BACKUP_DIR=~/local-backups $0"
    ;;
esac

if [ "${SKIP_BACKUP:-0}" = "1" ]; then
  BACKUP="$REUSE_BACKUP"
else
  # BACKUP_DIR lets you put the mirror outside a synced folder.
  if [ -n "${BACKUP_DIR:-}" ]; then
    mkdir -p "$BACKUP_DIR"
    BACKUP="$BACKUP_DIR/$(basename "$REPO").backup-$STAMP"
  else
    BACKUP="${REPO}.backup-${STAMP}"
  fi
  git clone --mirror "$REPO" "$BACKUP/.git" >/dev/null 2>&1
  chmod -R go-rwx "$BACKUP" 2>/dev/null || true
  echo "  wrote $BACKUP (mode 700)"
fi
echo "  to restore: git -C \"$BACKUP\" push --mirror <remote>"

# ── 2. what we are removing ──────────────────────────────────────────────────
PATHS=(
  "cti-vuln-report.md"
  "fleet-kit/sample-report.md"
  "fleet-kit/sample-digest.html"
  # A build of cti-appreport committed by mistake (b8e3994, untracked in
  # eabcd23). The text rules cannot clean it - filter-repo leaves binary files
  # alone - and a binary has no place in history anyway.
  "cti-appreport"
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
  # The rules list what is being scrubbed, so they go to a private temp file,
  # not a fixed world-readable path in /tmp, and are removed on exit.
  RULES="$(mktemp "${TMPDIR:-/tmp}/scrub-replacements.XXXXXX")"
  chmod 600 "$RULES"
  trap 'rm -f "$RULES"' EXIT
  grep -vE '^\s*(#|$)' "$PATTERNS" > "$RULES"
  n=$(wc -l < "$RULES" | tr -d ' ')
  echo "  $n rule(s) from scripts/scrub-patterns.txt, for file contents and messages"
  # Show only the replacement side, so running this in a shared terminal or
  # pasting the output somewhere does not re-disclose what you are scrubbing.
  awk -F'==>' '{print "    <pattern> ==> " $2}' "$RULES" | sort -u
  REPLACE_ARGS=(--replace-text "$RULES" --replace-message "$RULES")
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
#
# Every file in every commit is checked with git grep -P, and every commit and
# tag message with perl: both Perl-compatible, like the rewrite itself. git grep
# exits 0 on a hit and 1 on none (none is the SUCCESS case); anything else is an
# error, and an error is a failure here, never a zero. Discarding it is how a
# rule git could not parse used to count as clean.
if [ -s "${RULES:-}" ]; then
  ALL_COMMITS=$(git rev-list --all)
  MESSAGES="$(mktemp "${TMPDIR:-/tmp}/scrub-messages.XXXXXX")"
  chmod 600 "$MESSAGES"
  trap 'rm -f "$RULES" "$MESSAGES"' EXIT
  { git log --all --format='%B'; git for-each-ref refs/tags --format='%(contents)'; } > "$MESSAGES"
  i=0
  while IFS= read -r rule; do
    i=$((i + 1))
    pat="${rule%%==>*}"
    pat="${pat#regex:}"
    lit=""
    if [ "$pat" = "${rule%%==>*}" ]; then
      # A literal rule: match it literally. PCRE takes \Q...\E; perl gets
      # the flag and quotes it itself, since \Q is not a regex escape there.
      lit=1
      pat="\\Q${pat}\\E"
    fi
    # shellcheck disable=SC2086 # one argument per commit, on purpose
    hits=$(git grep -l -P "$pat" $ALL_COMMITS -- 2>/dev/null | wc -l | tr -d ' ') || true
    grc=0
    # shellcheck disable=SC2086
    git grep -q -P "$pat" $ALL_COMMITS -- 2>/dev/null || grc=$?
    if [ "$grc" -gt 1 ]; then
      warn "rule $i could not be checked (git grep exit $grc) - fix the rule"
      FAIL=1
      continue
    fi
    if [ "$hits" != "0" ]; then
      # The pattern file is gitignored, so a hit here is a real finding.
      warn "rule $i still matches $hits file version(s) - inspect before pushing"
      FAIL=1
    fi
    mrc=0
    raw="${rule%%==>*}"
    PAT="${raw#regex:}" LIT="$lit" perl -ne 'BEGIN { $p = $ENV{LIT} ? quotemeta($ENV{PAT}) : $ENV{PAT}; $p = qr/$p/ } $n++ if /$p/; END { exit($n ? 0 : 1) }' "$MESSAGES" || mrc=$?
    if [ "$mrc" = "0" ]; then
      warn "rule $i still matches a commit or tag message - inspect before pushing"
      FAIL=1
    elif [ "$mrc" != "1" ]; then
      warn "rule $i could not be checked against messages (perl exit $mrc)"
      FAIL=1
    fi
  done < "$RULES"
  [ "$FAIL" = "0" ] && echo "  clean: all $i replacement rule(s), in files and messages"
fi
echo "  commits after rewrite: $(git rev-list --all --count)"
[ "$FAIL" = "0" ] || { echo; warn "Verification FAILED - do not push. Restore from $BACKUP."; exit 1; }

# ── 6. next steps ────────────────────────────────────────────────────────────
# Push back only the branches that were already published: --all would also
# publish every local branch that was never meant to leave this machine.
PUSH_BRANCHES=""
for b in $ORIGIN_HEADS; do
  if git show-ref --verify --quiet "refs/heads/$b"; then PUSH_BRANCHES="$PUSH_BRANCHES $b"; fi
done
LOCAL_ONLY=""
for b in $(git for-each-ref refs/heads --format='%(refname:short)'); do
  case " $ORIGIN_HEADS " in *" $b "*) : ;; *) LOCAL_ONLY="$LOCAL_ONLY $b" ;; esac
done

cat <<NEXT

$(printf '\033[1mVerified clean. Nothing has been pushed.\033[0m')

filter-repo removed the 'origin' remote on purpose, so you cannot force-push by
accident. Check the result first (task test lint vet), then:

  git remote add origin ${ORIGIN_URL:-<the repository URL>}
  git push --force origin${PUSH_BRANCHES:- <the branches that were published>}
  git push --force origin --tags

Local-only branches, not pushed:${LOCAL_ONLY:- none}

Then finish the job - the rewrite alone is not remediation:

  1. GitHub still serves old commits by SHA. Ask GitHub Support to remove
     cached views and stale refs (including pull request refs), listing the old
     SHAs. The backup mirror can list them:
       git -C "$BACKUP" log --all --format=%H -- <affected paths>
  2. Check forks and other clones. A fork made before the leak does not hold
     it; one made after does, and only its owner or GitHub can remove it.
  3. Anyone who cloned before the rewrite still has the data. Treat what was
     public as disclosed, not recalled, and act on that (rotate, patch, MFA).
  4. Every other checkout has the old history: re-clone it or reset it to the
     new branch. One old clone pushed back restores everything. A deployed kit
     that only fast-forwards needs one fetch --force --tags and reset --hard.
  5. Delete the backup mirror once the force-push is verified. It holds the
     unscrubbed history:
       rm -rf "$BACKUP"
     If it is in a cloud-synced folder, the provider's version history keeps
     a copy too.

NEXT
