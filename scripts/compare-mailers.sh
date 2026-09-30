#!/usr/bin/env bash
# compare-mailers.sh - prove cti-mailer behaves exactly like mailer.py.
#
# Runs both across the cases that matter and reports PASS or FAIL for each,
# so the answer is a verdict rather than six diffs to read.
#
# NOTHING IS SENT. Every case passes --dry-run, and the fixture recipients are
# example.com addresses that go nowhere even if one escaped.
#
#   scripts/compare-mailers.sh            # from a checkout, uses ./.env
#
# The refusal cases matter more than the successes. A port that sends the same
# mail but has quietly loosened the recipient gate is the failure worth
# hunting, and it looks like success from the happy path.
set -uo pipefail

cd "$(dirname "$0")/.."

PY="fleet-kit/fleet/lanes/mailer.py"
[ -f "$PY" ] || { echo "cannot find $PY - run this from the repo" >&2; exit 2; }

# Load the real config for credentials, then OVERRIDE every routing variable.
# The comparison must not depend on what a particular box has configured, and
# it must not be able to reference a real distribution list.
if [ -f ./.env ]; then set -a; . ./.env; set +a; fi
export DIGEST_TO="dl@example.com"
export DIGEST_CC="cc1@example.com,cc2@example.com"
export FLEET_ALLOW_TO="dl@example.com,cc1@example.com,cc2@example.com"
export FLEET_OPERATOR_EMAIL="op@example.com"
export CTI_REPLY_MAILBOX="reply@example.com"
unset DIGEST_CC_FROM_ALLOW_TO

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
printf '<html><body>comparison fixture</body></html>\n' > "$TMP/fixture.html"
printf '# raw report fixture\n\nnot a real report.\n'   > "$TMP/raw.md"

GO="$TMP/cti-mailer"
go build -o "$GO" ./cmd/cti-mailer || { echo "build failed" >&2; exit 2; }

pass=0; fail=0

# json <file> - sorted, so Python's insertion order and Go's sorted map keys
# do not read as a difference.
json() { python3 -m json.tool --sort-keys < "$1" 2>/dev/null || cat "$1"; }

compare() {
  local name="$1"; shift
  local po go pc gc
  python3 "$PY" "$@" > "$TMP/py.out" 2> "$TMP/py.err"; pc=$?
  "$GO"          "$@" > "$TMP/go.out" 2> "$TMP/go.err"; gc=$?

  local why=""
  [ "$pc" -eq "$gc" ] || why="exit codes differ: py=$pc go=$gc"

  if [ -z "$why" ] && ! diff -q <(json "$TMP/py.out") <(json "$TMP/go.out") >/dev/null; then
    why="stdout differs"
  fi
  # stderr carries the refusal text, which is the part an operator reads.
  if [ -z "$why" ] && ! diff -q "$TMP/py.err" "$TMP/go.err" >/dev/null; then
    why="stderr differs"
  fi

  if [ -z "$why" ]; then
    printf '  PASS  %-44s (exit %d)\n' "$name" "$pc"; pass=$((pass+1))
  else
    printf '  FAIL  %-44s %s\n' "$name" "$why"; fail=$((fail+1))
    diff <(json "$TMP/py.out") <(json "$TMP/go.out") | sed 's/^/          /' | head -20
    diff "$TMP/py.err" "$TMP/go.err"                 | sed 's/^/          /' | head -20
  fi
}

echo "comparing mailer.py against cti-mailer - nothing is sent"
echo

echo "sends (should both succeed):"
compare "a digest"            --html "$TMP/fixture.html" --subject "test" --dry-run
compare "a digest with Cc"    --html "$TMP/fixture.html" --subject "test" \
                              --cc "cc1@example.com" --dry-run
compare "a digest + attachment" --html "$TMP/fixture.html" --subject "test" \
                              --attach "$TMP/raw.md" --dry-run
compare "a missing attachment" --html "$TMP/fixture.html" --subject "test" \
                              --attach "$TMP/nope.md" --dry-run
compare "an escalation"       --to-operator --message "line one" \
                              --board-id q17 --subject "approve?" --dry-run
compare "escalation, 2 paras" --to-operator \
                              --message $'first para\n\nsecond para' \
                              --board-id q1 --subject "t" --dry-run
compare "a Sev5 subject"      --html "$TMP/fixture.html" \
                              --subject "[Sev5] urgent" --dry-run
compare "no subject given"    --html "$TMP/fixture.html" --dry-run
compare "--save-to-sent=false" --html "$TMP/fixture.html" --subject "t" \
                              --save-to-sent false --dry-run

echo
echo "refusals (should both refuse, identically):"
compare "a recipient nobody approved" --html "$TMP/fixture.html" --subject t \
                              --to "stranger@example.com" --dry-run
compare "a stranger on Cc"    --html "$TMP/fixture.html" --subject t \
                              --cc "stranger@example.com" --dry-run
compare "--require-approval, unapproved" --html "$TMP/fixture.html" --subject t \
                              --require-approval --dry-run
compare "both --html and --message" --html "$TMP/fixture.html" \
                              --message "x" --subject t --dry-run
compare "neither --html nor --message" --subject t --dry-run
compare "--to-operator with --to" --to-operator --to "a@example.com" \
                              --message x --subject t --dry-run
compare "a malformed address" --html "$TMP/fixture.html" --subject t \
                              --to "not-an-address" --dry-run
compare "a missing html file"  --html "$TMP/absent.html" --subject t --dry-run

echo
echo "approved exceptions (should both succeed):"
compare "a stranger, approved" --html "$TMP/fixture.html" --subject t \
                              --to "stranger@example.com" --approve --dry-run
compare "--require-approval + --approve" --html "$TMP/fixture.html" --subject t \
                              --require-approval --approve --dry-run

echo
echo "-------------------------------------------------------------"
printf "  %d passed, %d failed\n" "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  echo "  Do NOT switch the runners over."
  exit 1
fi
echo "  Behaviour matches. See RUNBOOK 11b for the switch."
