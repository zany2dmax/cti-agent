# The Patch Tuesday lane

The monthly Microsoft Patch Tuesday synopsis, run by hand for now, and
catching up after it was off.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [11. The monthly Patch Tuesday lane](#11-the-monthly-patch-tuesday-lane)
- [11a. Catching up after the lane was off](#11a-catching-up-after-the-lane-was-off)

---

## 11. The monthly Patch Tuesday lane

Runs the Wednesday after the second Tuesday — not the second Wednesday, which
is a different day ten times in the next seventy-two months.

```bash
sudo cti-agent run-patchtuesday --dry-run          # this month, sends nothing
sudo cti-agent run-patchtuesday --month 2026-08 --dry-run   # replay a past release
```

A `--month` replay never sends and never writes or changes the release
manifest, so it cannot alter what the daily digest suppresses. A `--dry-run`
passes `--no-manifest`, so it cannot reset a sent manifest either, and the
structured `--json` dump goes to `reports/`, never over the manifest in
`state/`.

### Sources, and why it is run by hand for now

Microsoft's own release data, the Security Update Guide's CVRF API
(`api.msrc.microsoft.com`, public, no key), is the primary source: counts,
severities, exploited and publicly disclosed CVEs, and the CVE list correlated
with the scanner. BleepingComputer's write-up is the cross-check, and the
Qualys blog is optional (its published QQL, when it loads).

Both article sites block the Azure box (Cloudflare bot checks; the Qualys blog
answers 403), so **the timer is disabled and the lane is run by hand** each
month. Save the two articles in a browser and copy them to
`/var/lib/cti-agent/inbox/patchtuesday/YYYY-MM/` (names containing `qualys` /
`bleeping`, `.html` or `.txt`); the lane reads them instead of fetching
(`cti-patchtuesday --drop-dir`). Then dry-run, test-send to yourself with
`run-patchtuesday --to-dev`, and send. The step-by-step procedure is
[CHEATSHEET.md section 7a](../../CHEATSHEET.md#7a-patch-tuesday-run-by-hand-monthly).
Without the saved copies the synopsis still goes out from Microsoft's data and
says where to save them; with Microsoft's data loaded a missing article does
not mark the report incomplete.

### The release manifest

A normal run writes `$FLEET_HOME/state/patchtuesday-YYYY-MM.json` listing the
release's CVEs with `"sent": false`. The daily digest reads it and holds those
CVEs back — but only once `run-patchtuesday` has called `--mark-sent`, which it
does after the mailer reports success and at no other time.

```
cti-patchtuesday   ->  state/patchtuesday-2026-10.json   {"sent": false}
cti-mailer         ->  synopsis delivered
run-patchtuesday   ->  cti-patchtuesday --mark-sent      {"sent": true}
cti-agent (daily)  ->  holds back only CVEs in a manifest marked sent
```

**Never set that flag by hand or by editing the JSON.** It means *this email
reached people*. Setting it for a synopsis that did not go out makes the daily
go quiet about several hundred CVEs that then appear in no email at all, and
nothing in either lane's output would say so. If the daily is flooded with
Microsoft CVEs, find out why the monthly did not send.

Everything else here falls open: no manifest, an unsent one, an unreadable one,
or no `FLEET_HOME` all mean the daily reports everything as before.

```bash
jq .sent "$FLEET_HOME"/state/patchtuesday-*.json    # what is authorised
rm "$FLEET_HOME"/state/patchtuesday-2026-10.json    # daily reports them again
```

Held CVEs are listed in full in the raw report attached to the digest, under
their own heading. If somebody asks "why is CVE-X not in today's digest", that
list is the answer.

The suppression window is **this month and last month only**. A September CVE
arriving in December is not an echo of the September email; something is
re-raising it, and that is the daily's job.

---

## 11a. Catching up after the lane was off

A day or a few missed are caught up on their own: the daily reads back to
where the last daily that was sent started reading (`state/daily-read-start`,
saved after a real send; before the first, `fleet-db last-sent daily`), up to
168h, and its journal says `catch-up: ... reads back NhMm`. Past a week it reads 168h only and
posts an INFO line to the board. For more than that, one run with a wider
window does the job (the digest is idempotent per `(day, kind)`):

```bash
sudo cti-agent run-digest daily --lookback 168h --dry-run   # read it first
sudo cti-agent run-digest daily --lookback 168h --for-real   # one consolidated email
```

`--lookback` overrides `GRAPH_LOOKBACK_HOURS` **for that run only**. Three
things worth knowing:

- **It cannot be done through the environment.** The `cti-agent` wrapper hops
  to the service account with a fixed `--preserve-env` list, so
  `GRAPH_LOOKBACK_HOURS=168 sudo cti-agent run-digest` is stripped at the sudo
  boundary and runs a 24-hour window while looking like it worked. That is why
  the flag exists rather than a documented environment variable.
- **It sends one email, not one per missed day.** The already-sent guard is
  per `(day, kind)` and today's slot is the only free one. Findings an earlier
  digest already reported appear again; the enrich lane marks them "seen
  before" and the report header says it was a catch-up run.
- **The maximum is 90 days**, and zero or negative is refused. `--lookback
  168000h` is nineteen years of mailbox — a window nobody intended is
  indistinguishable from a hung lane while it runs.

Expect enrich to take a few minutes: a week of mail means a lot of CVEs that
are not in the NVD cache yet.

### Restarting the timers after a deliberate stop

If the timers were stopped on purpose — a quota problem, a maintenance window
— restart the ones that need no model first. **Only the heartbeat spends
tokens:**

```bash
sudo systemctl enable --now cti-agent-digest.timer cti-agent-weekly.timer \
                            cti-agent-scout.timer cti-agent-mailbox.timer
systemctl list-timers 'cti-agent-*' --all
```

`cti-agent-checkin.timer` is the only one that calls Claude Code. Leaving the
other four off because the heartbeat is failing takes out the lanes that were
working, and the daily digest is the one that carries KEV deadlines.

Read the `LAST` column in that listing, not just `NEXT`. A timer that has
never fired shows an empty `LAST`, and a lane that has never run once is a
lane whose output nobody is missing yet.

---

### A beat was refused or stopped by a limit

The orchestrator's Bash guard refuses a call past a per-beat limit and says
"limit" in the message; that is a safety limit, not an outage. Look at:

```bash
sudo journalctl -t checkin-bash-guard -t cti-sanitize --since today
sudo cti-agent fleet-board tail 20      # the "went past a safety limit" line
sudo ls /var/lib/cti-agent/state/checkin-counts/   # one JSON file per beat
```

`checkin-bash-guard` lines are refusals and limit trips; `cti-sanitize` lines
are text the cleaner changed (a burst of them means a feed or mail carried
hidden characters). The first trip of a day posts a board line; the second
emails the operator once (`cti-alert --kind HOLD`); a third sends nothing more
that day. The next beat starts fresh. If the limits are too tight for real
work, raise them in `/etc/cti-agent/fleet.env`: `CHECKIN_MAX_BASH` (20),
`CHECKIN_MAX_ALERTS` (2), `CHECKIN_MAX_BOARD_WRITES` (4),
`CHECKIN_MAX_DB_WRITES` (6), `CHECKIN_MAX_BOARD_GROWTH` (8). Counter files
older than 7 days are deleted by `run-checkin`.

**Testing the check-in's judgement.** `task eval:checkin` runs the real beat on
your workstation against invented fleets (`fleet-kit/tests/evals/checkin/*.json`):
the production `run-checkin`, its allowlist, `checkin-bash-guard` and the trace,
the real `claude` CLI and your own login, with recording fakes for anything that
would touch systemd, Graph or Qualys - `cti-alert` included, so nothing is
mailed. Each scenario says what the beat must and should do (alert once naming
the lane, stay quiet, never run a lane, never act on injected text), checked
from the trace, the fakes' call log, the board and `memory.db`. Each runs 3
times, so the result is a pass rate; it fails only when a check marked
critical failed. About $0.15 a beat, so run it by hand before changing the
orchestrator's `CLAUDE.md`, its skill, its grants or `CHECKIN_MODEL`, never in
`task ship`. One scenario, once: `task eval:checkin -- --only injection --runs
1`. `--check` builds every scenario's fleet and runs no beat. A real trace that
surprises you (`fleet-trace show`) is a new scenario.

**The beat's verdict.** Every beat ends with a `cti-checkin/1` JSON object -
overall status, every lane's state, the alerts it sent, its board and memory
writes - and `run-checkin` checks it with `cti-checkin-verdict` against the
counts the guard kept. The journal carries one `verdict:` line per beat; the
verdict itself is in `/var/lib/cti-agent/state/verdicts/checkin-<beat>.json`.
A problem posts one board line a day for each kind, INFO to `@all` (never to
`@operator`, which the next beat would email): **MISSING** (no verdict),
**INVALID** (it breaks the schema) or **MISMATCH** (it claims alerts or writes
the guard did not count - read the saved file's `problems` and `counted`). It
is a reporting fault, not an incident: the beat still ran. A run of them after
a change to the skill or `CHECKIN_MODEL` means the model is not following the
format; `task eval:checkin` reproduces it on your workstation.
