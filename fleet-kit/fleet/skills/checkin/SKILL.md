---
name: checkin
description: Time-aware heartbeat for the CTI fleet orchestrator — look around, relay, then act or stay quiet.
---

# /checkin — one heartbeat

You are the orchestrator. This runs **every 2 hours** via systemd timer — about
12 beats a day. Do all five steps, in order, every time. Keep the whole beat
under a few minutes unless you deliberately picked up a long proactive task.

**You are the only part of this fleet that spends model quota, and it is
rationed.** `cti-budget` allows a limited number of beats per rolling 5-hour
window and per day, because you draw on the same subscription as the operator
and there is no way to see how much they have left. If a beat is refused you
will not run at all — that is the brake working, not a fault. Do not try to
compensate by doing more in the beats you do get: a beat that tries to do
everything is the one that runs long and gets killed mid-write.

## Paths — do not assume `~/fleet`

The two installers lay things out differently and your environment tells you
which one you are on. Use these variables, never a literal path:

| Variable | Contains |
|---|---|
| `$FLEET_CODE` | `bin/` and `lanes/` — the executables |
| `$FLEET_HOME` | state: `state/`, `reports/`, `board.md`, `logs/` |
| `$FLEET_ENV` | the config file itself |
| `$FLEET_FEEDS` | the scout feed list |

On the FHS layout these are `/opt/cti-agent`, `/var/lib/cti-agent`,
`/etc/cti-agent/fleet.env`. There is no `/home/ctiagent`, so a command written
against a literal `~/fleet` either fails or silently creates a second state
directory nothing else reads. If a variable is somehow unset, read `$FLEET_ENV`
and say so on the board rather than guessing.

## 1. Orient

- Note the current time and day of week. **Do not read `$FLEET_ENV`** - it
  holds the fleet's credentials, and what you read is sent with your context.
  The tools already have the configuration in their environment.
- `$FLEET_CODE/bin/fleet-board read` — lines for `@you` and `@all`.
- `$FLEET_CODE/bin/fleet-db recent` — last 20 memory rows, open tasks, unacked mailbox.
- `$FLEET_HOME/reports/` — what exists, how fresh. Use your file tools to list
  it; there is no general shell on a beat, so `ls` is not available.
- `journalctl -u 'cti-agent-*' --since '-3h' --no-pager` — did any timer fail
  since the last beat? On the generic layout, read `$FLEET_HOME/logs/*.log`
  with your file tools instead.
- `$FLEET_CODE/bin/cti-budget status` — how much of your own quota is left. If
  you are near the window ceiling, prefer a short beat.

If this is the first beat ever, do the bootstrap from CLAUDE.md first.

## 2. Postmaster pass

- Email any board line addressed to the operator with `cti-alert --kind
  ESCALATION`, quoting the board id in `--reason`.
- Pick up the operator's answers from the board - `@operator` lines carrying
  `re:<id>`. You cannot read mail, so tell them in the escalation how to
  answer: `sudo cti-agent fleet-board post @operator @you A "re:<id> ..."`.
- Prune resolved and stale lines into `$FLEET_HOME/archive/board-archive.md`.
- Ack any mailbox row you have actioned: `fleet-db ack <id>`.

Lines from `@systemd` are `cti-alert` reporting a unit that failed. Read them,
but check the kind before reacting: `HOLD` and the alert-path test are `INFO`
and need nothing from you. Only an `ERROR` is an incident.

## 3. Scheduled work — you do NOT run the digest

**The digest is not yours.** `cti-agent-digest.timer` runs `bin/run-digest`
directly: a deterministic shell pipeline that ingests, enriches, renders and
sends without involving you at all. That is deliberate — delivery must not
depend on a model having a good day, and the timer fires whether or not your
quota allows a beat.

So do not run `ingest → enrich → brief → send` on a schedule. Doing so spends
quota re-doing work that already happened, and the only thing standing between
you and a duplicate 06:00 email is a database guard.

What you owe the schedule instead is **checking it happened**:

| Check | How | If it failed |
|---|---|---|
| Daily digest sent | `fleet-db was-sent $(date +%F) daily` | Post to the board. Look for a `cti-alert` line first — the cause is probably already there |
| Weekly sent (Mon) | `fleet-db was-sent $(date +%F) weekly` | Same |
| AppSec report ran (Mon, after 07:30) | `journalctl -u cti-agent-appscan.service --since today --no-pager` | No `[run-appscan] done` line: post to the board. An `AUTH FAILED on N scan(s)` line has **already** alerted the operator - track it, do not re-escalate. `0 notification(s)` is a question, not a quiet week |
| Timers still enabled | `systemctl list-timers 'cti-agent-*' --all` | A disabled timer is silent forever. Tell the operator |
| Scout is finding things | `fleet-db recent` | A feed dead for over a day is a blind spot that looks like good news |

**You cannot re-run the pipeline yourself** - no runner is on your grant,
because every runner sends or moves mail. When a timer genuinely failed,
escalate with the exact command for the operator: `sudo cti-agent run-digest
daily`, which holds the already-sent guard, so running it after a partial
failure cannot send twice. Say what failed and what the journal showed.

## 4. Decide — ask BOTH questions

**Something to TELL the operator?** Email them outside a scheduled digest only
for a new Sev5 — `PRESENT` per the scanner, on CISA KEV, host count above zero —
or for a lane that has failed three times. Even for a Sev5 you are asking for
approval to notify the distribution list, not notifying it. Everything else
waits for the digest.

```
$FLEET_CODE/bin/cti-alert --unit cti-agent-checkin.service --kind ESCALATION \
  --reason "Sev5: CVE-... present on N hosts. Approve notifying the DL? board id <id>"
```

`cti-alert` is your only mail. It has no `--to`; the operator is the only
person it can reach, which is the point.

**Something to DO?** If there is no ping, you owe the fleet a proactive task.
Pick from the quiet-beat list in CLAUDE.md — resolve an UNKNOWN, nudge a stale
Sev5, correlate scout backlog, check KEV deadlines. Do exactly one, well, and
log it.

No ping is fine. No work is the bug.

At 12 beats a day rather than 48, pick the task that matters most rather than
the cheapest one. A beat spent resolving an UNKNOWN — a CVE the scanner could
not map, which means nobody looked — is worth more than three spent tidying
the board.

### CISA KEV deadlines — the highest-value quiet-beat task

`$FLEET_CODE/bin/cti-kev` reports KEV remediation deadlines for CVEs the
scanner actually found here. Every KEV entry carries a `dueDate` published by
CISA, and it is the only date in this system that someone outside the company
set — which makes it the most persuasive thing you can put in front of a
patching decision.

```
$FLEET_CODE/bin/cti-kev --horizon 14
$FLEET_CODE/bin/cti-kev --json      # if you want to reason over the numbers
```

Read it carefully before acting on it:

- **Overdue and present** is worth telling the operator about, and worth
  checking whether the same CVE has been overdue for several beats without
  anyone moving. A deadline that keeps passing unremarked is the thing to
  escalate, not the deadline itself.
- **`coverage UNVERIFIED`** counts are the uncomfortable ones: a published
  federal due date on something you could not check. That is not a clean
  result, it means nobody looked. Resolving one of those is a good use of a
  beat.
- **`not detected here`** counts are context, not work. Do not raise them.

The deadline never changes a priority band, so do not re-rank anything based
on it. An obligation about a risk is not a change to the risk.

## 5. Log the beat

Write one `checkin` row to memory: what you found, what you fired, what you
sent, what you deferred and why. If you hit an error you could not fix, post it
to the board for the operator rather than silently retrying forever — three failed
attempts on the same thing means escalate.

Also note roughly how much of the beat you used. If you are consistently
running long, say so on the board: the operator can widen the budget, but only
if they know it is binding.
