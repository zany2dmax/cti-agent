# The mailbox cleanup lane

Rolling out mailbox cleanup safely: dry runs first, then the timer.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [10. Rolling out mailbox cleanup](#10-rolling-out-mailbox-cleanup)

---

## 10. Rolling out mailbox cleanup

This is the only thing in the fleet that modifies the mailbox, on a timer, with
nobody watching. Treat the rollout accordingly.

1. **Grant `Mail.ReadWrite`** and confirm it with `cti-mailer --check`. Without
   it the lane can read and plan but every move fails.
2. **Dry run, by hand, for several days:**
   ```bash
   sudo cti-agent cti-mailbox --dry-run
   ```
   `--dry-run` is how every lane is rehearsed, and this one moves mail without
   it (it used to be the reverse, `--for-real`, which is still accepted and
   ignored).
3. **Read the archive list every time.** It should contain nothing but CTI
   advisories. If a colleague's phishing report, a Defender alert or an
   ordinary email from a person appears there, stop and work out why — that is
   the failure this lane is most able to cause.
4. **Then enable the timer.** The unit passes `--for-real` explicitly, so the
   decision to modify mail is visible in the unit file rather than buried in a
   default.

### What may move, and nothing else

| Message | Action |
|---|---|
| The fleet's own report, delivered back to the mailbox, with a correctly **signed** `X-CTI-Agent-Sent` header | **Archive**, once a week old (`MAILBOX_SELF_MIN_AGE_HOURS`, default 168; a copy is in Sent Items) |
| A quarantine digest ("End User Digest") from `MAILBOX_DIGEST_SENDERS`, whoever it is addressed to, holding nothing from Qualys or `MAILBOX_FEED_SENDERS` | **Deleted Items**, on sight |
| The same digest holding mail from Qualys or a feed sender | **Left** a week; the operator is alerted to release the held mail (the fleet never does) |
| An automatic reply - by its headers, or a subject starting `Automatic reply:`, `Out of Office:` and the like - read by a lane or not | **Deleted Items** (recoverable) |
| The digest read it and took a CVE from it | **Archive**, after the grace |
| A Qualys WAS scan notice whose application's owners were sent its report (recorded by `run-appowners` after a real send), or that the AppSec weekly reported on | **Archive**, after the grace |
| A Qualys VM "Scan Results" notice the VM scan weekly combined and sent | **Archive**, after the grace |
| A supplier request the supplier lane judged not critical, or critical or unsure with its Kanban item filed (recorded after every real run in `state/processed-supplier.json`) | **Archive**, after the grace. A thread set aside as not a supplier request, one whose item failed to file, and a reply newer than the judgement are **left** |
| A companion notice of a run one of those weeklies reported as complete - WAS "Scheduled ... Scan Notification", VM "Scan Completed" and "Completed Vulnerability Scan Notification" - from Qualys and matched to that run | **Deleted Items**, after the grace |
| Everything else, under `MAILBOX_STALE_DAYS` (30) old | **Left alone** |
| Anything older than `MAILBOX_STALE_DAYS` that is still in the inbox, unless a person flagged it | **Moved to `Inbox/Unhandled`** (`MAILBOX_STALE_FOLDER`), at most `MAILBOX_STALE_MAX` (200) a run |

**The 30-day sweep.** The daily plan only sees the last 14 days
(`MAILBOX_LOOKBACK_HOURS`), and the records that let a lane vouch for a message
expire after 14 days too. Before the sweep, anything still in the inbox at two
weeks stayed there for good. Now mail past `MAILBOX_STALE_DAYS` goes to the
`Unhandled` folder under the inbox, by age alone, with no judgement of what it is:
not Archive, because no lane handled it, and never Deleted Items. A flagged
message stays. The first real run creates the folder; a first run against a deep
inbox moves 200 a day until it catches up. `MAILBOX_STALE_DAYS=0` turns it off.
Look in `Unhandled` now and then: it is where a reported phish nobody answered
ends up.

**What is left, said once a week.** Every run prints a `LEFT:` line (what stayed,
by reason) and a `STALE:` line (what was swept). Once a week the runner posts
the week's totals to the board as `mailbox week: ...`. If mail **no lane has
read** has been in the inbox over a week, a `NEVER-READ:` line goes on the board
every day and to you by `cti-alert` once a week: the digest reads every message
within a day, so that means it has stopped reading the mailbox, or the mail
arrived outside its window.

**Qualys WAS results notices wait for the weekly.** `run-appowners` records only
the companion notices (the scheduled-scan notice) of each scan it mailed to the
owners, and the cleanup deletes those after its 48-hour grace. A scan's results
notice is the AppSec weekly's only source of counts, so it stays in the inbox
until the weekly has read it, then goes after the usual grace. (For a few days
the owners lane released them early, and the weekly had counts for 1 of 13
applications.)

On a day the digest read no mail (out-of-office replies do not count) nothing
is archived, but auto-replies still go, and the sweep still runs. For a one-off sweep of old auto-replies:
`sudo cti-agent cti-mailbox --lookback 720h --timeout 10m --dry-run`, then run it
again without `--dry-run`.

A shared security mailbox receives reported phishing, alerts, scan
notifications and ordinary mail from colleagues. "The agent read it looking for
CVEs and found none" is not "this has been dealt with", and only the first of
those is what the processed-message log records. Rule 4 used to be archive, and
the first production dry run proposed filing away a message whose entire
subject was `suspicious`.

Auto-reply detection is **headers, or a subject prefix** (since 1.3.2) —
`Auto-Submitted: auto-replied` or `auto-notified`, or a subject that
*starts* `Automatic reply:`, `Out of Office:`, `Autoreply:` and similar. Anyone can
title a message that way, so a subject-only match the digest took a CVE from
is archived instead of deleted; Deleted Items is recoverable either way.

The self-sent header carries an HMAC keyed from the app's client secret, so a
sender cannot get a message archived by adding the header. Fleet mail sent
before 1.3, or before a client-secret rotation, fails the check and is left
for a human.

### The two leave counts

```
archive 3   delete 2   leave 5 (0 never read, 5 not CTI mail)
```

Only the first number can indicate a fault. Mail the agent read and left alone
is a security team's ordinary inbox; mail it **never read** piling up is what
"the digest succeeds every morning and reads nothing" looks like from outside.
The backlog alarm fires on that count only.
