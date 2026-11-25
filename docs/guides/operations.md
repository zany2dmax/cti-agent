# Operating the fleet

Day-to-day work on a running box: the mailer, Jira, versions, pausing a host,
the audit trail, checking a run, report sensitivity, the scanner cache, and
what to do when something breaks.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [11b. The mailer](#11b-the-mailer)
- [11c. Verifying the Jira connection](#11c-verifying-the-jira-connection)
- [11d. What version is this box running?](#11d-what-version-is-this-box-running)
- [11e. Taking a host off the schedule](#11e-taking-a-host-off-the-schedule)
- [11l. The audit trail](#11l-the-audit-trail)
- [12. Verifying a run](#12-verifying-a-run)
- [13. Report sensitivity](#13-report-sensitivity)
- [14. Scanner KB cache freshness](#14-scanner-kb-cache-freshness)
- [15. When something breaks](#15-when-something-breaks)

---

## 11b. The mailer

`cti-mailer` is the fleet's only mailer. It is the Go port of the old
`lanes/mailer.py`, and **since 1.6.6 every runner sends through it**. The
Python mailer was removed after 1.7.2, after dailies, weeklies and a Patch
Tuesday had all gone through `cti-mailer`. The installer deletes the old
`lanes/mailer.py` and its man page from the box on update, so `sudo cti-agent
mailer.py` no longer runs anything. A test (`EverySendGoesThroughCtiMailer`)
fails if the file or a runner calling it comes back.

There is no longer a one-line rollback. To go back to the Python mailer,
install 1.7.2 or earlier.

`run-checkin` and `run-mailbox-cleanup` do **not** call the mailer: they
escalate through `cti-alert`, which talks to `internal/graph` directly and has
its own recipient handling. (`cti-alert` bypassing `VM_ALLOW_TO` is a separate
known gap, recorded in SECURITY.md.)

### What the port changed on purpose

Nothing about who receives mail. A throttled send (429 or 503) is retried as
it was in `mailer.py`, up to three attempts, honouring `Retry-After`; unlike
`mailer.py`, a connection that drops mid-send is **not** retried, because the
POST may have been accepted and a retry would mail the team twice. Two things
are better by accident of the language:

- `fleet.env` is read through `internal/fleetenv`, which also handles
  `export KEY=value`. `mailer.py`'s own parser turned that into a variable
  named `export KEY`.
- Everything reaching the journal goes through `internal/safelog`, so a
  subject line cannot forge a log record.

And one thing is explicit rather than silent: `--text` is accepted and logged
as *not transmitted*. Graph sends one body, so `mailer.py` had always ignored
it — it just never said so.

---

## 11c. Verifying the Jira connection

Three steps, each of which can fail for a different reason, so they are run
separately rather than as one command.

### 1. Credentials, project and required fields - reads only

```bash
sudo cti-agent cti-jira --check
```

Reports the account the API token belongs to, whether the write gate is open,
whether `JIRA_ISSUE_TYPE` exists in the project, which fields the create screen
marks required, whether the duplicate-detection search works, and each Jira
permission the fleet uses as `ok` or `MISSING` (nothing is written).

That last one is not padding. A duplicate check runs before every create, so a
broken search breaks the whole lane — and it broke once already: Atlassian
removed `/rest/api/2/search` outright, and the first anyone knew was an HTTP
410 part-way through `--test-ticket --for-real`. A preflight that skips a path
the real run depends on is a preflight that lies.

Read two lines carefully:

- **the account name.** An API token carries every permission its account has.
  A token belonging to a person rather than a service account means tickets are
  attributed to somebody who did not file them, and the lane stops when they
  leave.
- **anything marked `<-`.** That is a required field `cti-jira` does not set,
  and every create will 400 until it is handled. On a Service Management
  project this is usually a request-type custom field.

If the issue type is wrong, the error names the valid ones:

```
JIRA_ISSUE_TYPE="Task" does not exist in this project; it offers:
  Ask a question, Emailed request, Hardware Return, Hardware / Software
  purchase request, IT Support, New-Hire IT Request, Off-Boarding
```

`Task` is the obvious guess and it does not exist in a JSM desk.

### 2. The ticket itself - still creates nothing

```bash
sudo cti-agent cti-jira --test-ticket --dry-run
```

Prints the summary, description, labels, duplicate-search JQL and the CSV as
one JSON object. Read the description as IT will read it. Nothing is written,
and the last line says so.

### 3. One real test ticket

```bash
sudo cti-agent cti-jira --test-ticket --for-real
```

Requires `JIRA_ALLOW_CREATE` to contain the project key. That gate covers
every write - tickets, comments, CSV attachments and the stored exposure
property - so with it empty the whole lane is read-only. Files one obviously
synthetic ticket — `CVE-1900-00000`, hosts under `.invalid` — titled so that
nobody mistakes it for a finding. Running it twice does not file a second: the
label-based duplicate check catches it.

**Then check by hand what the API cannot tell you:** does the ticket appear in
the queue your team actually works from? A JSM project can accept an issue over
the plain issue API and leave it out of the agent queues, and that is invisible
from the command's point of view. Close and delete the ticket when done.

### Using a scoped service-account token (optional)

A classic API token carries everything its account can do. A scoped token on a
service account is narrower, but Atlassian refuses it at the site URL, so set
`JIRA_CLOUD_ID` and the fleet calls the gateway
`https://api.atlassian.com/ex/jira/<cloud id>` instead (email links still use
`JIRA_BASE_URL`). Unset, nothing changes.

Setup:

1. Create a **service account** at admin.atlassian.com > Directory > Service
   accounts. Not the organisation Settings > API keys page: its `:admin`
   scopes administer the organisation and must not be used here.
2. Give it Jira product access on the **production** site (not a sandbox).
3. Add it to the project (Project settings > People/Access) in a role that can
   work issues, e.g. Member in a team-managed project. Owners named in
   `app-owners.txt` must be Assignable users in that project.
4. Put it in a group that is granted the global **Browse users and groups**.
5. Create its API token with exactly three classic scopes: `read:jira-work`,
   `write:jira-work`, `read:jira-user`. Tokens expire within 365 days: diary
   the renewal.
6. Find the cloud id (a UUID) at `https://<site>.atlassian.net/_edge/tenant_info`.

Switch: in `fleet.env` set `JIRA_EMAIL` to the service account's own address
(`...@serviceaccount.atlassian.com`, not a person's), `JIRA_API_TOKEN` to its
token, and `JIRA_CLOUD_ID=11111111-2222-3333-4444-555555555555` (your own
UUID). Then `sudo cti-agent cti-jira --check` (every permission should read
`ok`), a `--to-dev` run, then a real run.

Roll back: remove `JIRA_CLOUD_ID` and restore the old email and token.

Symptoms:

- HTTP 401 with `X-Failure-Category: FAILURE_CLIENT_AUTH`: wrong `JIRA_EMAIL`
  (it must be the service account's address).
- A JQL search returning `"issues":[]` for a key you know exists: the account
  cannot browse the project (BROWSE_PROJECTS `MISSING`).
- `USER_PICKER` `MISSING`: tickets are filed unassigned.

### The automatic path

Once configured, `run-digest` files tickets itself. The pipeline order is
`enrich -> cti-jira -> brief -> send`, and that position is the whole design:
after enrich because it needs the findings, before brief because the ticket
keys have to exist by the time the email is rendered.

**Every failure in that step is non-fatal.** This lane now sits between the
fleet and its daily security email, so a Jira outage, an expired token or a
project permission change costs tickets and nothing else. `cti-jira` exits 0
on its own internal failures and the runner adds `|| true` for the ones it
cannot catch.

`run-digest --dry-run` passes the dry run through: it reports what it *would*
file and writes nothing. A dry run that quietly filed real tickets would be
the September dropped-`--dry-run` incident again, with a longer cleanup.

What gets a ticket: a finding that is **KEV, Sev5, CVSS 9.0 or more, or QDS above 90** *and* **PRESENT** in the
estate. Not-present and unknown-coverage findings are skipped — a ticket for a
CVE the scanner cannot find carries no host list, which is the thing that makes
a ticket useless. A CVSS base score of 9.0 or more (CVSS's own Critical band)
files whether or not the CVE is on KEV: a CVSS 9.8 with low EPSS ranks Sev4
and would otherwise get a digest line and no ticket. Those tickets carry the
label `cvss-critical` and "CVSS 9.8" (the score) in the summary, and are
unassigned for triage. A Qualys Detection Score above 90 (91 and up) files the
same way, KEV or not: the scanner's own rating of the detection on our hosts.
The morning report's QDS picks the finding and the fresh lookup's QDS decides;
those tickets carry the label `qds-high`, "QDS 95" in the summary and a QDS row
in the body. A Sev5 that is not on KEV, below CVSS 9.0 and at QDS 90 or less is
reported but held for approval rather than filed.

**Patch Tuesday CVEs on KEV are always looked up.** Once a month's synopsis is
sent, the daily holds that release's Microsoft CVEs back (they are in the
monthly email), and a held CVE is not looked up, so it can never be ticketed.
CVEs on CISA KEV are the exception: they are reported, looked up and ticketed
every day, including one CISA adds to KEV after the synopsis went out. The KEV
list is the catalog `cti-enrich` keeps in `state/kev-cache.json`; if it cannot be
read, the daily holds as before and logs a WARNING. The Patch Tuesday lane
itself files no tickets.

Host names come from a fresh Qualys lookup, not from the enriched file — that
file carries only a ten-host sample. Only the selected CVEs are looked up, so
a normal day is a handful of Host Detection calls rather than one per finding.

The daily then quotes the key and links the ticket under each CVE, in both the
HTML and text parts, until the scanner stops finding it. Its **FLEET TICKETS**
section lists every ticket the follow-up re-checked - key and link, CVE, Jira
status, hosts the scanner sees today, and what the re-check did ("commented:
no detections remain", "no change - no comment", "not re-checked: the scanner
lookup failed") - with tickets closed in the last 30 days below, the
domains lane's lock-down ticket ([11g](../lanes/domains.md#3b-what-the-report-contains-and-the-lock-down-ticket))
and the VM scan lane's spreadsheet ticket. The weekly shows the same list from
the newest daily, headed "as the latest daily re-checked them". When the scanner
cannot be loaded nothing is re-checked, and the daily lists every ticket anyway,
headed "not re-checked against the scanner this run".

### Filing tickets for findings that are already outstanding

To ticket today's findings without waiting for tomorrow's digest, point the
lane at the enriched file the last run wrote:

```bash
ls -1 /var/lib/cti-agent/state/enriched-*.json | tail -1     # today's
sudo cti-agent cti-jira --from-enriched /var/lib/cti-agent/state/enriched-$(date +%F).json --dry-run
```

`--dry-run` reports what it would file and writes nothing. Use `--for-real`
instead once the list looks right.

**KEV, CVSS 9.0+ and QDS 91+ findings file automatically; a Sev5 that is none
of them is held.** The reason is that a KEV entry carries an external deadline and a
CVSS 9.0+ is critical by the standard's own measure (NVD's score, or the
CNA's when NVD has none), so delay is the larger risk,
whereas a Sev5 the fleet scored itself is a judgement call and
the larger risk is a scoring bug becoming a pile of tickets IT has to close.
To file the held ones deliberately:

```bash
sudo cti-agent cti-jira --from-enriched <file> --for-real --approve
```

`--approve` is a command-line flag and not a `fleet.env` setting on purpose:
`run-digest` never passes it, so the scheduled 06:00 run can only ever file
KEV, CVSS 9.0+ and QDS 91+ entries. Making it configuration would turn "the fleet decided to file
this" into something that happens overnight with nobody watching.

**A held CVE is named in the daily.** The digest carries a "HELD FOR APPROVAL"
section (HTML and text) listing each held CVE with its host count and the exact
`--approve` command for that day's file. No section means nothing was held.
Before this the only trace was one journal line
(`... held for approval (re-run with --approve to file it)`), so a Sev5
confirmed present and exploited could go unticketed without anyone knowing.
The list comes from the `held` array in the `-tickets.json` beside the enriched
file, which only a `--for-real` run writes. A CVE is listed every day until
someone approves it or the scanner stops finding it.

### What happens on the runs after the first

The ticket is found by its `cti-<cve>` label and **updated in place** — the
fleet never files a second ticket for a CVE it has already reported.

**Which tickets are re-checked: all of them, every morning.** `run-digest`
passes `--follow-up`, which searches Jira for the fleet's own tickets — the
`cti-agent` label, open or touched in the last 30 days — and asks the scanner
about each one whether or not its CVE is in that day's mail. Before this, a
ticket was only compared on a day its CVE happened to be back in the news, and
the "no detections left" comment below could never be sent: only PRESENT
findings reached the ticketing step, and a remediated CVE is not present.

Only a definite answer is compared. A lookup that failed, or a CVE the scanner
cannot map yet (`UNKNOWN`), leaves the ticket alone — a lookup that did not
answer is not a fix, and reading its zero hosts as "remediated" would tell IT a
live exposure was closed. The run logs one line:

```text
[cti-jira] follow-up: 15 fleet ticket(s) found, 11 re-checked, 2 already handled this run, 1 domains lock-down, 0 with no CVE label, 1 left alone because the scanner could not answer
```

To see what it would do without writing anything - one line per ticket,
saying whether IT would get a comment and why (`WOULD COMMENT: grew 300 -> 340
host(s)`, `WOULD COMMENT: no detections remain (was 12)`, `no change (220
host(s)) - no comment`):

```bash
sudo cti-agent cti-jira --from-enriched /var/lib/cti-agent/state/enriched-$(date +%F).json --follow-up --dry-run
```

What it says, and when:

Everything is compared with **what IT was last told** — the host list at the
time the ticket was filed or last commented on — not with yesterday's scan.

| Compared with the last report | Comment? |
|---|---|
| Nothing changed | No. A daily "still 441 hosts" is the storm in a different costume |
| A host missed one scan and came back | No. It was never gone from IT's point of view |
| Hosts only went away | No — they are listed the next time something else earns a comment |
| Hosts IT has not been told about | **Yes, at most once a week per ticket.** Hosts that appear in between are held and named together in the next comment, with a fresh dated CSV |
| A new QID | **Yes**, straight away |
| No detections left anywhere | **Yes**, straight away — "this ticket can be closed" |
| Back after "no detections left" | **Yes**, straight away — a regression is not held |
| Ticket is closed, detections persist | **Once, ever.** It is not reopened |

The weekly limit exists because the first daily dry run against real tickets
showed three of four would be commented on every morning, each for one host
swapped for another on a list of hundreds. A dry run shows a held change as
`N host(s) not yet reported - held for the weekly comment, due YYYY-MM-DD`.

That last row is deliberate. Somebody closed the ticket on purpose — an
exception, a compensating control, a replacement ticket — and software that
reverses a human decision every night is software that gets switched off.

The previous host and QID set is stored as a property **on the ticket**, not in
a file on this box, for the same reason the duplicate key is a label: a ticket
can be closed, cloned, moved or bulk-edited in the UI, and any local record
goes stale the moment somebody does. It also means a rebuilt fleet box does not
re-announce every host it has ever seen as newly discovered.

**The attached CSV always lists every affected host, at any scale.** A ticket
with no hostnames to work on is useless, so the attachment is never truncated.
Three different limits are at play and only one of them touches the host list
anybody works from:

| Limit | Value | What it affects |
|---|---|---|
| CSV attachment | **none** | the deliverable — every hostname, always |
| Hosts named in comment prose | 20 | readability; the rest are "…and N more, in the attached CSV" |
| Hosts remembered between runs | 800 | diff precision only, to stay inside Jira's 32KB property cap |

So above 800 hosts the comment says the count moved from 900 to 950 without
naming the 50, and states that it cannot name them — but the CSV attached to
that same comment has all 950 rows.

One consequence worth knowing: no new CSV is attached on a run with no material
change, so the newest attachment on a long-lived ticket can lag. That is safe in
one direction only, and deliberately so — growth is always material, so a fresh
CSV is always attached when hosts appear. The only way an attachment goes stale
is hosts going *away*, which makes the stale list a superset of reality. Working
it means patching a machine that is already clean: wasted effort, never a missed
host.

Note the flag direction. There is no `--dry-run`; the dangerous mode is the
one you have to ask for, because forgetting a `--dry-run` flag is how the
digest sent a real email to the whole distribution list in September.

---

## 11d. What version is this box running?

```bash
sudo cti-agent cti-mailer --check | head -2
sudo cat /etc/cti-agent/version
```

The first is what the binary says about itself; the second is what the last
install recorded. They should agree, and `--check` warns when they do not —
that means the binary was not replaced by the last install and predates
whatever else was, which is exactly what a partial install leaves behind.

`-DIRTY` means it was built from a working tree with uncommitted changes. That
is allowed, and sometimes the only way to test a fix on the box that has the
problem, but the build cannot be reproduced from its commit until it is rebuilt
from a clean tree.

An absent `/etc/cti-agent/version` means the box was installed before version
recording existed. Re-run the installer to create it.

See [CHANGELOG.md](../../CHANGELOG.md) for what each version requires of you.

---

## 11e. Taking a host off the schedule

```bash
sudo ./fleet-kit/stop-fedora.sh --status        # what is scheduled, changes nothing
sudo ./fleet-kit/stop-fedora.sh                 # stop and disable every timer
sudo ./fleet-kit/stop-fedora.sh --resume        # put it back
```

Nothing is removed: config, state, the seen-CVE database and the Jira ticket
map all survive, so a resume is a resume rather than a re-onboarding. Use
`install-fedora.sh --uninstall --for-real` when you actually want the units gone.

### Two hosts against one mailbox

This is the case the script exists for, and it is worse than duplicate email.
The cleanup lane archives advisories once a *completed run* has read them — so
a run on host A archives mail that host B has not ingested yet, and B then
reports a quiet day it did not have. That collision has already cost three
advisories here, with no error logged anywhere. It was caught only because a
person recognised two senders that should have been in the digest.

So the order is not negotiable. Cutting over from the test host to a new
production host:

1. **On the OUTGOING host**, before the new one is enabled:

   ```bash
   sudo ./fleet-kit/stop-fedora.sh --decommission
   ```

   It waits for any lane mid-run, then stops, disables and masks every timer,
   and exits non-zero if anything is still scheduled. Do not continue until it
   exits 0.

2. **Confirm it, from the outgoing host:**

   ```bash
   sudo ./fleet-kit/stop-fedora.sh --status
   sudo crontab -l 2>/dev/null | grep -i cti || echo "no root crontab entries"
   ```

   The script only knows about systemd. A leftover cron entry would keep this
   host live against the shared mailbox and is invisible to it.

3. **Then** install and enable on the new host, following
   [section 9](setup.md#9-enabling-the-timers-in-order) as if it were a first install.
   The seen-CVE database and ticket map do not transfer; the new host will
   re-discover state from the mailbox and from Jira labels, which is why
   ticketing is keyed on a label rather than a local database.

4. Leave the old host decommissioned for a week before uninstalling it. If the
   new host has a problem, `--resume` is one command and the config is still
   there.

`--decommission` masks the timers, so `systemctl enable --now` refuses until
somebody deliberately unmasks them. That is the point: a test box must not
quietly start sending again alongside production after a reboot or a
re-install.

### What it will not do

It waits up to two minutes for a lane that is mid-run rather than killing it. A
digest interrupted between "Graph accepted the send" and "the ledger recorded
it" leaves no record of a mail that went out, and the duplicate-send guard
cannot then stop the next run sending it again. `--force` overrides the wait;
if you use it, check what the ledger knows:

```bash
sudo cti-agent fleet-db recent
```

It also cannot see anything that is not a systemd timer. A leftover cron entry
would keep the host live against the shared mailbox and is invisible to this
script, so it prints the commands to check that yourself.

Every run verifies the result rather than announcing it, and exits non-zero if
any timer is still active or still enabled. A stop that quietly did nothing is
the failure that matters here — you would believe the host was off while it
kept archiving a mailbox the new host is reading.

---

## 11l. The audit trail

Every mail sent or moved, every Jira write and every change to the application
owners leaves one syslog line in `/var/log/cti-agent/`, one file per UTC day.
What is logged, and the limits of the trail, are in
[SECURITY.md](../../SECURITY.md#the-audit-trail). Nothing needs setting up for the
files; the installer creates the directory and systemd creates it for each unit
that changes something.

**Look at it.**

```bash
ls -l /var/log/cti-agent
sudo tail -f /var/log/cti-agent/audit-$(date -u +%F).log
sudo grep ' mail.send ' /var/log/cti-agent/audit-*.log          # one action
sudo grep 'run="<invocation-id>"' /var/log/cti-agent/audit-*.log  # one unit run
```

The message id (after the process id) is the action, and `run` is the unit's
invocation id, so every line one run wrote shares it.

**Check it.**

```bash
sudo cti-agent cti-audit --check
```

It reports whether the directory is writable and, when forwarding is set,
whether the collector answers. It exits 1 if either fails. If it says the
directory is not writable, make it:

```bash
sudo install -d -m 0750 -o ctiagent -g ctiagent /var/log/cti-agent
```

While the directory is unwritable no lane stops: the events go to the journal
with one warning per run.

**Ship it to a SIEM.** Nothing is bundled; this only sends the lines on. In
`/etc/cti-agent/fleet.env`:

```
AUDIT_SYSLOG_ADDR=siem.example.com:6514
AUDIT_SYSLOG_PROTO=tls
```

then `sudo cti-agent cti-audit --check`. `tls` is the default and verifies the
certificate and host name. `tcp` and `udp` are unencrypted: they have to be named and are refused unless
the collector is on this host (a local rsyslog that forwards onward over TLS).
Forwarding is in addition to the file. A dead or hung collector costs one
2-second timeout and one warning, then forwarding stays quiet for 30 seconds
(the file still has every event) and the next event tries again; the recovery
is reported once. `AUDIT_DIR=off` is refused inside a systemd unit. Without any setting, you can instead point a collector's file reader at
`/var/log/cti-agent/audit-*.log`.

**Retention.** The daily mailbox cleanup lane prunes first, before it touches
mail: `cti-audit --prune --days $AUDIT_RETAIN_DAYS`, default 120. It deletes
only `audit-YYYY-MM-DD.log` files older than that. To change it, set
`AUDIT_RETAIN_DAYS` in `fleet.env`. A value that is not a number, or is zero,
falls back to 120 with a board WARN. A prune failure is a board WARN and never
fails the unit. To see what it would delete:

```bash
sudo cti-agent cti-audit --prune --days 120 --dry-run
```

The installer's `--purge` leaves `/var/log/cti-agent` in place.

**The heartbeat and scout write to the journal, not the files.** They have no
write access to the directory on purpose (see SECURITY.md), so their events
fall back to the journal:

```bash
sudo journalctl -u cti-agent-checkin --since today | grep audit@32473
```

---

## 12. Verifying a run

A lane that exits 0 is not the same as a lane that did something. These are the
checks worth making after any deploy:

```bash
# The digest ran, wrote the processed-message log, and found something
sudo journalctl -u cti-agent-digest --since today \
  | grep -E "brief\] wrote|recorded|distinct CVE"

# The cleanup plan, and whether the archive list is only CTI mail
sudo cti-agent cti-mailbox --dry-run

# Would the heartbeat start? Integrity and steering checks, no beat
sudo cti-agent run-checkin --audit

# The heartbeat's quota position, if it is skipping beats
sudo cti-agent cti-budget status

# Every timer, including the disabled ones
systemctl list-timers 'cti-agent-*' --all
```

| What you see | What it means |
|---|---|
| `recorded N message(s) in …` | the processed-message log was written; cleanup has something to work from |
| `distinct CVE(s)` but no `recorded` line | the digest ran but could not write the log — cleanup will refuse every day and look healthy |
| `NOTE: neither FLEET_PROCESSED_LOG nor FLEET_HOME is set` | the same, with the cause named |
| `The digest has read no mail today` | either an empty mailbox, or the above. The three commands distinguish them (older builds said `No CTI email has been processed today`, and said it on every day without a CVE) |
| `severity bands for 0 of N` | an old build. That column no longer exists |

---

## 13. Report sensitivity

A CTI report pairs "this CVE is exploitable" with "these are the machines that
have it." That is a targeting list if it leaks.

The default is nonetheless `full`, because the alternative is worse in
practice: a pseudonym cannot be looked up in the scanner, so a redacted report
tells you a Sev5 exists without telling you where, and you have to rerun the
pipeline to act on it. An unactionable security report is not a safe security
report.

What keeps that defensible is everything around it — reports are written
`0600`, excluded by `.gitignore`, and mailed only to an allowlisted internal
distribution list. Switch to `redact` or `count` for any copy leaving that path.

| `REPORT_HOSTNAMES` | Output |
|---|---|
| `redact` | Stable pseudonyms — `host-3797a22b`. The same machine keeps the same label across reports, so remediation can be tracked without naming it. **Not reversible**: there is no lookup table |
| `count` | Host count only, names withheld entirely |
| `full` *(default)* | Real hostnames. The report carries a "do not commit" banner |

Set `REPORT_REDACTION_SALT` to a private, stable value. Pseudonyms are
deterministic, so without a salt anyone holding a list of candidate hostnames
can confirm matches by hashing them.

Do not commit generated reports, attach them to tickets, or paste them into
chat tools. `scripts/scrub-history.sh` exists because this rule is easier to
break than it looks.

---

## 14. Scanner KB cache freshness

The Qualys provider maps CVE→QID from a local cache of the KnowledgeBase, which
expires after `QUALYS_KB_MAX_AGE_HOURS` (default 168 = 7 days), after which the
agent tops it up incrementally and falls back to a full rebuild.

This matters more than it sounds. A cache older than a CVE has no mapping for
it, so the CVE reports `UNKNOWN` — which reads as "not affected" when it
actually means "never checked". If a refresh fails the run continues, but every
`UNKNOWN` then says **"coverage UNVERIFIED, not confirmed absent"** rather than
"no mapping found". Those are different facts and the report distinguishes
them.

To force a rebuild, delete the cache file and rerun. The first build is a large
download and takes a few minutes.

### The API version, and the guard around it

The KnowledgeBase calls use `/api/4.0/`. The `/api/2.0/` path reached
End-of-Service in September 2026 with EOL 91 days out; Host Detection was
already on 4.0. The response shape is unchanged, per the release notes.

A rebuild is now refused if it returns no mappings, or fewer than half of
what is already cached — the old cache is kept and marked stale instead.
That guard exists because `parseKB` binds to XML element names and **Go's
decoder returns an empty result and a nil error** for a document it cannot
match. A renamed schema would therefore produce a successful-looking rebuild
of nothing, overwrite a 160,000-CVE cache, and make every CVE report "no
mapping" rather than "coverage unverified" — wrong, and reassuring.

If you see `Qualys KB rebuild REJECTED`, the two counts in the message
distinguish the two causes: a schema change gives 0, while a credential that
lost entitlement to part of the KnowledgeBase gives a real but shrunken
number.

### `CODE 1960`: the concurrency limit

```
This API cannot be run again until 1 currently running instance has finished.
```

Qualys allows one KnowledgeBase call at a time per subscription. Another job —
or an abandoned call from an earlier run — is holding the slot. It clears on
its own; the lane falls back to the stale cache and says so. If it persists,
something else in the estate is using the same API account.

---

## 15. When something breaks

The symptom-to-cause table lives in
[fleet-kit/README.md → Troubleshooting](../../fleet-kit/README.md#troubleshooting).
It covers Graph 403s, SELinux labels, stale locks, quota holds, dead feeds,
missing environment variables and the mailbox lane.

Two that catch everyone:

**Works by hand, every timer fails.** Not permissions — SELinux. A `fleet.env`
staged in a home directory and moved into `/etc` keeps its original label,
`init_t` cannot read it, and the unit fails before `ExecStart` with an empty
journal. `sudo restorecon -RFv /etc/cti-agent /opt/cti-agent /var/lib/cti-agent`.

**A lane that reports success while doing nothing.** The recurring failure in
this system is not a crash; it is a check that ran and had no effect, or a
refusal that looks exactly like a quiet day. When output looks *too* clean,
verify the lane did work rather than that it exited 0 — [section
12](#12-verifying-a-run) is the short list.
