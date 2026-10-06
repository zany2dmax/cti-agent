# Changelog

## How this is versioned

Not SemVer. This is an internal tool with one operator, not a library with API
consumers, so "breaking change" in the SemVer sense means very little here.

The version answers a different question — **does upgrading require you to do
something?**

| Bump | Means | What you do |
|---|---|---|
| Patch — `1.0.1` | Fixes. Behaviour you already relied on now works | Pull, reinstall |
| Minor — `1.1` | New lanes, new output. Nothing existing changes meaning | Pull, reinstall. Read the entry in case a new feature wants configuring |
| Major — `2.0` | **The fleet will not work correctly until you act** | Read the entry first. New credentials, new permissions, a manual migration |

Every entry below ends with **Upgrade** saying exactly that. If it says
"nothing", there is nothing.

### Finding out what is deployed

```bash
sudo cti-agent cti-mailer --check | head -2     # what the binary says it is
sudo cat /etc/cti-agent/version                 # what the last install recorded
```

They should agree. If `--check` warns that they disagree, that binary was not
replaced by the last install and predates whatever else was — which is what a
partial install leaves behind.

A build from a working tree with uncommitted changes reports `-DIRTY`. That is
allowed, and sometimes necessary to test a fix on the box that has the problem,
but such a build cannot be reproduced from its commit, so "production matches
the tag" stops being a true statement until it is rebuilt from a clean tree.

---

## Unreleased

### Fixed

- **The orchestrator's grant allowed what its prompt forbade.** `fleet-db:*`
  let a beat record a digest as sent (so `run-digest` would skip the real one)
  and rewrite stored findings; `cti-patchtuesday:*` let it mark a Patch Tuesday
  manifest sent, which makes the daily drop the release's CVEs. The grant is
  now per subcommand, and `cti-patchtuesday` refuses `--mark-sent` with
  `--dry-run` - previously the combination marked the manifest sent despite
  `--dry-run` promising to write nothing.
- **The orchestrator's prompt described a capability it did not have.** It
  said it could "run any lane", recover with `run-digest`, escalate through
  `mailer.py`, check timers with `systemctl`, and read replies from the
  mailbox. None was granted; on an unattended beat a denied command just does
  not happen. The prompt and the `/checkin` skill now say exactly what a beat
  can run, re-runs are escalated as `sudo cti-agent ...` commands for the
  operator, and answers come back on the board. `systemctl list-timers` is
  now granted - read-only, and the only way a beat can see a disabled timer.
- **The prompt told the agent to read `fleet.env`.** It holds the Graph secret,
  the Qualys password and a Claude token, and what the model reads is sent
  with its context. It now says never to.

### Upgrade

Reinstall. Nothing to configure. The three operator playbooks
(`/cti-digest`, `/patch-tuesday`, `/scout-sweep`) are unchanged in content and
now say they are for a session with you present.

---

## 1.1 — 2026-10-06

### Added

- **A weekly application-security lane.** `cti-appscan` +
  `cti-agent-appscan.timer`, Mondays 07:30. It reads the DAST scanner's own
  scan-completion emails out of the CTI mailbox, optionally pulls per-finding
  detail from the Qualys WAS Findings API, and mails the result to the people
  who own application code.

  `internal/appscan` is a provider boundary, the way `internal/vulnlookup` is
  for host VM. A new scanner needs `Name`, `Recognises(sender, subject)` and
  `Parse(body)` — **no credentials**, so Invicti or Wiz becomes useful the day
  its email arrives rather than the day somebody negotiates API access. An API
  is an optional second interface, `DetailFetcher`; losing it costs
  per-finding detail and not the report.

  The lane reports the Qualys **Active** counts, never the lifecycle totals.
  The two differ by an order of magnitude on a real application — one carries
  270 "Urgent" on record of which 247 are already fixed — and leading with the
  lifecycle number would be a false alarm twelve times too large.

- **Per-lane recipient allowlists, fail-closed.** `cti-mailer --lane was`
  resolves `WAS_TO` against `WAS_ALLOW_TO` and **refuses if either is unset**,
  naming the variable that is missing. There is no fallback to the digest
  audience, and `--approve` does not override an empty list. An allowlist may
  reference another by name — `PT_ALLOW_TO=$VM_ALLOW_TO,extra@example.com` —
  with cycles caught and a depth limit; a wildcard reference (`$*_ALLOW_TO`)
  is refused by name rather than resolved to something surprising.

### Fixed

- **An unauthenticated scan was being reported as a coverage gap.** It is not
  one. The first real send of this report put three applications under a
  heading reading `COVERAGE GAPS`; all three are public sites with **no login
  at all**, so there is no missing authentication record, nothing to configure
  and nothing for the audience of that mail to do. The lane was filing a
  defect against three applications for being public.

  Authentication is now two separate things. A **label** — every count in the
  report says whether an authenticated or an unauthenticated scan produced it,
  because a zero from a scan that never logged in is not the same number, and
  that caveat is the part of the old design worth keeping. And a **fault**,
  but only when a credential *was* configured and *failed*: then the scan
  covered the public surface while still looking configured in Qualys, and
  this week's counts are not comparable with last week's.

  `Auth.Blind()` is gone, replaced by `Configured()`, `Authenticated()`,
  `Failed()` and `Label()`. `ScanResult.Attention()` no longer fires merely
  because a scan did not authenticate — it used to sort three public sites to
  the top of the report every week with nothing actionable in them, and a
  permanent alarm is read as no alarm.

- **A failed login no longer alerts the wrong people — or nobody.** An
  authentication failure now emails the fleet operator through `cti-alert`
  (kind `HOLD`), because the App Dev audience cannot fix a scanner credential.
  `cti-appscan --auth-fail-out` writes the finding to a file and the runner
  decides what to do with it: this binary does not send mail and must not
  learn how, since `cti-mailer` holds the only recipient gate in the fleet.
  The file is written on **every** run — empty means "checked, none failed",
  absent means an older binary that never checked, and the runner says which.

- **A broken login stopped erasing the open backlog.** Found by rendering it:
  the report partitioned "faulted" and "counted" scans as mutually exclusive,
  so the week an application's login failed it dropped out of `OPEN NOW`
  entirely and the severity tiles went to zero with it. An application with 23
  Urgent findings open does not become clean because the scanner had a bad
  password. The two sets now overlap; only an *incomplete* scan has no numbers
  to print.

- **`run-appscan` did not source `fleet.env`.** Every other runner does, and
  this one did not, so `cti-appscan` ran with no credentials at all and
  reported `missing required environment variables: CLIENT_ID CLIENT_SECRET
  GRAPH_MAILBOX TENANT_ID` on a box where all four are set. The error was
  accurate and pointed at the wrong thing. A lane test now asserts that every
  runner reads the config file, because four of the five followed an unwritten
  convention and the fifth did not.

- **`cti-appscan` did not load `fleet.env` itself.** The runner fix above made
  the timer work and left the hand-run broken: `sudo cti-agent cti-appscan
  --since 336h` still reported the same missing variables, because the binary
  never opened the file - only its runner did. Every other command that reads
  credentials calls `fleetenv.Load()`; a lane test now fails one that does not.

- **The AppSec unit logged as the weekly digest.** It was generated from the
  weekly's unit and kept `SyslogIdentifier=cti-agent-weekly`, so its lines -
  including `AUTH FAILED` - read as the digest's, and `journalctl -t
  cti-agent-appscan` returned nothing. A lane test now checks every unit logs
  under its own name.

- **Per-finding detail was empty for nearly every application.** The finding
  search was keyed on `webApp.name`, and the name it was given came from the
  scan title ("Example Run #47" -> "Example"), which on the real estate matched
  the scanner's application name in almost no scan. The search returned zero
  findings without error and the report said "detail not available". It is
  now keyed on `webApp.id` from the scan list, asks for vulnerabilities only,
  marks unconfirmed ("potential") findings as such, and no longer lists
  findings someone set to ignored in Qualys as new work. The application name
  falls back to the notification's `Target` line, not the title.

- **Quiet applications had no report link.** The link was rendered only under
  CHANGED THIS WEEK, so an application with nothing new - on the first send,
  all three public sites - never showed one. It is now one line under every
  application in OPEN NOW, and under the fault entry for a scan that did not
  finish.

- **`run-appscan` accepted and ignored unknown arguments.** The unit file was
  first generated from the weekly one and arrived with a stray `weekly` on its
  `ExecStart`. The runner would have shrugged and run in the default mode while
  the service file looked correct to anyone reading it; it now refuses.

### Changed

- **The application-security email looks like the rest of the fleet's mail.**
  The daily brief's palette, navy header band and 640px card, severity tiles,
  and a subject in the family shape — `CTI Fleet AppSec Oct 05: ...`, with
  `[AUTH FAILED]` or `[INCOMPLETE]` in front when something is broken. It
  previously read `[AppSec] Week of Oct 4: ...`, which nowhere said where the
  mail had come from.

  The severity **colours** are shared with the daily; the severity **words**
  are not, and the footer says so on every send.

- **One clickable link, for links the lane builds.** Every URL that arrived in
  scanner mail stays plain text. Each application's "open in Qualys" link is
  built from the WAS scan list: the UI host derived from `QUALYS_BASE_URL`,
  a constant path, and the scan's integer id -
  `/was/#/reports/online-reports/email-report/scan/<id>`, the same page
  Qualys's own email links to, with the id checked against a real
  notification. It is rendered as an anchor only after an https and
  exact-host check against hosts registered for that scan's provider.

- **The mailbox is reconciled with the Qualys WAS scan list.** Joined on the
  scan reference. The API supplies the real application name and id, can mark
  a scan's authentication FAILED (never the reverse), and adds vulnerability
  scans whose completion email never arrived - listed under SCANNED, NO
  NOTIFICATION with no counts, never totalled. Discovery scans, scans still
  running, and on-demand runs that failed with no email are left out; a
  scheduled authentication failure is a fault whether or not an email came.
  With no Qualys credentials the lane reports from the notifications exactly
  as before. Qualys severity 5 is a claim
  about one HTTP response; the fleet's Sev5 means exploited in the wild and
  confirmed present in the estate.

- **The weekly digest is a roll-up of stored findings, not a second mailbox
  read.** It never was a week: `cti-agent-weekly.service` runs `run-digest`
  with no `--lookback`, so it read the same 24 hours as the daily. On
  2026-10-05 both briefs reported reading the same four emails an hour apart,
  and the operator reasonably read that as the daily having sent twice.

  Widening the mailbox query to 168h does not fix it — the cleanup lane
  archives advisories on a 48-hour grace once a completed run has read them, so
  a 7-day query sees only what happened not to be archived yet. That is a
  partial week presented as a whole one, which is worse than the honest 24
  hours it produced before. `fleet-db rollup --days N` reads the findings table
  instead: those are what the fleet concluded, they outlive the mail they came
  from, and they are immune to the archive grace.

- **The weekly subject is no longer byte-identical to the daily's.**
  `subject(data, kind)` accepted `kind` and used it in none of its six return
  paths, so the Monday weekly went out with the daily's subject line —
  including "in the last 24h" on a report covering seven days.

### Upgrade

Reinstall and set two variables. The lane's timer is **not** enabled by the
installer; see [RUNBOOK 11f](RUNBOOK.md#11f-the-weekly-application-security-lane).

```bash
# in fleet.env, both required - the mailer refuses without them
WAS_TO="appdev-leads@example.com"
WAS_ALLOW_TO="appdev-leads@example.com,security@example.com"
```

```bash
sudo cti-agent run-appscan --dry-run     # open the HTML it leaves in state/
sudo systemctl enable --now cti-agent-appscan.timer
```

Nothing else changes meaning. The Qualys WAS Findings API uses the same
credentials as the VM lane and the same `QUALYS_BASE_URL`, but needs the WAS
module enabled on the account's role — without it the lane reports counts from
the notification emails and logs a warning naming the role.

---

## 1.0.2 — 2026-10-04

### Fixed

- **The daily digest was reading its own output back in.** The digest is
  delivered to the same mailbox it reads, so yesterday's digest arrived as
  today's input, the extractor pulled the CVEs out of our own report, and they
  were presented as newly mentioned. Self-sustaining: a CVE reported once
  re-entered every subsequent run, so the daily could never go quiet and the
  "emails mentioning a CVE" count was fiction. Observed on 2026-10-04, where
  the single CVE-bearing email of the run was the previous day's own Sev5
  digest. Outgoing mail now carries `X-CTI-Agent-Sent`, and the ingest skips
  anything carrying it — with the sending address as a backstop for mail sent
  before the header existed. The count of skipped messages is logged, because a
  filter that silently removes input is how the next blind spot starts.
- **The cleanup lane would have left those reports in the inbox forever.** Its
  first rule is "no processing record → leave, absolute", and our own mail is
  now deliberately never processed. Left alone it would have filled the inbox
  and then escalated *"the agent has stopped reading the mailbox"* about a
  mailbox it was reading perfectly well. Self-sent mail is archived — not
  deleted; there is no case for a schedule quietly destroying our own audit
  trail in a shared mailbox.
- **A dead feed was reported as malformed XML for four days.**
  `msrc.microsoft.com/blog/feed` now 302s to an HTML page. Every run logged an
  identical `mismatched tag: line 124, column 158` — true about a stable HTML
  document, thoroughly misleading about the cause, and it sent the diagnosis
  looking for a bad byte in somebody's XML. Twenty-four consecutive beats
  recorded it as "known, persists". Microsoft advisory coverage was dark
  throughout. `scout` now distinguishes "this is not XML at all" from "this XML
  is malformed" and says which, and the feed is replaced by the MSRC Update
  Guide RSS — one item per CVE, which is what the lane keys on.

### Changed

- `task ship` ran `gofmt -w .` and then `git push`, so any reformatting it
  performed was left uncommitted and never pushed. That is how `v1.0` got
  stamped `-DIRTY`. It now fails instead: a gate may not modify the thing it is
  checking. Run `task fmt` yourself and commit the result.
- `task check` referenced a task named `fmt:check` that did not exist, so the
  CI entry point would have errored on first use. It exists now.

### Upgrade

Nothing required. Pull, reinstall.

On the first scout run after this, expect a large batch of first-seen CVE IDs:
the Update Guide feed carries every revision, including a lot of republished
Chromium entries, and none of them are in the seen-set yet. Worth watching that
run rather than letting it land unattended.

---

## 1.0.1 — 2026-10-02

### Fixed

- **The installer could stop halfway and look like it had finished.** Reading
  an optional `FLEET_*` key from `fleet.env` with a `grep` pipeline ends the
  script when the key is absent: grep exits 1 on no match, `set -o pipefail`
  carries that status to the end of the pipeline, the assignment inherits it
  and `set -e` exits — with no message at all. A box whose `fleet.env` predated
  the Patch Tuesday lane stopped four lines after printing `✓ daemon-reload`,
  with 400 lines left to run. The wrapper, `/etc/cti-agent/version` and the
  entire verification block never executed, and the visible output was
  indistinguishable from a clean install. Config reads now go through a `sed`
  helper that returns empty for an absent key.
- **`check_path` could never report a missing path.** It read config the same
  way, so a missing key killed the script one line before the `"$1 is unset"`
  branch that exists to report missing keys.
- **`scrub-history.sh` aborted its verification when the scrub had worked.**
  `git grep -l` exits 1 on zero matches, and zero matches is the success case,
  so a fully scrubbed history stopped the loop instead of printing "clean".
- **`run-checkin` could die while explaining why it was holding.** `grep -v`
  exits 1 when it filters everything out, which is reachable whenever
  `cti-budget` prints a flag and no explanation.

### Added

- `internal/shellgate`: a test that fails the build on this pattern. It ran
  clean against all 11 fleet scripts and is checked against the three real
  lines that caused the bugs above, so a failure can be trusted.
- The installer now has an EXIT trap. Any end other than reaching the
  "Installed" banner prints the line number and says the box is partially
  installed. Deliberate exits — `--help`, a dry run, a failed verification —
  stay quiet.
- `task test:syntax` derives its script list from the directories instead of a
  hand-written one. It was checking 9 of 11 scripts; `run-mailbox-cleanup` and
  `compare-mailers.sh` had never been checked.

### Upgrade

Nothing. Pull and reinstall.

If an install ever stopped early on this box, re-running the installer is
sufficient — it is idempotent. Confirm with:

```bash
sudo cat /etc/cti-agent/version      # must exist
sudo cti-agent cti-mailer --check | head -2
```

---

## 1.0 — 2026-10-02

First tagged release. Everything below was already running; this marks the
point from which changes are tracked and a rollback target exists.

### Lanes

- **Daily and weekly digest** — reads the CTI mailbox over Graph, enriches
  against NVD, EPSS and CISA KEV, confirms presence against Qualys Host
  Detection, scores Sev5–Sev1 and emails the result.
- **Patch Tuesday** — monthly synopsis correlated against the estate, reported
  per QID. Holds its CVEs out of the daily so the same release is not reported
  twice.
- **KEV deadlines** — CISA remediation dates for CVEs confirmed present.
- **Mailbox cleanup** — archives advisories the agent has taken a CVE from,
  deletes header-confirmed auto-replies, leaves everything else for a human.
- **Orchestrator heartbeat** — a `/checkin` beat every two hours, rationed
  against the subscription by `cti-budget`.
- **Jira ticketing** — one ticket per confirmed KEV or Sev5 CVE, carrying every
  QID and host, updated in place as exposure changes.
- **Failure alerting** — `cti-alert` on unit failure, and as the orchestrator's
  only route to a human.

### Added in the run-up to this tag

- `cti-jira`: files and updates one Jira ticket per CVE, identified by a label
  on the ticket rather than a local database, so closing or moving a ticket in
  the UI cannot cause a duplicate. Host lists attach as CSV; the attachment is
  never truncated at any scale.
- `cti-mailer`: the Go port of `mailer.py`, verified byte-identical across a
  19-case comparison harness. **The runners still call `mailer.py`** — see
  RUNBOOK 11b to switch.
- `internal/triage`: deterministic extraction of CVEs, MITRE techniques and
  defanged indicators from advisories that carry no CVE at all. Nothing invokes
  it yet.
- `fleet-db note`: records that a finding has been handed to someone, so a
  ticketed CVE stops being reported as un-actioned.
- Version stamping: binaries carry their tag and commit, and the installer
  records what it built.

### Fixed

Six defects, five of which reported success while doing nothing:

- **The duplicate-send guard had never once fired.** `fleet-db sent` read the
  kind from the message-id's argument index, so every digest was stored under a
  Graph request id and `was-sent` could never match.
- **`findings --stale-days`** compared an ISO-8601 timestamp against SQLite's
  own format as raw strings, silently missing everything from the boundary day.
- **The cleanup archived mail the digest had not finished reading**, so CVEs
  reported only by those advisories dropped out of the next digest. The grace
  period must now be at least as long as the ingest window, enforced at startup.
- **`run-mailbox-cleanup` was never installed** — the copy step used a
  hand-written list while the verification step asserted the file existed.
- **Errored heartbeats consumed model quota**, so a crash-looping orchestrator
  rationed itself into a hold and reported a budget problem instead of a code
  one.
- **An escalation was presented as a crash**, titled "CTI fleet failure" with
  "systemd result: success" underneath.

### Known gaps

- The Graph app is **not scoped to one mailbox**. With `Mail.ReadWrite` and
  `Mail.Send` consented tenant-wide and no access policy, the credential on the
  fleet host can read, move and send as any mailbox in the tenant. Verified
  2026-10-01, accepted for now, recorded in SECURITY.md with the probe to
  re-check it.
- `/etc/cti-agent/ORG-PROFILE.md` is created unfilled. The triage lane stays
  dormant until it is written.
- The orchestrator cannot send mail by design. Escalation is `cti-alert` only,
  which has no `--to`.

### Upgrade

**From an untagged install:**

1. `MAILBOX_LOOKBACK_HOURS` and `MAILBOX_MIN_AGE_HOURS` are new, and the
   installer will refuse to start if the grace is shorter than
   `GRAPH_LOOKBACK_HOURS`. The defaults (72 and 48 against an ingest window of
   24) are consistent; you only need to act if you set them yourself.
2. For Jira ticketing, set `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
   `JIRA_PROJECT_KEY` and `JIRA_ISSUE_TYPE`. Nothing is filed until
   `JIRA_ALLOW_CREATE` also names the project — it fails closed.
3. `Mail.ReadWrite` is required only for the mailbox cleanup lane. Without it
   that lane 403s; everything else is unaffected.
4. Existing files in the state directory keep their old permissions:
   `sudo find /var/lib/cti-agent/state -type f ! -perm 600 -exec chmod 600 {} +`

Nothing else requires action.
