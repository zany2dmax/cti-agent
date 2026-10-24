# RUNBOOK

Everything needed to get this running, from an empty checkout to a box whose
lanes do their chores on schedule without being asked — starting with the
threat-intel digest every morning, then each other lane in turn.

Read [README.md](README.md) first if you want to know *what* it is; this
document assumes you have decided to run it.

- [Before you start](#before-you-start)
- [1. Microsoft Entra app registration](#1-microsoft-entra-app-registration)
- [2. Qualys API access](#2-qualys-api-access)
- [3. The NVD API key](#3-the-nvd-api-key)
- [4. Configuration](#4-configuration)
- [5. The agent alone](#5-the-agent-alone)
- [6. Local development loop](#6-local-development-loop)
- [7. The two-box workflow: Mac to Fedora](#7-the-two-box-workflow-mac-to-fedora)
- [8. Installing the fleet](#8-installing-the-fleet)
- [9. Enabling the timers, in order](#9-enabling-the-timers-in-order)
- [10. Rolling out mailbox cleanup](#10-rolling-out-mailbox-cleanup)
- [11. The monthly Patch Tuesday lane](#11-the-monthly-patch-tuesday-lane)
- [11a. Catching up after the lane was off](#11a-catching-up-after-the-lane-was-off)
- [11b. Switching the mailer](#11b-switching-the-mailer)
- [11c. Verifying the Jira connection](#11c-verifying-the-jira-connection)
- [11d. What version is this box running?](#11d-what-version-is-this-box-running)
- [11e. Taking a host off the schedule](#11e-taking-a-host-off-the-schedule)
- [11f. The weekly application-security lane](#11f-the-weekly-application-security-lane)
- [11g. The weekly domains lane](#11g-the-weekly-domains-lane)
- [11h. Man pages](#11h-man-pages)
- [12. Verifying a run](#12-verifying-a-run)
- [13. Report sensitivity](#13-report-sensitivity)
- [14. Scanner KB cache freshness](#14-scanner-kb-cache-freshness)
- [15. When something breaks](#15-when-something-breaks)

---

## Before you start

| You need | Why | Notes |
|---|---|---|
| Go 1.23+ | builds the ten binaries | stdlib only; `go.mod` has no dependencies |
| [Task](https://taskfile.dev) | every build, test and gate target | `task --list` shows all of them |
| Python 3.9+ | the enrich, scout, brief and mailer lanes | stdlib only |
| A shared M365 mailbox | where the CTI advisories arrive | the agent reads it; it never replies |
| An Entra app registration | daemon auth to Graph | [section 1](#1-microsoft-entra-app-registration) |
| Qualys API credentials | presence in the estate | [section 2](#2-qualys-api-access) — or run `LOOKUP_PROVIDER=none` to skip |
| An NVD API key | 10x faster enrichment | free, one minute, [section 3](#3-the-nvd-api-key) |

For the always-on fleet you also need a Linux host, a service account, and
optionally Claude Code for the orchestrator heartbeat. See
[fleet-kit/README.md → Install](fleet-kit/README.md#install).

---

## 1. Microsoft Entra app registration

Daemon operation uses the client credentials flow, so these are **application**
permissions, not delegated ones, and each needs admin consent.

| Permission | Needed by | Skip it if |
|---|---|---|
| `Mail.Read` | the agent, to read the CTI mailbox | never — this is the minimum |
| `Mail.Send` | the fleet, to send digests and escalations | you only want markdown reports |
| `Mail.ReadWrite` | `cti-mailbox` only, to move messages | you are not running mailbox cleanup |

### Granting it

1. Entra ID → App registrations → your app → **API permissions**
2. Add a permission → Microsoft Graph → **Application permissions**
3. Add `Mail.Read`, plus `Mail.Send` and `Mail.ReadWrite` if you need them
4. **Grant admin consent.** This is the step people skip, and nothing works
   without it. The button is greyed out unless you hold a directory role that
   can consent — if it is, that is an access request, not a bug.

Then prove it, rather than assuming:

```bash
sudo cti-agent mailer.py --check     # on the fleet box
./fleet-kit/bin/dev-run doctor       # from a checkout
```

`mailer.py --check` decodes the token and prints the roles actually granted,
which is the only reliable answer. It also reports roles that are consented but
that nothing in this codebase calls — worth pruning.

### Confine it to one mailbox first

An application permission is **tenant-wide by default**. `Mail.Send` means the
app can send as any mailbox in the tenant; `Mail.ReadWrite` means it can move
and "delete" mail in any of them. Apply an Exchange Application Access Policy
**before** granting, not after:

```powershell
New-ApplicationAccessPolicy -AppId <CLIENT_ID> `
  -PolicyScopeGroupId cti-agent-mailboxes@example.com `
  -AccessRight RestrictAccess -Description "CTI: security mailbox only"

Test-ApplicationAccessPolicy -Identity <MAILBOX> -AppId <CLIENT_ID>
```

The policy is scoped to the **app**, not to a permission, so an existing
`RestrictAccess` policy covers a permission you add later. That is worth saying
explicitly in an access request: adding `Mail.ReadWrite` to an app already
confined by policy does not widen its reach beyond that one mailbox.

Microsoft has been steering people from `New-ApplicationAccessPolicy` toward
RBAC for Applications in Exchange Online. Either confines the app; ask whoever
administers Exchange which they want to use.

### What this codebase cannot do

`internal/graph` exposes move-to-folder and nothing else. Graph's
`DELETE /messages/{id}` and the purge endpoints are deliberately not
implemented, so "delete" means Deleted Items — recoverable — and emptying that
folder stays a person's job.

---

## 2. Qualys API access

The account needs API access to:

- **KnowledgeBase** vulnerability list — builds the local CVE→QID map
- **Host Detection List** — which QIDs have assets against them

Nothing else. The agent never writes to Qualys: no tickets, no exceptions, no
scan configuration. The one exception is optional: with `WAS_ATTACH_REPORT=1`
(section 11f) it creates a WAS report for an application and deletes it again
after downloading, which needs the WAS report permission on the account.

To run without a scanner at all — useful for separating "can we read the
mailbox" from "does the scanner answer", two failures that look identical
together — set `LOOKUP_PROVIDER=none`. Every CVE then reports `UNKNOWN`, and the
report says so rather than implying absence.

---

## 3. The NVD API key

The enrich lane calls NVD once per CVE. Get a key before running this on a
schedule: **https://nvd.nist.gov/developers/request-an-api-key**

| | Rate limit | 20 CVEs | 50 CVEs |
|---|---|---|---|
| No key | 5 req / 30s | ~2 min | ~5 min |
| With `NVD_API_KEY` | 50 req / 30s | ~15 s | ~35 s |

Responses are cached for 7 days, so the cost is worst on a first run. EPSS and
the CISA KEV catalog need no key.

---

## 4. Configuration

One file, `fleet.env` in production or `.env` in a checkout. Every Go command
reads it through `internal/fleetenv`, and the `cti-agent` wrapper loads it as
the service account before starting any command (Python lanes and `fleet-db`
included), so a run by hand gets the same settings systemd gives it.
`export KEY=value` and `KEY=value` both work.

### Microsoft Graph — required

| Variable | Purpose |
|---|---|
| `TENANT_ID` | Entra tenant ID |
| `CLIENT_ID` | App registration client ID |
| `CLIENT_SECRET` | App registration client secret |
| `GRAPH_MAILBOX` | Mailbox to read, e.g. `threatintel@example.com`. **Required, no default** |
| `GRAPH_FOLDER` | Folder to read, default `inbox` |
| `GRAPH_LOOKBACK_HOURS` | How far back to read messages, default 24 |

There is deliberately no default mailbox. A hardcoded fallback once shipped one
organisation's internal distribution list as everyone else's default, and an
unconfigured install read that mailbox instead of refusing to start.

### Vulnerability scanner

| Variable | Purpose |
|---|---|
| `LOOKUP_PROVIDER` | `qualys`, `crowdstrike`, or `none`/`noop` |
| `QUALYS_BASE_URL` | Qualys API base URL, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_USERNAME` | Qualys username, same condition |
| `QUALYS_PASSWORD` | Qualys password, same condition |
| `QUALYS_KB_CACHE` | Local JSON cache path for the CVE→QID map |
| `QUALYS_KB_MAX_AGE_HOURS` | Hours before the cache refreshes, default 168 |

A command only fails on the credentials it actually uses: `cti-mailbox` never
asks for Qualys settings, and `cti-patchtuesday` never asks for Graph ones. A
missing-variable list that names irrelevant settings sends the reader to the
wrong file, so each command validates its own needs. `task test:env` is the
regression test.

### Paths, recipients and content

| Variable | Purpose |
|---|---|
| `FLEET_HOME` | Fleet state directory. Also where the processed-message log and release manifests live |
| `REPORT_PATH` | Markdown output file for the agent |
| `DIGEST_TO` | Digest recipients, comma-separated. No default |
| `VM_ALLOW_TO` | Recipient allowlist enforced in code; anything outside it needs `--approve`. Named `FLEET_ALLOW_TO` before 1.3.1; the old name is still read, and both set to different lists refuses to send |
| `WAS_TO` | Application-security report recipients — the people who own application code, not the people who patch servers. No default |
| `WAS_ALLOW_TO` | Allowlist for `WAS_TO`. **Fail-closed and separate from `VM_ALLOW_TO`:** with either variable unset, `cti-mailer --lane was` refuses and names the one that is missing. `--approve` does not override an empty list. An allowlist may reference another by name (`PT_ALLOW_TO=$VM_ALLOW_TO,extra@example.com`); wildcards are refused |
| `FLEET_OPERATOR_EMAIL` | Where the orchestrator escalates. Pre-approved |
| `FLEET_DEV_EMAIL` | Development only: where `--to-dev` sends a test (never CC'd, subject `[DEV TEST] ...`). Accepted by `cti-mailer`, `cti-alert` and the `run-digest`, `run-patchtuesday`, `run-appscan` and `run-domains` runners; a runner test send records nothing, files no tickets and advances no baseline. Nothing scheduled uses it |
| `CTI_REPLY_MAILBOX` | Mailbox you reply into; defaults to `GRAPH_MAILBOX` |
| `REPORT_HOSTNAMES` | Hostname disclosure: `full` (default), `redact`, `count`. [Section 13](#13-report-sensitivity) |
| `REPORT_REDACTION_SALT` | Private, stable salt for hostname pseudonyms |
| `FLEET_ORG` | Organisation name used in email copy, default `Security` |
| `FLEET_ATTRIBUTION` / `FLEET_REPO_URL` | Credit line at the foot of the digests. Both unset means no line at all |
| `FLEET_TIMEZONE` | Timezone for the "was anything processed today" check |

### Enrichment and the fleet

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Free NVD key. Without it enrichment is 10x slower |
| `FLEET_USER_AGENT` | User-Agent sent to NVD, EPSS, CISA and advisory feeds |
| `FLEET_PROCESSED_LOG` | Where the agent records which messages it read. Defaults to `$FLEET_HOME/state/processed-messages.json`. **This file is mailbox cleanup's entire authority to move anything** — no entry, no move |
| `FLEET_MAILBOX_BACKLOG_THRESHOLD` | Report when this many inbox messages have no processing record, default 25 |
| `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` | Only for the orchestrator heartbeat |
| `FLEET_BUDGET_*` | Quota ceilings for the heartbeat. See [fleet-kit/README.md → Quota ceilings](fleet-kit/README.md#8-quota-ceilings) |

The full annotated reference, including every fleet-only setting, is
[fleet-kit/README.md → Configuration reference](fleet-kit/README.md#configuration-reference).
`fleet.env.example` is the authoritative list.

---

## 5. The agent alone

The threat-intel lane's ingest binary on its own: build it, point it at a
mailbox, get a markdown report. No fleet, no systemd.

```bash
cp .env.example .env
vi .env                  # real values

set -a; source .env; set +a
go run ./cmd/cti-agent
```

Or with Task:

```bash
task build               # all ten binaries into bin/
task run
```

The report lands at `REPORT_PATH`, mode `0600`, gitignored. Read
[section 13](#13-report-sensitivity) before moving it anywhere.

---

## 6. Local development loop

Once per checkout:

```bash
./scripts/dev-setup.sh            # install the git hooks
./scripts/dev-setup.sh --status   # check they are installed and current
```

That installs a `pre-commit` hook which runs `gofmt` over staged Go files and
re-stages them, so `task ship` has nothing left to complain about. Git does not
version `.git/hooks`, so a fresh clone silently has none — hence `--status`.

The hook formats; `task ship` only *checks*. That asymmetry is deliberate:
`ship` ends in `git push`, so reformatting there would rewrite files and then
push without them, which is how `v1.0` got stamped `-DIRTY`. A commit hook is
the opposite case — nothing is published yet, and the fix lands before the
commit it would otherwise invalidate exists.

It skips any file with unstaged changes rather than rewriting it, because
`gofmt -w` rewrites the whole working-tree file and re-staging it would commit
edits you had deliberately held back.

`fleet-kit/bin/dev-run` executes the whole pipeline from a checkout with no
root, no service account and no systemd. It sends nothing unless asked.

```bash
./fleet-kit/bin/dev-run doctor                  # config + Graph token + granted roles
./fleet-kit/bin/dev-run ingest --provider none  # mailbox + CVE extraction only
./fleet-kit/bin/dev-run all                     # full pipeline, opens the digest
```

Start with `--provider none`. It needs only the Entra credentials, so it
separates "can we read the mailbox" from "does the scanner answer".

Tests:

```bash
task test               # Go tests + Python lane tests
task test:kev           # deadline bands, sign convention, present-only filtering
task test:budget        # quota ceilings, backoff growth, rate-limit classification
task test:patchtuesday  # release dates, source parsing, exposure, QQL, the QID table
task test:mailbox       # the processed-message gate and the cleanup decision table
task test:env           # fleet.env parsing, and which credentials each command needs
task test:safelog       # the log sanitiser: control characters, rune-safe truncation
task test:graph         # URL construction, sendMail, error diagnosis
task test:report        # hostname redaction and file permissions
```

---

## 7. The two-box workflow: Mac to Fedora

The development box and the fleet box have different jobs and different gates.

```bash
# --- on the Mac: write, prove, push ---
task test           # while changing one thing
task ship           # fmt, build, test, lint, scan, gosec, govulncheck, THEN push

# --- on the Fedora box: deploy, verify, then enable ---
# KIT = wherever the kit checkout lives. Not ~, because the deploy runs
# under sudo and $HOME is then root's.
sudo git -C "$KIT" pull
sudo "$KIT/fleet-kit/install-fedora.sh"
sudo vi /etc/cti-agent/fleet.env            # any new settings
sudo cti-agent mailer.py --check            # token + granted roles
sudo cti-agent run-digest daily --dry-run   # read it before enabling anything
sudo systemctl enable --now cti-agent-digest.timer
```

**`task ship` is the only thing that pushes.** It stops at the first failing
gate, so a push cannot outrun a red test — which it did once, when `task test`
and `git push` were separate lines in the same paste.

**A deploy never enables a timer before a dry run has been read.** The dry run
is the only place a wrong recipient, a broken parser or an empty report is
cheap.

The longer version, including what runs where and why, is
[fleet-kit/README.md → The two-box workflow](fleet-kit/README.md#the-two-box-workflow).

---

## 8. Installing the fleet

Two installers, two layouts:

| Installer | Layout | Use when |
|---|---|---|
| `fleet-kit/install.sh` | everything under one directory | a VM you own, simple paths |
| `fleet-kit/install-fedora.sh` | FHS: `/opt`, `/etc`, `/var/lib` | Fedora/RHEL, SELinux, a service account |

The Fedora installer builds all ten binaries, installs 17 systemd units and the
man pages, writes the `/usr/local/bin/cti-agent` wrapper, relabels for SELinux,
and then verifies
the paths it just created. It refuses to install from inside the tree it
deploys into.

```bash
sudo ./fleet-kit/install-fedora.sh
```

Read its verification output rather than its exit code. It reports which timers
are enabled, which is how you find out that only one of six is running — a
fleet where the weekly timer is off will never tell you it is off.

**One path the installer builds but does not verify:** the ingest binary at
`$CTI_AGENT_DIR/cti-agent`, which is what `run-digest` actually executes. It is
built from the same source as the rest, but it lives outside
`$FLEET_CODE/bin/`, so a lane can be running older code than everything around
it. If a feature you just deployed appears to do nothing, check that binary's
mtime before anything else:

```bash
D=$(sudo sed -n 's/^CTI_AGENT_DIR=//p' /etc/cti-agent/fleet.env | tr -d '"')
sudo ls -l "$D/cti-agent"
sudo git -C "$D" log --oneline -1
```

---

## 9. Enabling the timers, in order

One primitive at a time. Each of these should run, and be read, before the next
one is enabled.

| Order | Timer | What it does | Gate before enabling |
|---|---|---|---|
| 1 | `cti-agent-digest.timer` | the threat-intel daily digest | a dry run you have read end to end |
| 2 | `cti-agent-weekly.timer` | the threat-intel Monday roll-up | one daily digest delivered successfully |
| 3 | `cti-agent-scout.timer` | vendor advisory sweep | the digest is stable |
| 4 | `cti-agent-checkin.timer` | orchestrator heartbeat | Claude Code installed, budget ceilings set |
| 5 | `cti-agent-patchtuesday.timer` | monthly synopsis | a `--month` replay against an email you already sent. **Leave it disabled for now** and run the lane by hand ([section 11](#11-the-monthly-patch-tuesday-lane)) |
| 6 | `cti-agent-mailbox.timer` | mailbox cleanup | [section 10](#10-rolling-out-mailbox-cleanup) — several dry runs |
| 7 | `cti-agent-appscan.timer` | weekly application-security report | `WAS_TO` **and** `WAS_ALLOW_TO` both set, and one `--dry-run` whose rendered HTML you have opened |
| 8 | `cti-agent-domains.timer` | weekly domains check | `/etc/cti-agent/domains.txt` exists, `DOM_TO` and `DOM_ALLOW_TO` set, one `--dry-run` read ([11g](#11g-the-weekly-domains-lane)) |

```bash
systemctl list-timers 'cti-agent-*' --all
```

Check that list after every install. **A disabled timer is silent**, and the
weekly one being off means nobody receives the Sev1 roll-up while every other
signal says the fleet is healthy.

Timers use the **system** timezone, not `FLEET_TIMEZONE`. See
[fleet-kit/README.md → Timezones, the trap](fleet-kit/README.md#timezones--the-trap).

---

## 10. Rolling out mailbox cleanup

This is the only thing in the fleet that modifies the mailbox, on a timer, with
nobody watching. Treat the rollout accordingly.

1. **Grant `Mail.ReadWrite`** and confirm it with `mailer.py --check`. Without
   it the lane can read and plan but every move fails.
2. **Dry run, by hand, for several days:**
   ```bash
   sudo cti-agent cti-mailbox
   ```
   Dry run is the default. `--for-real` is the only thing that moves mail, and
   a flag that must be added to cause an effect cannot be triggered by a
   misconfigured unit file.
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
| The fleet's own report, delivered back to the mailbox, with a correctly **signed** `X-CTI-Agent-Sent` header | **Archive** (a copy is in Sent Items) |
| An automatic reply - by its headers, or a subject starting `Automatic reply:`, `Out of Office:` and the like - read by a lane or not | **Deleted Items** (recoverable) |
| The digest read it and took a CVE from it | **Archive**, after the grace |
| A Qualys WAS scan notice the AppSec weekly reported on (recorded only after a real send) | **Archive**, after the grace |
| Everything else | **Left alone** |

On a day no CTI email was processed nothing is archived, but auto-replies
still go. For a one-off sweep of old auto-replies:
`sudo cti-agent cti-mailbox --lookback 720h --timeout 10m` (dry run), then add
`--for-real`.

A shared security mailbox receives reported phishing, alerts, scan
notifications and ordinary mail from colleagues. "The agent read it looking for
CVEs and found none" is not "this has been dealt with", and only the first of
those is what the processed-message log records. Rule 4 used to be archive, and
the first production dry run proposed filing away a message whose entire
subject was `suspicious`.

Auto-reply detection is **headers, or a subject prefix** (since 1.3.2) —
`Auto-Submitted: auto-replied`, `X-Auto-Response-Suppress`, or a subject that
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

---

## 11. The monthly Patch Tuesday lane

Runs the Wednesday after the second Tuesday — not the second Wednesday, which
is a different day ten times in the next seventy-two months.

```bash
sudo cti-agent run-patchtuesday --dry-run          # this month, sends nothing
sudo cti-agent run-patchtuesday --month 2026-08    # replay a past release
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
[CHEATSHEET.md section 7a](CHEATSHEET.md#7a-patch-tuesday-run-by-hand-monthly).
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
mailer.py          ->  synopsis delivered
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

The digest is idempotent per `(day, kind)`, so a lane that was off for a week
does not backfill itself. One run with a wider window does the job:

```bash
sudo cti-agent run-digest daily --lookback 168h --dry-run   # read it first
sudo cti-agent run-digest daily --lookback 168h             # one consolidated email
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

## 11b. Switching the mailer

`mailer.py` has been ported to `cmd/cti-mailer`. **Both exist**, and the
runners still call the Python one, because this is the component where a
subtle difference is discovered by somebody not receiving a security finding.

Switch it when, and only when, the two agree on real digests.

### Compare them

One command runs both mailers across nineteen cases and prints a verdict:

```bash
task compare:mailers
```

Nothing is sent. Every case passes `--dry-run`, and the harness overrides
every routing variable with `example.com` addresses, so it cannot reference a
real distribution list even if a case escaped the dry run. It compares stdout
(the JSON the runners parse), stderr (the text an operator reads) and the exit
code, and fails the whole run if any case differs.

Nine of the nineteen are refusals — a recipient nobody approved, a stranger on
Cc, `--require-approval` without `--approve`, a malformed address, and the
mutually exclusive flag combinations. **Those are the cases worth reading.** A
port that sends identical mail but has quietly loosened the gate looks like
success from the happy path.

To compare a single case by hand:

```bash
D=/var/lib/cti-agent/reports/digest-daily-$(date +%F).html
S='[Sev5] CTI test comparison'

sudo cti-agent mailer.py    --html "$D" --subject "$S" --dry-run > /tmp/py.json
sudo cti-agent cti-mailer   --html "$D" --subject "$S" --dry-run > /tmp/go.json
diff <(python3 -m json.tool /tmp/py.json) <(python3 -m json.tool /tmp/go.json)
```

They should differ in nothing. Repeat for the cases that matter:

| Case | Command |
|---|---|
| the real digest, with its attachment | add `--attach /var/lib/cti-agent/reports/raw-$(date +%F).md` |
| an escalation | `--to-operator --message "test" --board-id q1 --subject "test"` |
| a recipient outside the allowlist | `--to stranger@example.com` — **both must refuse, with the same message** |
| `--require-approval` without `--approve` | both must refuse |
| the role report | `--check` on both |

The refusals matter more than the successes. A port that sends the same mail
but has quietly loosened the gate is the failure mode worth looking for.

### Then switch

**Two runners send mail, not four.** `run-digest` and `run-patchtuesday`
each have one line to change:

```bash
grep -n 'lanes/mailer\.py' $FLEET_CODE/bin/run-*
#   run-digest:102
#   run-patchtuesday:135
```

Change `python3 "$FLEET_CODE/lanes/mailer.py"` to `"$FLEET_CODE/bin/cti-mailer"`
in each. The flags and the parsed JSON are identical, so nothing else in
either runner moves.

`run-checkin` and `run-mailbox-cleanup` do **not** call `mailer.py` — they
escalate through `cti-alert`, which talks to `internal/graph` directly and has
its own recipient handling. Switching the mailer does not touch them, and
looking for a line there that does not exist is how somebody concludes they
missed a step. (`cti-alert` bypassing `VM_ALLOW_TO` is a separate known gap,
recorded in SECURITY.md.)

Keep `mailer.py` on disk for a couple of weeks; deleting it is a separate,
reversible decision. Until it goes, `task compare:mailers` still works and the
two ST1005 suppressions in `internal/mailer` still earn their place.

### What the port changed on purpose

Nothing about who receives mail. Two things are better by accident of the
language:

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
sudo cti-agent cti-jira --test-ticket
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

What gets a ticket: a finding that is **KEV or Sev5** *and* **PRESENT** in the
estate. Not-present and unknown-coverage findings are skipped — a ticket for a
CVE the scanner cannot find carries no host list, which is the thing that makes
a ticket useless. Non-KEV Sev5 findings are reported but held for approval
rather than filed.

Host names come from a fresh Qualys lookup, not from the enriched file — that
file carries only a ten-host sample. Only the selected CVEs are looked up, so
a normal day is a handful of Host Detection calls rather than one per finding.

The daily then quotes the key and links the ticket under each CVE, in both the
HTML and text parts, until the scanner stops finding it. Its **FLEET TICKETS**
section lists every ticket the follow-up re-checked - key and link, CVE, Jira
status, hosts the scanner sees today, and what the re-check did ("commented:
no detections remain", "no change - no comment", "not re-checked: the scanner
lookup failed") - with tickets closed in the last 30 days below, and the
domains lane's lock-down ticket ([11g](#3b-what-the-report-contains-and-the-lock-down-ticket)).

### Filing tickets for findings that are already outstanding

To ticket today's findings without waiting for tomorrow's digest, point the
lane at the enriched file the last run wrote:

```bash
ls -1 /var/lib/cti-agent/state/enriched-*.json | tail -1     # today's
sudo cti-agent cti-jira --from-enriched /var/lib/cti-agent/state/enriched-$(date +%F).json
```

That is a dry run — it reports what it would file and writes nothing. Add
`--for-real` once the list looks right.

**KEV findings file automatically; a Sev5 that is not on KEV is held.** The
reason is that a KEV entry carries an external deadline, so delay is the
larger risk, whereas a Sev5 the fleet scored itself is a judgement call and
the larger risk is a scoring bug becoming a pile of tickets IT has to close.
To file the held ones deliberately:

```bash
sudo cti-agent cti-jira --from-enriched <file> --for-real --approve
```

`--approve` is a command-line flag and not a `fleet.env` setting on purpose:
`run-digest` never passes it, so the scheduled 06:00 run can only ever file
KEV entries. Making it configuration would turn "the fleet decided to file
this" into something that happens overnight with nobody watching.

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
sudo cti-agent cti-jira --from-enriched /var/lib/cti-agent/state/enriched-$(date +%F).json --follow-up
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

See [CHANGELOG.md](CHANGELOG.md) for what each version requires of you.

---

## 11e. Taking a host off the schedule

```bash
sudo ./fleet-kit/stop-fedora.sh --status        # what is scheduled, changes nothing
sudo ./fleet-kit/stop-fedora.sh                 # stop and disable every timer
sudo ./fleet-kit/stop-fedora.sh --resume        # put it back
```

Nothing is removed: config, state, the seen-CVE database and the Jira ticket
map all survive, so a resume is a resume rather than a re-onboarding. Use
`install-fedora.sh --uninstall` when you actually want the units gone.

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
   [section 9](#9-enabling-the-timers-in-order) as if it were a first install.
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

## 11f. The weekly application-security lane

`cti-agent-appscan.timer`, Fridays 07:30. Reads the DAST scanner's own
completion notifications out of the CTI mailbox, pulls per-finding detail from
the Qualys WAS Findings API where credentials allow, and mails the result
through `cti-mailer --lane was`.

```bash
sudo cti-agent run-appscan --dry-run   # render, print the subject, send nothing
sudo cti-agent run-appscan             # render and send
```

A dry run leaves the rendered report at
`$FLEET_HOME/state/appscan-YYYY-MM-DD.html`, mode 0600. Open it before enabling
the timer: it names which applications have open Urgent findings, so it is a
map of where to look, and it is handled like the VM reports for that reason.

### One Jira ticket per application

Before the weekly email goes, `cti-jira --appscan-tickets` keeps ONE open
ticket per application (label `cti-appscan-<web app id>`), and the email's
**JIRA TICKETS** section names each one:

- **What is on it:** every active, confirmed finding of Qualys severity 5-3
  (Urgent, Critical, Serious) - not ignored, not fixed - grouped
  by QID, with every URL and parameter, and for each: **Risk**, **What the
  scanner found** and **How to fix it**, from the Qualys KnowledgeBase entry
  for the QID. Medium and Minimal are a count. The full list is attached.
- **Potential findings, listed on purpose:** the scanner's own
  **unconfirmed** findings of severity 4 (Critical) and 5 (Urgent) get a
  separate "POTENTIAL - please verify" section under a callout saying they are
  not confirmed - and that not confirmed does not mean not there. Each line is
  labelled `POTENTIAL <sev> - unconfirmed, please verify`, and the ticket header
  and email count them apart ("To verify: ..."). Potential Serious and below
  are still left out. They are part of the findings fingerprint, so an open
  ticket gets one comment the first time a potential appears or goes away.
- **Who it is assigned to:** the owner in `/etc/cti-agent/app-owners.txt`
  (`APPSCAN_OWNERS_FILE`), looked up in Jira by email. Not listed, or not
  exactly one active Jira user with that address: filed **unassigned**, and the
  email says so. If Jira refuses the assignee or component, it is filed
  without them.
- **Each week:** a comment only when the findings changed (what is new, in
  full; what is no longer detected); nothing when they did not; "nothing of
  Serious or above left - it can be closed" once.
- **Built from every open finding** Qualys holds (NEW, ACTIVE, REOPENED),
  however long ago last detected - not just this week's detections, which would
  read a page the week's scan did not reach as fixed.
- **Left alone** that week when the scan did not complete, failed to
  authenticate, was a discovery scan, was not matched to the WAS scan list, or
  the open findings could not be fetched - a scan that did not cover the
  application must not tell its ticket everything was fixed.
- **Optionally, the scanner's own report is attached** (`WAS_ATTACH_REPORT=1`,
  off by default): see "Attaching the scanner's report" below.
- `--dry-run` and `--to-dev` preview only, writing the would-be ticket text to
  `state/appscan-tickets-preview-DATE.txt` (0600), not the journal. Jira
  trouble never stops the email.

Set up the owners file from the scanner's own list, then fill in the owners.
`--list-apps` keeps every owner already on file, adds each new web app with
`OWNER@example.com`, and lists stale lines at the end; the weekly email also
names any web app with no owner, so re-run it when one appears:

```bash
sudo cti-agent cti-appscan --list-apps > /tmp/app-owners.txt
vi /tmp/app-owners.txt                     # replace every OWNER@example.com
sudo install -o root -g ctiagent -m 0640 /tmp/app-owners.txt /etc/cti-agent/app-owners.txt
rm /tmp/app-owners.txt
sudo cti-agent run-appscan --to-dev        # the JIRA TICKETS section previews every app
```

The Jira API account needs the **Browse users and groups** global permission
to look owners up; without it every ticket is filed unassigned.

**Watchers.** A line may add `watchers=a@example.com,b@example.com` (up to 10,
any field order) to copy others on the application's ticket. The owner field
stays ONE email - the assignee. `cti-jira` adds each watcher on create and on
every weekly comment, so watchers added to the file later are picked up. Each
is looked up by email like the owner; one not found, invalid, or refused is
logged and skipped and never blocks the ticket. Needs the **Manage watcher
list** permission on the Jira API account. Watchers are not shown in the
weekly email. Separate emails with commas, spaces or `;`. Adding is one-way:
removing someone from the file does not remove them in Jira, and someone who
unwatches there is re-added at the next weekly comment. `watchers=` on a
placeholder-owner line is ignored until a real owner is set (and lost when
`--list-apps` regenerates the file); on a `site:` line it is ignored with a
problem line. `--list-apps` keeps it on lines with a real owner.

```
id:123456 | dev.lead@example.com | Web Portal | watchers=a@example.com,b@example.com
```

**Coverage: live websites nothing scans.** The domains lane writes our live
websites to `state/domains-websites.json` each week (redirects, registrar
landers, parked pages and domains marked `landing` in `domains.txt` left out).
The weekly AppSec email lists any that no Qualys WAS web app points at under
**NOT SCANNED**, and `--list-apps` adds a `site:<domain>` line for each - the
owner there is who should get a web application scan set up. The line drops
out once a web app covers the site. If a listed site is really a landing page,
mark it `landing` in `domains.txt` instead.

### Staging copies that stand in for production

Some production sites are scanned through a staging or test copy instead of
directly - a WordPress site on WP Engine, say, whose Qualys WAS web app points
at the `*.wpenginepowered.com` staging install, because intrusive DAST tests
belong on staging, not on the live site. Without telling the fleet, the
production site shows under NOT SCANNED, which is wrong, and the staging web
app's ticket reads as if staging were the thing to fix, which is also wrong.

**Record it on the staging web app's line** in `app-owners.txt`:

```
id:777777 | dev.lead@example.com | Web | covers=www.example.com
```

(`covers=` takes several hosts, comma-separated; `www.` is ignored. It can sit
with or without a Jira component.) From then on:

- **The weekly email** moves the production site from NOT SCANNED to
  **COVERED VIA STAGING**, naming the staging host and web app id, with
  "production not scanned directly".
- **The staging web app's ticket** carries a *Stands in for* line: fix it in
  the code, plugins or configuration, then deploy - and check anything
  configured only on production.
- **`--list-apps`** keeps `covers=` when it regenerates the file (even on a line
  whose owner is still the placeholder), lists the covered-via-staging sites
  as comments, and flags any web app whose URL *looks* like staging (a
  hosting provider's staging domain, or a host starting `staging`, `dev`,
  `test`, `uat`, `qa`...) that has no `covers=` yet.
- A site that a web app also scans **directly** is reported as scanned, never
  as via staging.

**What a stand-in does not tell you.** It tests the code and plugins. It does
not test production's own edge, CDN, WAF, TLS settings, security headers,
caching, or anything installed or changed only on production. Two things are
worth doing for every stand-in:

1. **Lock the staging copy down.** A public staging site with production
   content is a second, less-watched copy of the site - drafts, debug output,
   old plugins. Put it behind the host's password protection (WP Engine has a
   per-install switch) and `noindex`.
2. **Add a light scan of production** - a Qualys WAS web app for the live URL
   on a crawl-only / non-intrusive option profile. It catches configuration
   drift without attack payloads against the live site. The production site
   then shows as scanned directly, and the stand-in still carries the
   intrusive tests.

### A different audience, enforced in code

This mail goes to the people who own application code — not the people who
patch servers. The split is not a convention: `cti-mailer --lane was` resolves
`WAS_TO` against `WAS_ALLOW_TO` and **refuses if either is unset**. It does not
fall back to the digest audience, and `--approve` does not override an empty
allowlist.

### Authenticated and unauthenticated scans are both normal

Every count in the report is labelled with the kind of scan that produced it.
That is a statement of scope, not a defect:

- **unauthenticated scan** — covers what a visitor can reach without logging
  in. For a site with no login that is the whole application.
- **authenticated scan** — the scanner logged in, so the pages behind the login
  were tested too.

The report does **not** treat an unauthenticated scan as a coverage gap. An
earlier version did, and named three public sites with no login as having one
— a standing complaint with nothing behind it and nothing anybody could do.

### What does raise a fault

`SCANNER FAULTS` appears only for two things, and both are yours rather than
the App Dev team's:

| Fault | Means | Where to look |
|---|---|---|
| `authentication failed` | A credential **is** configured and did not work. The scan covered the public surface while still looking configured, so this week's counts are not comparable with last week's | The authentication record in Qualys WAS |
| `scan did not complete` | Cancelled, errored, or hit a time limit. Its counts describe a crawl that stopped partway, so none are reported | The scan schedule and the scan's own log in Qualys |

An authentication failure also **emails you** through `cti-alert`, kind `HOLD`,
because the people receiving the report cannot fix a scanner login. The runner
sends the report first; an alerting problem never costs the weekly mail.

```bash
# which applications failed to authenticate on the last run
sudo cat "$FLEET_HOME"/state/appscan-authfail-$(date -u +%F).tsv
```

The file is written on **every** run. Empty means "checked, none failed";
absent means the binary predates `--auth-fail-out` and nothing was checked. The
runner says which in its log, because those two look identical from the mail.

### Links in the report

Each application shows one report link, under OPEN NOW. A link that came from
the scanner's email is **plain text** — the mail arrived at a published
address, and the findings name attackable paths on our own sites. A link the
lane builds from the scanner's API record is **clickable**, after an https and
host check: `https://qualysguard.<pod>/was/#/reports/online-reports/email-report/scan/<scan id>`,
the same page Qualys's own email links to, with the pod taken from
`QUALYS_BASE_URL`. A built link that fails the check is not printed; the
email's link is used instead. Without Qualys credentials there are no built
links.

### What the scan list adds

With Qualys credentials the lane also reads the WAS scan list and joins it to
the mailbox on the scan reference. The run logs one line saying what it found:

```text
[appscan] scans  : 20 in the WAS scan list, 9 matched a notification, 1 added with no notification, 10 skipped (discovery, in flight, or on-demand faults)
```

- **Real application names**, and per-finding detail looked up by the
  application's id. A `note : ... has no application id` line means a
  notification did not match, and its detail was looked up by name instead.
- **SCANNED, NO NOTIFICATION** lists vulnerability scans Qualys ran whose
  completion email never arrived — usually a scan with no notification
  configured. They have no counts; the report says so rather than printing
  zeroes.
- Discovery scans, scans still running, and on-demand runs that failed or were
  cancelled with no email are skipped. A **scheduled** scan that fails to log
  in is a fault and alerts you, email or not.

### A different window

`run-appscan` takes only `--dry-run`. For a two-week test, run the binary and
send it yourself:

```bash
S=/var/lib/cti-agent/state
sudo cti-agent cti-appscan --since 336h --out $S/appscan-14d.html --text-out $S/appscan-14d.txt
sudo cti-agent cti-mailer --lane was --to you@example.com \
  --html $S/appscan-14d.html --text $S/appscan-14d.txt --subject "[TEST 14d] AppSec"
```

The copy still says "this week", and each application still gets one row from
its newest scan. An address outside `WAS_ALLOW_TO` needs `--approve`.

### Attaching the scanner's report

`cti-appreport` fetches the scanner's own per-application report (Qualys WAS:
create, poll, download as HTML_ZIPPED, delete) and `cti-jira --appscan-reports`
attaches it when the ticket is filed or its findings change. Each report is
about five API calls, so only the applications about to be filed or commented
are fetched. **The report contains the scan account's session cookies**: it is
`0600` in a `0700` directory, deleted from Qualys after download, and the
runner deletes the directory after `cti-jira` has attached it.

The Qualys Report API element names are not verified against a live account in
this repository, so test on the box in this order before turning it on:

```bash
sudo cti-agent cti-appreport --list-ids                    # app ids from the last weekly run; no API calls
sudo cti-agent cti-appreport --check                       # credentials, API budget
sudo cti-agent cti-appreport --app-id <id> --dump-request  # the body it would send; nothing sent
sudo cti-agent cti-appreport --app-id <id> --out-dir /tmp/r --keep   # one real report, left in Qualys to inspect
sudo cti-agent cti-appreport --app-id <id> --out-dir /tmp/r          # again, now deleted from Qualys
(umask 077; sudo cti-agent cti-appreport --probe-findings <id> > /tmp/probe.xml)   # raw finding fields, redacted, 0600
sudo rm -rf /tmp/r /tmp/probe.xml
```

If the request is rejected, correct the field in a copy of the dumped body and
send it with `--request-file FILE` (`{{APP_ID}}` and `{{NAME}}` are filled in)
instead of rebuilding. Check the unzipped report opens and the probe shows the
fields you expect, then set `WAS_ATTACH_REPORT=1` in `fleet.env` and run
`sudo cti-agent run-appscan --to-dev` (previews only; nothing is attached on a
dry run or `--to-dev`). Friday's real run attaches. A report that cannot be
fetched is logged and the ticket goes out without it; it never stops the email.

The other settings are in `fleet.env` section 2 and rarely need touching.
`QUALYS_RL_RESERVE` (default 5) is how many API calls the report work leaves for
the VM lane and KnowledgeBase lookups; when only that many remain, reports give
way. `QUALYS_RL_MAX_WAIT` (default 5m) is the longest it sleeps out a rate-limit
refusal. It follows the limits Qualys reports in its response headers, so there
is nothing to change when the contract's limits are raised.
`APPSCAN_REPORT_PROVIDER` (default `qualys-was`) names the scanner; another
one implements `appscan.ReportFetcher` and is added in `cmd/cti-appreport`.

### Adding a second scanner

`internal/appscan` is a provider boundary, like `internal/vulnlookup` for host
VM. A new scanner needs a `Provider` — `Name`, `Recognises(sender, subject)`,
`Parse(body)` — and nothing else; no credentials are required to implement one,
so Invicti or Wiz becomes useful the day its email arrives rather than the day
somebody negotiates API access. A provider that *does* have an API additionally
implements `DetailFetcher`, and losing that costs per-finding detail and not
the report.

## 11g. The weekly domains lane

`cti-agent-domains.timer`, Tuesdays 08:00, to the security team through
`cti-mailer --lane dom`. What it checks is in
[fleet-kit/README.md → The weekly domains check](fleet-kit/README.md#the-weekly-domains-check).

### 1. The inventory (not in the repository)

```bash
sudo install -m 0640 -o root -g ctiagent /dev/null /etc/cti-agent/domains.txt
sudoedit /etc/cti-agent/domains.txt
```

One domain per line, then the markers that choose its row in the security
team's decision chart; `#` comments:

```text
example.com          send receive     # 1: active mail domain
example.net          send             # 2: send-only (no MX needed)
example.org          receive          # 3: receive-only
parked.example                        # 4/5: no mail at all (null MX preferred)
app.example          saas             # 6: an application or service sends as it
unsure.example       unknown          # 7: senders not known - reported, never tightened
old-brand.example    receive legacy   # 9: outbound moved to the main domain
```

`send receive legacy` is row 8. **`send` alone now means send-only**, so mark
every domain that also receives mail `send receive`. A domain with no marker is
checked as one that must not send or receive (`v=spf1 -all`, DMARC
`p=reject`, null MX `0 .`). A typo in a marker is reported in the email rather
than silently read as "no mail". `man cti-domains` has the full chart.
`domains.txt` is in `.gitignore`, and a test fails if one appears anywhere in
the tree.

### 2. The GoDaddy token

Create a Personal Access Token in the GoDaddy developer portal with **only**
`domains.domain:read`. Put it in `GODADDY_PAT` in `/etc/cti-agent/fleet.env`.
The lane makes one call, `GET /v1/domains`, and never requests auth codes.

| Error | Means |
|---|---|
| `HTTP 401` | token missing, expired or revoked |
| `HTTP 403` | token lacks `domains.domain:read`, or the account is not eligible - GoDaddy's code in the message says which |
| `HTTP 429` | rate limited; the next weekly run will retry |

Without a token the report still runs DNS, web and mail checks, and its subject
carries `[REGISTRAR NOT CHECKED]`.

### 3. Recipients and the first run

```bash
# in fleet.env
DOM_TO=$FLEET_OPERATOR_EMAIL           # or the security team's list
DOM_ALLOW_TO=$DOM_TO

sudo cti-agent cti-mailer --check      # lists DOM_TO / DOM_ALLOW_TO
sudo cti-agent run-domains --dry-run   # renders, sends nothing, baseline untouched
sudo systemctl enable --now cti-agent-domains.timer
```

The first real run says *"First run: no previous week to compare with"*. The
week-over-week section starts the Tuesday after. State is
`$FLEET_HOME/state/domains-state.json` (0600); move it aside to start over.

### 3b. What the report contains, and the lock-down ticket

In order: **INVENTORY vs GODADDY** (only when the account and `domains.txt`
disagree: domains in the account but not listed, listed but not in the
account, and listed registrations cancelled, expired or transferred out more
than 45 days ago, which are set aside for removal and not probed);
**WEBSITES** (live, redirecting, registrar-hosted, parked, DNS but no working
page, none); NEEDS ACTION, CHANGED SINCE LAST WEEK, REVIEW and NOTES; then
**DNS CHANGES FOR IT** - the exact records each domain needs to match its
profile, and items to review.

`cti-domains --actions-out` writes those changes, and after the email has gone
`run-domains` passes them to `cti-jira --domains-actions`, which files **one
lock-down ticket** for IT (every change needs the same registrar access). When
that ticket is already open it adds a comment only if the list has changed,
and says once when nothing is left. A dry run only previews the ticket; with
`JIRA_ALLOW_CREATE` empty nothing is written; a Jira failure is logged and
never stops the report. Read DNS CHANGES FOR IT in a `--dry-run` before the
first Tuesday run: every unmarked domain gets a null MX in it.

### 4. Public DNS, and outbound port 53

The lane asks public resolvers (1.1.1.1, 8.8.8.8) rather than this host's DNS.
On the first real run the internal resolver answered for the organisation's
own domains from an internal zone with no SPF or DMARC, and the report called
both domains spoofable. Check the box can reach public DNS:

```bash
dig @1.1.1.1 example.com TXT +short     # use one of your domains
```

If outbound 53 is blocked, set `DOMAINS_DNS_SERVERS` to a resolver that
answers with the public view, or `system` to accept the internal one.

### 4b. Outbound port 25

The lane greets each domain's MX on port 25 to check STARTTLS. Many networks
block outbound 25; if every probe fails the report says *"outbound port 25 is
almost certainly blocked from this host"* once, in its footer, and nothing per
domain. To test from the box:

```bash
timeout 5 bash -c '</dev/tcp/<an-mx-host>/25' && echo open || echo blocked
```

Either open it for this host or set `DOMAINS_SMTP=off`.

### 5. Proofpoint on Demand

With any domain's MX on PoD, the weekly gains a **PROOFPOINT ON DEMAND**
section: domains whose mail is received elsewhere (acquisitions not yet
moved, named by provider, with how many weeks), an MX on another
organisation's PoD tenant (High), senders whose SPF does not authorise PoD,
and what is left after a move (an old SPF include, a Google DKIM key). The
tenant is learned from the MX records; pin it with `PROOFPOINT_POD_TENANT`
if a week could ever have more domains off the gateway than on it.

### 6. DKIM selectors and DMARC reports

DKIM keys cannot be listed, only probed by selector. If a sending domain shows
"no DKIM key at the selectors tried", find the selector from a message header
(`DKIM-Signature: ... s=<selector>`) and add it to `DOMAINS_DKIM_SELECTORS`.

`DOMAINS_DMARC_RUA` is **empty pending a decision** on where aggregate reports
should go (the mail gateway may provide an address). Until it is set the check
is only that every sending domain has *some* `rua=`; once set, every sending
domain's `rua=` must include it.

---

## 11h. Man pages

Every operator command has a page: the ten Go binaries, the `run-*` runners,
`fleet-db`, `fleet-board`, the `cti-agent` wrapper, the Python lanes and
`dev-run`. The installer puts them in `/usr/local/share/man/man1`:

```bash
man cti-domains
man run-digest
man -k cti        # list them all (after mandb has indexed them)
```

They are written from the source. `fleet-kit/tests/test_lanes.py` fails if a
command gains a flag, argument or subcommand its page does not document, and
`task man:lint` checks they render cleanly. Conventions are in `man/STYLE.md`.

---

## 12. Verifying a run

A lane that exits 0 is not the same as a lane that did something. These are the
checks worth making after any deploy:

```bash
# The digest ran, wrote the processed-message log, and found something
sudo journalctl -u cti-agent-digest --since today \
  | grep -E "brief\] wrote|recorded|distinct CVE"

# The cleanup plan, and whether the archive list is only CTI mail
sudo cti-agent cti-mailbox

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
| `No CTI email has been processed today` | either a genuinely quiet day, or the above. The three commands distinguish them |
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
[fleet-kit/README.md → Troubleshooting](fleet-kit/README.md#troubleshooting).
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
