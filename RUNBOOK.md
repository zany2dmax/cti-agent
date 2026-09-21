# RUNBOOK

Everything needed to get this running, from an empty checkout to a box that
mails a digest every morning without being asked.

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
- [12. Verifying a run](#12-verifying-a-run)
- [13. Report sensitivity](#13-report-sensitivity)
- [14. Scanner KB cache freshness](#14-scanner-kb-cache-freshness)
- [15. When something breaks](#15-when-something-breaks)

---

## Before you start

| You need | Why | Notes |
|---|---|---|
| Go 1.23+ | builds the six binaries | stdlib only; `go.mod` has no dependencies |
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
scan configuration.

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
reads it through `internal/fleetenv`, so a run by hand gets the same settings
systemd gives it. `export KEY=value` and `KEY=value` both work.

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
| `FLEET_ALLOW_TO` | Recipient allowlist enforced in code; anything outside it needs `--approve` |
| `FLEET_OPERATOR_EMAIL` | Where the orchestrator escalates. Pre-approved |
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

Build it, point it at a mailbox, get a markdown report. No fleet, no systemd.

```bash
cp .env.example .env
vi .env                  # real values

set -a; source .env; set +a
go run ./cmd/cti-agent
```

Or with Task:

```bash
task build               # all six binaries into bin/
task run
```

The report lands at `REPORT_PATH`, mode `0600`, gitignored. Read
[section 13](#13-report-sensitivity) before moving it anywhere.

---

## 6. Local development loop

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

The Fedora installer builds all six binaries, installs 13 systemd units, writes
the `/usr/local/bin/cti-agent` wrapper, relabels for SELinux, and then verifies
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
| 1 | `cti-agent-digest.timer` | the daily digest | a dry run you have read end to end |
| 2 | `cti-agent-weekly.timer` | the Monday roll-up | one daily digest delivered successfully |
| 3 | `cti-agent-scout.timer` | vendor advisory sweep | the digest is stable |
| 4 | `cti-agent-checkin.timer` | orchestrator heartbeat | Claude Code installed, budget ceilings set |
| 5 | `cti-agent-patchtuesday.timer` | monthly synopsis | a `--month` replay against an email you already sent |
| 6 | `cti-agent-mailbox.timer` | mailbox cleanup | [section 10](#10-rolling-out-mailbox-cleanup) — several dry runs |

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
| The agent read it and took a CVE from it | **Archive** |
| Its own headers declare it an automatic reply | **Deleted Items** (recoverable) |
| Everything else | **Left alone** |

A shared security mailbox receives reported phishing, alerts, scan
notifications and ordinary mail from colleagues. "The agent read it looking for
CVEs and found none" is not "this has been dealt with", and only the first of
those is what the processed-message log records. Rule 4 used to be archive, and
the first production dry run proposed filing away a message whose entire
subject was `suspicious`.

Auto-reply detection is **headers only** — `Auto-Submitted: auto-replied` or
`X-Auto-Response-Suppress`. Subject text does not delete mail. An auto-reply
whose sender omits the headers stays in the inbox, which is the direction to
fail in.

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
manifest, so it cannot alter what the daily digest suppresses.

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
