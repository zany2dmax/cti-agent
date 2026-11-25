# Setting up the fleet

The accounts each vendor needs, the install, and turning the timers on in a
safe order. [INSTALL.md](../../INSTALL.md) is the short path through it; this
is the detail behind each step.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

**It follows standard *IX naming, locations and configuration wherever it
can**:
- **Layout:** the Filesystem Hierarchy Standard (code in `/opt`, config in
  `/etc`, state in `/var/lib`, logs in `/var/log` and the systemd journal).
  A fork can move them ([layout.md](../layout.md)).
- **Running:** systemd units, timers and credentials for scheduling and
  secrets, and a system account with no login shell.
- **Commands:** a man page for every command, bash and zsh tab completion,
  `sudo` for anything privileged, and long options with exit status 0 for
  done, 1 for failed and 2 for bad usage.

Nothing needs a custom SELinux policy. The [table below](#where-it-lives)
lists every location.

- [Where it lives](#where-it-lives)
- [Before you start](#before-you-start)
- [1. Microsoft Entra app registration](#1-microsoft-entra-app-registration)
- [2. Qualys API access](#2-qualys-api-access)
- [3. The NVD API key](#3-the-nvd-api-key)
- [8. Installing the fleet](#8-installing-the-fleet)
- [9. Enabling the timers, in order](#9-enabling-the-timers-in-order)

---

## Where it lives

Every path the installer uses is a standard one, so it is where a Linux admin
would look. The installer prints the same list under **Layout**.

| What | Where | Standard |
|---|---|---|
| Code | `/opt/cti-agent` (root-owned, read-only to the service) | FHS add-on software |
| Settings | `/etc/cti-agent/fleet.env`, or `/etc/cti-agent/fleet.d/` once split per lane (11o) | FHS host config |
| Secrets | `/etc/credstore.encrypted/NAME` (11n) | systemd credentials (`systemd-creds`) |
| State | `/var/lib/cti-agent` | FHS variable state, systemd `StateDirectory=` |
| Run output | the systemd journal: `journalctl -u 'cti-agent-*'`; hand runs `-u 'cti-manual-*'` | journald |
| Audit trail | `/var/log/cti-agent` (11l), RFC 5424 syslog lines; optionally forwarded to a syslog server | FHS logs, systemd `LogsDirectory=` |
| Units and timers | `/etc/systemd/system/cti-agent-*.service` and `.timer` | systemd |
| Hand-run wrapper | `/usr/local/bin/cti-agent` | FHS local programs |
| Root tools | `/usr/local/sbin/cti-agent-update`, `cti-agent-secrets`, `cti-agent-settings` | FHS local admin programs |
| Man pages | `/usr/local/share/man/man1` (`man -k cti`) | man(1), FHS |
| Tab completion | `/usr/share/bash-completion/completions`, `/usr/share/zsh/site-functions` | bash-completion, zsh |
| Service account | `ctiagent`, a system account with no login shell, home = the state directory | useradd `--system` |
| Temporary files | private to each run (`PrivateTmp=`), removed when it ends | systemd |

---

A fork that installs elsewhere sets these paths and the account in a
`layout.env`; see [docs/layout.md](../layout.md). This table is the default.

---

## Before you start

| You need | Why | Notes |
|---|---|---|
| Go, at least the `go` line in `go.mod` (1.26) | builds the fourteen binaries | stdlib only; `go.mod` has no dependencies |
| [Task](https://taskfile.dev) | every build, test and gate target | `task --list` shows all of them |
| Python 3.9+ | the SQLite tools (`fleet-db`, `fleet-owners`), `fleet-config` and the root tools; no lane | stdlib only |
| A shared M365 mailbox | where the CTI advisories arrive | the agent reads it; it never replies |
| An Entra app registration | daemon auth to Graph | [section 1](#1-microsoft-entra-app-registration) |
| Qualys API credentials | presence in the estate | [section 2](#2-qualys-api-access) — or run `LOOKUP_PROVIDER=none` to skip |
| An NVD API key | 10x faster enrichment | free, one minute, [section 3](#3-the-nvd-api-key) |

For the always-on fleet you also need a Linux host, a service account, and
optionally Claude Code for the orchestrator heartbeat. See
[fleet-kit/README.md → Install](../../fleet-kit/README.md#install).

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
sudo cti-agent cti-mailer --check    # on the fleet box
./fleet-kit/bin/dev-run doctor       # from a checkout
```

`cti-mailer --check` decodes the token and prints the roles actually granted,
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

## 8. Installing the fleet

One installer, `fleet-kit/install-fedora.sh`, with the FHS layout: code in
`/opt/cti-agent` (`root:root`, read-only to the service), config in
`/etc/cti-agent`, state in `/var/lib/cti-agent`. There used to be a generic
single-directory installer; it is gone because it left the code owned by the
service account, and the heartbeat now refuses to start on a layout like that.
The orchestrator's `CLAUDE.md` and skills live in `/opt/cti-agent/orchestrator`
(root-owned) with `/opt/cti-agent/checkin-settings.json`; on an existing box the
installer moves the old copies from `/var/lib/cti-agent` into
`/etc/cti-agent/quarantine/<timestamp>/`. If a beat refuses with "files that
could steer the beat" or "REFUSING ... is missing", re-run the installer, then
check with `sudo cti-agent run-checkin --audit`.

The installer builds all fourteen binaries, installs 23 systemd units and the
man pages, writes the `/usr/local/bin/cti-agent` wrapper, relabels for SELinux,
and then verifies
the paths it just created. It refuses to install from inside the tree it
deploys into.

```bash
sudo ./fleet-kit/install-fedora.sh --dry-run    # look first
sudo ./fleet-kit/install-fedora.sh --for-real
```

With neither flag it prints usage and exits 2 without touching anything.

Read its verification output rather than its exit code. It reports which timers
are enabled, which is how you find out that only one of six is running — a
fleet where the weekly timer is off will never tell you it is off.

Its last line says which kind of box this is. With any fleet timer enabled it
is an upgrade: `Updated. The fleet is running: N timer(s) enabled`, and nothing
else is asked of you. With none it is a new deployment: `Installed. No timer is
enabled yet`, and it points at [section 9](#9-enabling-the-timers-in-order),
which holds the steps that follow an install.

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

**Start with `sudo cti-agent-onboard --for-real`.** It asks which lanes the
box runs, then each empty setting those lanes need (with the example's
comment), then offers each secret they read that is not stored yet. It writes
the answers where the box keeps its settings and ends with
`fleet-config check`. `--dry-run` shows the same without asking or writing.
In a fork, the `/onboard` Claude Code skill (`.claude/skills/onboard`) walks
through it with you. See `cti-agent-onboard(1)`.

**A box that does not run every lane** sets `FLEET_LANES` in
`fleet.d/00-core.env`: the lanes it runs, comma-separated, by the names in
`/opt/cti-agent/share/lanes.list`. The installer then:
- turns off the timers of the others and skips them in its timer report
- checks that every name is a lane, and stops if one isn't

`fleet-config check` stops requiring the other lanes' settings, and
`fleet-timers --all` lists them as off on purpose. So the check-in neither
reports them nor runs their credential checks, and its verdict must call them
`off`. Unset, every lane runs. Skip the steps below for a lane you left out.

### On a new deployment: the steps after the installer

The installer enables no timer, on purpose. On a new box it ends by pointing
here; on a box where the fleet is already running it says so and how many
timers are enabled. Take these steps in order, reading each one's output before
the next.

1. **Fill in the config, then confirm Graph can see the mailbox.**
   `cti-agent-onboard` asks for each setting and secret the box's lanes need
   ([INSTALL.md](../../INSTALL.md)):

   ```bash
   sudo cti-agent-onboard --dry-run
   ```

   ```bash
   sudo cti-agent-onboard --for-real
   ```

   ```bash
   sudo cti-agent cti-mailer --check
   ```

   Mail.Read is required. Mail.Send is required to send the digest. Missing
   "grant admin consent" is the usual cause of a 403.

2. **Dry run the whole pipeline by hand.** Sends nothing:

   ```bash
   sudo cti-agent run-digest daily --dry-run
   ```

   The first run downloads the Qualys KnowledgeBase, which takes several
   minutes.

3. **Enable ONLY the daily digest.** Live with it for a few days:

   ```bash
   sudo systemctl enable --now cti-agent-digest.timer
   systemctl list-timers 'cti-agent-*'
   journalctl -u cti-agent-digest -f
   ```

4. **Once the digest is trustworthy, add the orchestrator heartbeat.** This is
   the part that needs Claude Code authenticated as the service account
   (`ctiagent`):

   ```bash
   sudo systemctl enable --now cti-agent-checkin.timer
   ```

   The next install turns on `cti-agent-credcheck.timer` with it: the daily
   credential checks, whose report the heartbeat reads (it doesn't run them
   itself). To have one today:

   ```bash
   sudo systemctl enable --now cti-agent-credcheck.timer
   ```

5. **Trim `/etc/cti-agent/feeds.txt` to vendors you run, then:**

   ```bash
   sudo systemctl enable --now cti-agent-scout.timer cti-agent-weekly.timer
   ```

6. **The monthly Patch Tuesday synopsis.** Run it by HAND for now: both article
   sites block Azure addresses, so save the two articles into
   `/var/lib/cti-agent/inbox/patchtuesday/YYYY-MM/` first (CHEATSHEET 7a).
   Leave its timer disabled. A replay cannot send:

   ```bash
   sudo cti-agent run-patchtuesday --month 2026-10 --dry-run
   ```

   It needs outbound 443 to `api.msrc.microsoft.com` and
   `www.bleepingcomputer.com` (`blog.qualys.com` is optional; it refuses Azure
   addresses).

7. **LAST, and only when the digest has been running for a few days: mailbox
   cleanup.** It moves mail in a shared mailbox, so it is the one lane whose
   mistakes other people see ([section 10](../lanes/mailbox.md#10-rolling-out-mailbox-cleanup)).

   It needs Mail.ReadWrite as an APPLICATION permission with admin consent:
   Mail.Read cannot move a message. Apply the Application Access Policy first
   if you have not ([section 1](#confine-it-to-one-mailbox-first)): without it
   that role is tenant-wide.

   ```bash
   sudo cti-agent cti-mailer --check         # expect OK Mail.ReadWrite
   sudo cti-agent cti-mailbox --dry-run      # moves nothing
   sudo systemctl enable --now cti-agent-mailbox.timer
   ```

   The first dry run reports everything as "leave". That is correct: the lane
   only touches messages a completed digest recorded, and the log starts
   filling from the next digest. Run the dry run again the next day before
   enabling the timer.

**If something is denied for no visible reason:**

```bash
sudo ausearch -m avc -ts recent          # SELinux denials
systemd-analyze security cti-agent-digest.service
journalctl -u cti-agent-digest -n 50 --no-pager
```

The rest of the lanes, with the gate before each, are in the table below.

### Every timer, and its gate

| Order | Timer | What it does | Gate before enabling |
|---|---|---|---|
| 1 | `cti-agent-digest.timer` | the threat-intel daily digest | a dry run you have read end to end |
| 2 | `cti-agent-weekly.timer` | the threat-intel Monday roll-up | one daily digest delivered successfully |
| 3 | `cti-agent-scout.timer` | vendor advisory sweep | the digest is stable |
| 4 | `cti-agent-checkin.timer` | orchestrator heartbeat | Claude Code installed, budget ceilings set |
| 4a | `cti-agent-credcheck.timer` | the credential checks, daily 05:30; the heartbeat reads its report | none: read-only. The installer turns it on with the heartbeat's timer |
| 5 | `cti-agent-patchtuesday.timer` | monthly synopsis | a `--month` replay against an email you already sent. **Leave it disabled for now** and run the lane by hand ([section 11](../lanes/patchtuesday.md#11-the-monthly-patch-tuesday-lane)) |
| 6 | `cti-agent-mailbox.timer` | mailbox cleanup | [section 10](../lanes/mailbox.md#10-rolling-out-mailbox-cleanup) — several dry runs |
| 7 | `cti-agent-appscan.timer` | weekly application-security report | `WAS_TO` **and** `WAS_ALLOW_TO` both set, and one `--dry-run` whose rendered HTML you have opened |
| 8 | `cti-agent-domains.timer` | weekly domains check | `/etc/cti-agent/domains.txt` exists, `DOM_TO` and `DOM_ALLOW_TO` set, one `--dry-run` read ([11g](../lanes/domains.md#11g-the-weekly-domains-lane)) |
| 9 | `cti-agent-appowners.timer` | each application's scanner report to its owners, daily | owners moved into `owners.db` and `fleet-owners check` clean ([11f](../lanes/appscan.md#application-owners-in-ownersdb)), one `--to-dev` run whose emails and reports you have opened ([11f](../lanes/appscan.md#reports-to-application-owners-by-email)) |
| 10 | `cti-agent-vmscan.timer` | weekly VM scan report, both scheduled scans in one email, Mondays unless `FLEET_VMSCAN_DAY` says otherwise | `VMSCAN_TO` and `VMSCAN_ALLOW_TO` set, `cti-vmscan --check` listing the scan schedules, one `--dry-run` and one `--to-dev` read; for its coverage check, `SUBNETS_DRIVE_ID` and `SUBNETS_ITEM_ID` set and `sudo cti-agent cti-vmscan --check` OK ([11f](../lanes/appscan.md#the-weekly-vm-scan-report-run-vmscan)) |
| 11 | `cti-agent-supplier.timer` | supplier-request triage, daily | `SUPPLIER_ADDRESS`, `SUPPLIER_TO`, `SUPPLIER_ALLOW_TO` and the Jira settings set, a `--dry-run` whose digest and items you have read, then one `--to-dev` ([11f](../lanes/appscan.md#the-supplier-request-lane-run-supplier)) |

```bash
systemctl list-timers 'cti-agent-*' --all
```

Check that list after every install. **A disabled timer is silent**, and the
weekly one being off means nobody receives the Sev1 roll-up while every other
signal says the fleet is healthy.

Timers use the **system** timezone, not `FLEET_TIMEZONE`. See
[fleet-kit/README.md → Timezones, the trap](../../fleet-kit/README.md#timezones--the-trap).
