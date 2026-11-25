# Configuring the fleet

Where the settings live (`fleet.env`, or `fleet.d/` per lane), how secrets are
stored as systemd credentials, and the org pack. [lanes.md](../lanes.md) lists
each lane's own settings and secrets.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [4. Configuration](#4-configuration)
- [11m. What is in fleet.env](#11m-what-is-in-fleetenv)
- [11n. Moving secrets into systemd credentials](#11n-moving-secrets-into-systemd-credentials)
- [11o. Settings per lane](#11o-settings-per-lane)
- [11p. The org pack](#11p-the-org-pack)

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
| `DIGEST_SKIP_SUBJECTS` | Optional. Comma-separated, case-insensitive subject substrings the daily reads no CVEs from. Unset = Qualys's weekly "Latest Vulnerabilities Added to the Knowledge Base" (thousands of CVEs that describe the scanner, not our estate; it stalled the 2026-11-02 daily). Empty = skip nothing. Skipped mail is logged by subject and left in the mailbox |

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
| `QUALYS_KB_CACHE` | Local JSON cache path for the CVE→QID map. QID titles live beside it in `<path>.titles.json` |
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
| `FLEET_OPERATOR_EMAIL` | Where the orchestrator escalates and where failure alerts go. Pre-approved. Comma-separated for more than one operator (people, not a distribution list); a typo is not caught by the allowlist, because the operator is always allowed |
| `FLEET_DEV_EMAIL` | Development only: where `--to-dev` sends a test (never CC'd, subject `[DEV TEST] ...`). Accepted by `cti-mailer`, `cti-alert` and the `run-digest`, `run-patchtuesday`, `run-appscan` and `run-domains` runners; a runner test send records nothing, files no tickets and advances no baseline. Nothing scheduled uses it |
| `CTI_REPLY_MAILBOX` | Mailbox you reply into; defaults to `GRAPH_MAILBOX` |
| `REPORT_HOSTNAMES` | Hostname disclosure: `full` (default), `redact`, `count`. [Section 13](operations.md#13-report-sensitivity) |
| `REPORT_REDACTION_SALT` | Private, stable salt for hostname pseudonyms |
| `FLEET_ORG` | Organisation name used in email copy, default `Security` |
| `FLEET_ATTRIBUTION` / `FLEET_REPO_URL` | Credit line at the foot of the digest, the Patch Tuesday synopsis, the AppSec weekly and the application-owner emails. Both unset means the lane's plain "Generated by" line |
| `FLEET_TIMEZONE` | Timezone for the "was anything processed today" check |

### Enrichment and the fleet

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Free NVD key. Without it enrichment is 10x slower |
| `FLEET_USER_AGENT` | User-Agent sent to NVD, EPSS, CISA, advisory feeds, Microsoft and the domains web check. `GRAPH_MAILBOX` is appended as the contact unless the value has its own `(...)` comment |
| `FLEET_PROCESSED_LOG` | Where the agent records which messages it read. Defaults to `$FLEET_HOME/state/processed-messages.json`. **This file is mailbox cleanup's entire authority to move anything** — no entry, no move. A `run-digest` dry run or test send sets its own, under `dryrun/digest-<kind>/` |
| `FLEET_LOCK_WAIT_SECONDS` | How long a real `run-digest`, `run-appscan`, `run-domains`, `run-supplier`, `run-appowners`, `run-vmscan` or `run-patchtuesday` waits for another run of its lane (the lane lock, `state/locks/<lane>.lock`) before failing (or, past a rehearsal still running, going ahead with a warning). Default 600. A dry run or test send never waits: it refuses with exit 75 |
| `MAILBOX_SELF_MIN_AGE_HOURS` | How long the fleet's own reports stay in the inbox before cleanup archives them. Default 168 (a week); 0 archives on sight; must be less than `MAILBOX_LOOKBACK_HOURS` |
| `MAILBOX_DIGEST_SENDERS` | The quarantine digest's sending address(es), exactly. A digest holding nothing the fleet reads goes to Deleted Items; one holding mail from Qualys or `MAILBOX_FEED_SENDERS` stays a week and the operator is alerted to release it. Blank: rule off |
| `MAILBOX_FEED_SENDERS` | The senders the fleet reads besides Qualys (newsletters, advisory lists): `name@example.com` exactly or `@example.com` for a domain |
| `MAILBOX_TEAM_SENDERS` | Who may mail a CVE in to be checked: each CVE in authenticated mail from them is looked up and listed under "Asked about" in the next daily, whatever its severity. Same format; a message naming more than 5 CVEs asks about none. Unset: the mailbox's own domain; `none`: off. "Authenticated" includes Exchange's internal stamp, which a connector of type OnPremises (or with TreatMessagesAsInternal) also puts on mail it relays - keep third-party gateways as Partner connectors |
| `FLEET_MAILBOX_BACKLOG_THRESHOLD` | Report when this many inbox messages have no processing record, default 25 |
| `MAILBOX_STALE_DAYS` | Inbox mail older than this many days that no rule moved goes to `MAILBOX_STALE_FOLDER`. Default 30; 0 turns the sweep off; must be longer than `MAILBOX_LOOKBACK_HOURS` |
| `MAILBOX_STALE_FOLDER` | The folder under the inbox the sweep moves into, created on first use. Default `Unhandled` |
| `MAILBOX_STALE_MAX` | The most messages one cleanup run sweeps, 1-5000. Default 200 |
| `AUDIT_DIR` | Where the audit trail is written. Default `/var/log/cti-agent`; `off` discards it (tests and development only). See [11l](operations.md#11l-the-audit-trail) |
| `AUDIT_RETAIN_DAYS` | Audit files older than this many days are deleted by the daily mailbox cleanup. Default 120 |
| `AUDIT_SYSLOG_ADDR` | `host:port` of a syslog collector to forward each audit line to, as well as the file. Unset: no forwarding |
| `AUDIT_SYSLOG_PROTO` | `tls` (default; verifies certificate and host name), `tcp` or `udp`. The last two are unencrypted and allowed only to a collector on this host |
| `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` | Only for the orchestrator heartbeat |
| `FLEET_BUDGET_*` | Quota ceilings for the heartbeat. See [fleet-kit/README.md → Quota ceilings](../../fleet-kit/README.md#8-quota-ceilings) |

The full annotated reference, including every fleet-only setting, is
[fleet-kit/README.md → Configuration reference](../../fleet-kit/README.md#configuration-reference).
`fleet.env.example` is the authoritative list.

---

## 11m. What is in fleet.env

`fleet.env` holds about 165 settings. Before the split, every unit loaded all
of it, so every lane carried every secret. `fleet-config` was step 1 of
splitting it. It shows what the file holds, and never prints a value:

```bash
sudo cti-agent fleet-config check
sudo cti-agent fleet-config list --by-reader
```

`check` reports:

| Heading | What to do |
|---|---|
| `MISSING` | A required setting that's unset or empty. Set it. |
| `NOT READ BY ANY CODE` | A typo (it suggests the nearest name) or a leftover. Fix or remove it. |
| `SET MORE THAN ONCE` | The last line wins. Keep one. |
| `NOT A SETTING` | Line numbers that aren't `KEY=value`. |
| `REFERENCES THAT EXPAND TO NOTHING` | A `$NAME` in a value whose key isn't set above that line. Bash reads the file top to bottom, so it expands to nothing. Move the helper up, or set it. |
| `HELPERS` | Keys no code reads that other settings use as `$NAME` (a team list added to several address lists, say). Not a problem. |
| `EQUAL TO THE DEFAULT` / `SET TO NOTHING` | Can be removed: the code does the same without them. |
| `SECRETS SET` | Each secret, and the programs that actually read it. Step 2 grants each secret only to those. |

It exits 1 only for the problems (missing, unknown, set twice, not a
setting, references that expand to nothing), so it can gate an install. Removable
settings aren't problems.

**Where its knowledge comes from.** `/opt/cti-agent/settings.manifest`, built
from the code by `scripts/settings-manifest`. Every key in the code and in
`fleet.env.example` is listed, with the programs that read it. For Go, that
includes every command that imports the package reading it. A test fails the
build if the manifest drifts from the code. Kept by hand in that file: which
keys are secrets, when a key is required, and a default the scanner can't
see. After changing what the code reads:

```bash
scripts/settings-manifest --write
git diff fleet-kit/fleet/settings.manifest
```

---

## 11n. Moving secrets into systemd credentials

Step 2 of splitting `fleet.env`. Today every unit loads all of `fleet.env`,
so every lane, and every process it starts, holds every secret in its
environment. After the move:

- **Encrypted store.** Each secret is encrypted to this machine (its TPM where
  it has one) in `/etc/credstore.encrypted/NAME`.
- **Per-unit grants.** Each unit imports only the secrets its programs read.
  The `ImportCredential=` lines in each unit are generated from
  `settings.manifest`.
- **Files, not environment.** systemd decrypts a unit's secrets, for that run
  only, into a private folder the programs read. Each runner then drops the
  `fleet.env` copy of any secret it has as a file, so its children stop
  inheriting it.
- **Hand runs.** `sudo cti-agent CMD` runs as a temporary systemd unit with
  the same grants as the command's timer. You see its output as usual, its
  exit code comes back, and the journal records it as `cti-manual-*`, with who
  ran it.

**Nothing breaks along the way.** A unit skips a credential that isn't stored
yet, every program falls back to `fleet.env`, and hand runs keep using `sudo`
until a secret the command needs is stored. So secrets move one at a time,
and each step can be checked.

**Needs:** systemd 254 or later. The installer warns if the box is older, or
if a test transient unit refuses `ImportCredential=`. In either case, keep
the secrets in `fleet.env`: nothing else changes. The model token must be
`ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`, as before.

### The move

1. **See where things stand.** This never prints a value:
   ```bash
   sudo cti-agent-secrets status
   ```
2. **Encrypt what `fleet.env` holds.** Check with the dry run, then import:
   ```bash
   sudo cti-agent-secrets import --dry-run
   sudo cti-agent-secrets import
   ```
   It reads each value the way the runners do, by having bash source
   `fleet.env`, so comments, quotes and `$HELPER` references mean the same.
   To store one by hand instead: `sudo cti-agent-secrets set NAME` (typed,
   not echoed).
3. **Check every lane.** Each hand run below now goes through systemd with
   its timer's grants:
   ```bash
   sudo cti-agent cti-mailer --check
   sudo cti-agent cti-jira --check
   sudo cti-agent run-digest daily --dry-run
   sudo cti-agent run-vmscan --dry-run
   sudo cti-agent run-supplier --dry-run
   sudo cti-agent run-domains --dry-run
   sudo cti-agent run-checkin --dry-run
   ```
   `journalctl -u 'cti-manual-*' -n 50` shows each one.
4. **Delete the secrets' lines from `fleet.env`.** Do this once the dry runs
   pass. `sudo cti-agent-secrets status` and `sudo cti-agent fleet-config
   check` both list the secrets that are stored and still in the file. After
   that, no environment holds them.
5. **Let one day of timers run**, then check the Daily Brief and
   `sudo cti-agent fleet-journal` as usual.

**The login halves move too.** A secret is only half a login. Its client ID,
username or API host (`TENANT_ID`, `CLIENT_ID`, `QUALYS_USERNAME`,
`QUALYS_BASE_URL`, `JIRA_EMAIL`, `JIRA_BASE_URL`, `JIRA_CLOUD_ID`,
`FALCON_CLIENT_ID`, `FALCON_BASE_URL`, `POD_CLUSTER_ID`) is marked
`credential: yes` in `settings.manifest`. It moves with its secret, and only
the units that get the secret get it. `cti-agent-secrets import` stores them,
and `fleet-config check` lists any still in `fleet.env` under `LOGINS NOT
MOVED YET`. Then run the lanes' dry runs and delete those lines, as for the
secrets.

**Rotating a secret** (a new Graph client secret, say):
`sudo cti-agent-secrets set CLIENT_SECRET`. The next run of every unit uses
it. No `fleet.env` edit and no restart.

**Going back.** Put the line back in `fleet.env` and run
`sudo cti-agent-secrets remove NAME`. Programs fall back to `fleet.env` from
their next run.

**What each unit gets.** The grants are generated, so the lists are wider
than strictly needed. A program counts as reading a secret if it could, such
as `cti-mailer`'s `--check` table naming the model token, and a runner gets
the secrets of every program it calls. Wider is safe: a lane never lacks a
secret it needs. Narrowing the lists is later work.

---

## 11o. Settings per lane

Step 3 of splitting `fleet.env`. With the secrets and their logins in systemd
credentials (11n), `fleet.env` holds only ordinary settings: recipients,
allowlists, paths, schedules and switches. Every unit still loads all of
them. After the split:

```
/etc/cti-agent/fleet.d/00-core.env     what several lanes read
/etc/cti-agent/fleet.d/<lane>.env      what only that lane reads
```

- **Units.** Each unit loads core, then its own file. The check-in loads every
  file, because its job is to run every lane's checks.
- **Hand runs.** A hand run of a runner loads exactly its unit's files. Any
  other hand run loads them all.
- **Plain files.** They stay plain text: edit them as you edited `fleet.env`.

**Which file a setting goes in** is `file:` in `settings.manifest`, generated
from the code:
- **The intent** comes from a rule on the name (`SUPPLIER_*` to supplier,
  `DOM_*` and `DOMAINS_*` to domains, `CHECKIN_*` to checkin, and so on), or a
  hand-kept `lane:`.
- **The check:** a setting stays in its lane's file only if no program outside
  that lane could read it. Otherwise it goes to core, and `file-why:` says why.

Core is large, because programs that every lane runs read many settings. The
lane files hold what truly belongs to one lane.

**Nothing changes until you split.** Every unit loads `fleet.env` first while
it exists.

### The split

1. **Secrets and logins first.** The split refuses while any secret or login
   is still in `fleet.env` (11n).
2. **See the plan.** It shows key names only:
   ```bash
   sudo cti-agent-settings split --dry-run
   ```
   It refuses if a setting uses `$NAME` from another lane's file, because that
   lane never loads the other file and the value would be empty. Write the
   value out, or use a helper (a name no code reads, like `EY_TEAM`), which
   goes to core.
3. **Split.**
   ```bash
   sudo cti-agent-settings split --for-real
   ```
   This writes `fleet.d/`, keeping every setting line and the comments above
   it. A helper goes before the settings that use it, and a setting no code
   reads goes to core and is named. `fleet.env` is moved aside to
   `fleet.env.pre-split-<time>`, root-only.
4. **Check.**
   ```bash
   sudo cti-agent fleet-config check
   ```
   It checks every file. Two headings matter after a split: `IN THE WRONG
   FILE` (a setting the right lane won't see), and `REFERENCES THAT EXPAND TO
   NOTHING` (a `$NAME` its lane doesn't load).
5. **Run each lane's dry run** (as in 11n), then let a day of timers run.

**Editing afterwards.** Edit the file the setting belongs in.
`fleet-config check` flags one put in the wrong file. A new setting's file is
in `settings.manifest` (`file:`).

**Going back.** The split tool prints the exact commands: move the
`pre-split` file back to `fleet.env` and remove `fleet.d`.

**Status.** `sudo cti-agent-settings status`.

---

## 11p. The org pack

What this organization adds to the orchestrator's instructions, the three
agent prompts and the skills goes in an org pack, not in edits to the
installed files. The installer adds the pack's notes after the core text on
every install and update, so the notes survive updates and the core rules
still apply. [docs/org-pack.md](../org-pack.md) has the layout, the rules
the installer checks, and how to move existing edits into a pack.

On this box (installed from an upstream clone) the pack is
`/etc/cti-agent/org/`, owned by root. A fork commits it as `org/` instead.
Start from `examples/org-pack/`.

The installer refuses to go on when the pack is not root-owned, holds a
symlink or a file it does not know, or reuses a core skill's name. Check a
pack before installing:

```bash
sudo /root/cti-agent-kit/fleet-kit/bin/org-pack check /etc/cti-agent/org /root/cti-agent-kit/fleet-kit/fleet --root-owned
```

**`VMSCAN_GAP_TEAMS`** came with the pack: who the VM scan report asks about
unscanned networks used to be fixed text ("the network and M&A teams") and is
now this setting, default the network team. Set it in
`/etc/cti-agent/fleet.d/vmscan.env` to keep the old wording:

```
VMSCAN_GAP_TEAMS="network and M&A teams"
```
