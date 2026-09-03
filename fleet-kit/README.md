# CTI Agent Fleet — Build Runbook

An always-on threat-intel fleet for a Linux server. It wraps `cti-qualys-agent`
in an orchestrator plus three executor lanes, adds exploitability context to
every CVE, and mails a prioritized digest to a security distribution list on a
schedule.

The fleet pattern — orchestrator, executors, heartbeat, message board,
persistent memory — comes from [Build Your Own Claude Code Agent
Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet).
This applies it to a CTI workload instead of a personal-assistant one.

**Conventions in this document.** Replace these with your own values:

| Placeholder | Meaning | Example |
|---|---|---|
| `SECURITY_DL` | Where digests are sent | `soc@example.com` |
| `CTI_MAILBOX` | Shared mailbox the agent reads | `threatintel@example.com` |
| `<TENANT>` / `<CLIENT_ID>` | Entra tenant and app registration | |
| `ctifleet` | Local service account | keep as-is unless it collides |
| `/opt/cti-fleet` | Where the kit is installed | |

---

## The idea in one paragraph

The Go agent already does the hard part: read the CTI mailbox, pull CVEs, ask
the vulnerability scanner whether the environment is actually exposed, write
markdown. What it doesn't do is decide what matters, or tell anyone. The fleet
wraps it. An orchestrator wakes every 30 minutes, three executor lanes add
exploitability context and find CVEs the mailbox missed, and a digest lands in
the security inbox each morning with P1 items at the top. Nobody has to remember
to run anything, and nobody has to read a fifty-row table to find the four rows
that matter.

---

## Architecture

```
LINUX SERVER · your Claude subscription · user: ctifleet
│
├── ORCHESTRATOR ─ the analyst on duty
│   /checkin every 30 min (systemd timer)
│   · reads the board, memory, lane logs
│   · emails the operator when it needs a decision
│   · fires lanes, decides what's worth sending
│   · THE ONLY AGENT THAT SENDS MAIL
│
├── @ingest   cti-qualys-agent (Go)   mailbox → CVEs → scanner → markdown
├── @enrich   lanes/enrich.py         + NVD CVSS, EPSS, CISA KEV → P1–P4
├── @scout    lanes/scout.py          advisory feeds → CVEs the mailbox missed
└── @brief    lanes/brief.py          enriched JSON → HTML digest
                                            │
      ┌─────────────────────────────────────┴──────────────────────┐
      │ SHARED STATE (survives restarts, compaction, reboots)      │
      │  ~/fleet/state/memory.db   findings, scout items, digests  │
      │  ~/fleet/board.md          append-only, lock-safe          │
      │  ~/fleet/CLAUDE.md         standing behavior + autonomy    │
      └────────────────────────────────────────────────────────────┘
                                            │
                          lanes/mailer.py → Graph sendMail
                                            ↓
                                        SECURITY_DL
```

Two things are worth calling out because they're where most fleets go wrong.

**Lanes never mail and never contact a human directly.** They post to the board;
the orchestrator relays. One outbound channel means one place to audit and one
place where the recipient allowlist lives.

**Delivery doesn't depend on the LLM noticing the clock.** The morning digest
runs from a plain systemd timer calling `bin/run-digest` — a deterministic shell
pipeline. The orchestrator's heartbeat does judgment work: chasing UNKNOWNs,
nudging stale P1s, correlating scout backlog. If the model has a bad day, the
digest still goes out. If the timer is disabled, the orchestrator notices on its
next beat and says so.

---

## Why P1–P4 instead of CVSS

CVSS answers "how bad is this vulnerability in the abstract," which is close to
useless for deciding what to do on a Tuesday. A representative report makes the
point: one CVE is PRESENT on 305 hosts with a CVSS of 6.5, while a container
escape most estates don't run scores 8.8 and is NOT_PRESENT. Sorting by severity
buries the first behind the second.

The enrich lane crosses **exploitability in the wild** with **presence in the
environment**:

| | Definition | What it means |
|---|---|---|
| **P1** | `PRESENT` with hosts > 0 **and** (on CISA KEV **or** EPSS ≥ 10%) | Being exploited right now, and you have it. Today. |
| **P2** | `PRESENT` with hosts > 0, any severity — or `UNKNOWN` on something with KEV / EPSS ≥ 50% | You have it, or you can't prove you don't. This patch cycle. |
| **P3** | Exploited or EPSS ≥ 10% but not detected — or `UNKNOWN` with CVSS ≥ 9.0 | Verify scan coverage actually reaches it. |
| **P4** | Everything else | Awareness. Suppressed from the daily; appears in the weekly. |

Three deliberate choices, each of which came out of testing the scoring against
real report data:

**Presence alone earns P2, regardless of CVSS.** An earlier cut gated P2 on
CVSS ≥ 7.0, which put a CVE present on 186 hosts with CVSS 5.5 into P3 — *below*
a NOT_PRESENT CVE. That inverts the exact thing this scoring exists to fix. If
it's on your machines, it's a patching obligation.

**`UNKNOWN` + actively exploited lands in P2, and `UNKNOWN` + CVSS ≥ 9.0 lands
in P3.** A CVE comes back UNKNOWN when the scanner's KnowledgeBase has no QID
mapping for it. That is not "we're clean" — it's "we didn't look." Letting
missing data sink to P4 is the failure mode that shows up in a post-incident
review.

**Host count breaks ties before CVSS does.** A 6.5 on 305 hosts outranks a 9.8
on one.

**EPSS** (FIRST's Exploit Prediction Scoring System) is the probability a CVE
will be exploited in the next 30 days, from `api.first.org/data/v1/epss`. **KEV**
membership comes from NVD's `cisaExploitAdd` field, with CISA's catalog feed
layered on for the remediation due date and ransomware association — so if the
catalog fetch fails, KEV detection degrades but doesn't disappear.

Thresholds live in `enrich.py::prioritize()`. They are opinions, not physics —
tune them to your estate and your patch cadence.

---

## Command reference

Every way to run this, in one place. `task` targets wrap `dev-run`; use either.

### Local pipeline

| Task | Direct | What it does | Sends mail? |
|---|---|---|---|
| `task dev:doctor` | `dev-run doctor` | Tools, `.env` completeness, Graph token, granted app roles | no |
| `task dev:ingest:none` | `dev-run ingest --provider none` | Mailbox → CVEs, **no scanner** | no |
| `task dev:ingest` | `dev-run ingest` | Mailbox → CVEs → scanner lookup | no |
| `task dev:enrich` | `dev-run enrich` | + NVD CVSS, EPSS, KEV → P1–P4 | no |
| `task dev:brief` | `dev-run brief` | Render HTML + text digest | no |
| `task dev:send TO=…` | `dev-run send --to …` | Validate the send path and gate | **dry run** |
| `task dev:send:real TO=…` | `dev-run send --to … --for-real` | Deliver it | **YES** |
| `task dev:all` | `dev-run all` | doctor → ingest → enrich → brief, opens the digest | no |
| `task dev:report` | — | Show the latest report and priority counts | no |
| `task dev:clean` | — | Wipe `.fleet-local/` | no |

### Tests

| Task | Covers |
|---|---|
| `task test` | Everything: Go + Python |
| `task test:go` | All Go packages |
| `task test:graph` | Graph URL building and error diagnosis (guards the `$orderby` bug) |
| `task test:report` | Hostname redaction, salt behavior, `0600` file mode |
| `task test:cve` | CVE extraction and numeric CVE ordering |
| `task test:lanes` | Priority truth table, report parsing, digest, mailer gate (33 cases) |
| `task test:syntax` | Byte-compiles the lanes, `bash -n` the scripts, parses the systemd units |
| `task check` | What CI should run: `fmt:check`, `vet`, all tests, syntax |

### Build and quality

| Task | Does |
|---|---|
| `task build` | Build to `bin/cti-agent` |
| `task run` | Run the Go agent directly from env vars |
| `task install` | Copy the binary to `~/bin` |
| `task fmt` / `task fmt:check` | Format / fail if unformatted |
| `task vet` / `task lint` / `task scan` | `go vet` / golangci-lint / staticcheck |
| `task clean` / `task clean:all` | Build artifacts / also local state |

### Production (on the server)

| Command | Does |
|---|---|
| `bin/run-digest daily` | Deterministic ingest → enrich → brief → **send** |
| `bin/run-digest daily --dry-run` | Same, sends nothing |
| `bin/run-digest weekly` | Weekly rollup, includes P4 |
| `bin/run-checkin` | One orchestrator heartbeat |
| `bin/fleet-board tail 30` | Recent board lines |
| `bin/fleet-board read @you` | Lines addressed to the orchestrator |
| `bin/fleet-db recent` | Memory, open tasks, unacked mailbox, priority counts |
| `bin/fleet-db findings --priority P1` | Query findings |
| `bin/fleet-db findings --stale-days 7` | Findings with no remediation note |
| `lanes/mailer.py --check` | Decode the token, list granted app roles |
| `lanes/scout.py --out …` | Poll advisory feeds for new CVEs |

### Run modes that change behavior

| Setting | Values | Effect |
|---|---|---|
| `LOOKUP_PROVIDER` | `qualys` \| `crowdstrike` \| `none` | `none` skips the scanner entirely — everything returns UNKNOWN, which is how you isolate mailbox and parsing problems |
| `REPORT_HOSTNAMES` | `redact` *(default)* \| `count` \| `full` | Pseudonyms / counts only / real hostnames |
| `GRAPH_LOOKBACK_HOURS` | integer, default `24` | How far back to read mail. `168` = one week |
| `GRAPH_FOLDER` | folder name, default `inbox` | Read a subfolder instead |
| `QUALYS_KB_MAX_AGE_HOURS` | integer, default `168` | When the CVE→QID cache refreshes |
| `--provider` | on `dev-run ingest` | Overrides `LOOKUP_PROVIDER` for one run |
| `--for-real` | on `dev-run send` | Required to actually send; absent = dry run |
| `--approve` | on `mailer.py` | Required for any recipient outside the allowlist |

---

## The NVD API key

Get one before this runs on a schedule. It is free and takes about a minute:
**https://nvd.nist.gov/developers/request-an-api-key**

Put it in `.env` (local) or `fleet.env` (server) as `NVD_API_KEY`.

| | Rate limit | 20 CVEs | 50 CVEs |
|---|---|---|---|
| Without a key | 5 requests / 30s | ~2 min | ~5 min |
| With a key | 50 requests / 30s | ~15 s | ~35 s |

The enrich lane caches NVD responses for 7 days, so day-to-day runs only fetch
CVEs it has not seen. The cost is worst on the first run and after a quiet
period. It works without a key — it is just slow enough to be annoying, and
slow enough that a 06:00 timer might still be running when you check your
phone.

`enrich.py` prints which mode it is in: `set NVD_API_KEY to go 10x faster`
appears when the key is missing.

EPSS and the CISA KEV catalog need no key and no registration.

---

## Test it locally first

Before any of the server setup below, prove the pipeline works on your laptop.
`bin/dev-run` runs the whole thing from a repo checkout: macOS or Linux, no
root, no service account, no systemd. Nothing sends email except the `send`
stage, and that dry-runs unless you pass `--for-real`. State goes to
`.fleet-local/` inside the repo, which is gitignored.

```bash
cd <repo>
cp .env.example .env && vi .env      # tenant, client secret, mailbox

./fleet-kit/bin/dev-run doctor       # tools, config, Graph token + roles
./fleet-kit/bin/dev-run all          # ingest -> enrich -> brief, opens the digest
```

Work up in stages, so a failure tells you *where* it failed:

| Command | Proves |
|---|---|
| `dev-run doctor` | Go and Python present, `.env` complete, Graph token acquired, which app roles are actually granted |
| `dev-run ingest --provider none` | Graph can read the mailbox and CVEs extract — **no scanner involved**, so a failure here is auth or parsing, never Qualys |
| `dev-run ingest` | the scanner lookup works and returns PRESENT / NOT_PRESENT / UNKNOWN |
| `dev-run enrich` | NVD, EPSS and KEV are reachable and P1–P4 comes out sane |
| `dev-run brief` | the digest renders; prints a plain-text preview |
| `dev-run send --to you@example.com` | the send path and the recipient gate work — **dry run**, sends nothing |
| `dev-run send --to you@example.com --for-real` | actually delivers, so you can see what lands in an inbox |

Start with `--provider none`. It needs only the Entra credentials, so it
separates "can we read the mailbox and find CVEs" from "does Qualys answer" —
two failures that look identical in a combined run.

`doctor` failing on `Mail.Send` is expected until you test sending: only
`Mail.Read` is needed for ingest. The `send` stage checks for `Mail.Send`
itself and names the Entra fix if it is missing.

**If ingest finds zero CVEs**, check `Emails inspected` in its output first.
Zero emails is an auth, mailbox or folder problem. Non-zero emails with zero
CVEs is a parsing or content problem — try `GRAPH_LOOKBACK_HOURS=168`, or
`GRAPH_FOLDER=<subfolder>` if the CTI mail is filtered somewhere other than the
inbox. `dev-run` prints this checklist when it happens.

Dev runs set `REPORT_HOSTNAMES=redact`, so local reports carry pseudonyms
rather than real machine names. Override with `REPORT_HOSTNAMES=full` when you
specifically need to see hosts, and remember what that file then contains.

---

## Install

### Prerequisites

- Linux server that stays on. RHEL 8+ / Ubuntu 22.04+, 2 vCPU / 4 GB is plenty.
- Python 3.9+ (stdlib only — no pip installs anywhere in this kit).
- Go 1.21+ *or* a prebuilt `cti-qualys-agent` binary.
- Claude Code, installed and authenticated **as the service account** (see
  below). The heartbeat needs it; the digest timers do not.
- A shared mailbox receiving CTI email, and an Entra app registration that can
  read it.
- Outbound HTTPS to: `login.microsoftonline.com`, `graph.microsoft.com`, your
  scanner's API endpoint, `services.nvd.nist.gov`, `api.first.org`,
  `www.cisa.gov`, and whichever advisory feeds you keep in `feeds.txt`.

### Steps

```bash
# 1. Get the kit onto the box
sudo mkdir -p /opt/cti-fleet && sudo chown "$USER" /opt/cti-fleet
# copy this fleet-kit/ directory to /opt/cti-fleet

# 2. Build the Go agent as the service user
sudo useradd -m -s /bin/bash ctifleet
sudo -u ctifleet git clone <YOUR_FORK_OR_UPSTREAM_URL> /home/ctifleet/cti-qualys-agent
cd /home/ctifleet/cti-qualys-agent
sudo -u ctifleet go build -o cti-qualys-agent ./cmd/cti-qualys-agent

# 3. Install the fleet
cd /opt/cti-fleet && sudo ./install.sh

# 4. Fill in config and secrets (mode 600)
sudo -u ctifleet vi /home/ctifleet/fleet/fleet.env

# 5. Verify Graph permissions BEFORE trusting the morning timer
sudo -u ctifleet python3 /home/ctifleet/fleet/lanes/mailer.py --check

# 6. Dry run the whole pipeline — renders and validates, sends nothing
sudo -u ctifleet /home/ctifleet/fleet/bin/run-digest daily --dry-run

# 7. Enable the timers
sudo systemctl enable --now cti-fleet-checkin.timer cti-fleet-digest.timer \
                            cti-fleet-weekly.timer cti-fleet-scout.timer
systemctl list-timers 'cti-fleet-*'
```

`install.sh` is idempotent and rewrites the systemd units to match whatever
`FLEET_USER` and `FLEET_HOME` you set, so non-default paths work:

```bash
sudo FLEET_USER=secops FLEET_HOME=/srv/fleet ./install.sh
```

### Installing Claude Code on the server

The digest pipeline is plain Python and Go — it never calls Claude. Only the
`/checkin` heartbeat does. So you can run the whole reporting side without this
step and add the orchestrator later.

Install **as the service account**, not as root or as yourself. Claude Code
lives in a user home and authenticates per user; installing it as root leaves
the timer with no credentials.

```bash
# Native installer (auto-updates in the background)
sudo -u ctifleet bash -lc 'curl -fsSL https://claude.ai/install.sh | bash'

# Or via the signed apt repo (updates come through your normal patch cycle)
sudo apt install curl gnupg
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSL https://downloads.claude.ai/keys/claude-code.asc \
  -o /etc/apt/keyrings/claude-code.asc
gpg --show-keys /etc/apt/keyrings/claude-code.asc   # expect 31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
echo "deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main" \
  | sudo tee /etc/apt/sources.list.d/claude-code.list
sudo apt update && sudo apt install claude-code
```

For a server, prefer the **package-manager install**. The native installer
auto-updates in the background, which means an unattended version change under
a running timer; with apt/dnf/apk, updates arrive when you patch the box. If
you do use the native installer, you can pin behavior in the service account's
`~/.claude/settings.json`:

```json
{
  "autoUpdatesChannel": "stable",
  "env": { "DISABLE_AUTOUPDATER": "1" }
}
```

**Authenticate once, interactively.** This is the step that catches people on a
headless box: login opens a browser.

```bash
sudo -u ctifleet -i          # a login shell, so $HOME is right
claude                       # follow the URL it prints, paste the code back
claude --version && claude doctor
exit
```

If the server has no browser, open the printed URL on your laptop and paste the
code back into the server session. Claude Code requires a Pro, Max, Team, or
Enterprise account — the free tier does not include it.

**Path.** There is no single install path: native puts it in
`~/.local/bin/claude`, apt/dnf in `/usr/bin/claude`, Homebrew in
`/opt/homebrew/bin/claude`. `bin/run-checkin` searches all of them at runtime,
so the systemd unit does not hardcode one. If you have several installs, pin the
right one with `CLAUDE_BIN` in `fleet.env`.

### Entra permissions

The Go agent needs `Mail.Read` to read the mailbox. The fleet needs one more to
send the digest:

| Permission | Type | Why |
|---|---|---|
| `Mail.Read` | Application | read the CTI mailbox |
| `Mail.Send` | Application | send the digest as that mailbox |

Entra ID → App registrations → your CTI app → API permissions → Add permission
→ Microsoft Graph → Application permissions → `Mail.Send` → **Grant admin
consent**. Consent is the step people skip; `mailer.py --check` decodes the
token and reports which roles are actually present, so you find out now rather
than at 6am.

Then scope it. `Mail.Send` as an application permission is tenant-wide by
default — the app could send as *any* mailbox in the tenant. Restrict it with an
Application Access Policy:

```powershell
New-ApplicationAccessPolicy -AppId <CLIENT_ID> `
  -PolicyScopeGroupId cti-fleet-mailboxes@example.com `
  -AccessRight RestrictAccess `
  -Description "CTI fleet: security mailbox only"

Test-ApplicationAccessPolicy -Identity CTI_MAILBOX -AppId <CLIENT_ID>
```

Do this even though it's optional. A leaked client secret that can send as
anyone in the organization is a phishing platform; one scoped to a single
mailbox is a contained incident.

---

## Autonomy — where the gates are

The shipped default is **auto-send scheduled digests, gate everything else**,
enforced in three independent places, because a prompt alone isn't a control.

| Layer | Enforces |
|---|---|
| `CLAUDE.md` | The orchestrator's standing instructions — what it may and may not do |
| `mailer.py` recipient allowlist | `FLEET_ALLOW_TO` in `fleet.env`. Any recipient not on it **exits non-zero** unless `--approve` is passed. Not advisory. |
| systemd hardening | `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths` limited to the fleet home |

**No approval needed:** running lanes; reading mailbox, scanner, NVD, EPSS, KEV,
feeds; writing to memory, reports, logs, board; sending the scheduled daily and
weekly digests to `SECURITY_DL`.

**Approval required:** any off-cycle email, including an "urgent" one; any
recipient outside the allowlist; creating tickets, changing scanner config or
scan exceptions; deleting anything outside logs and archive; touching a
production host.

The P1 case is the one you'll be tempted to loosen, so it's explicit: a new P1
does *not* buy the fleet an off-cycle blast. It posts to the board tagged
`[P1 APPROVE-TO-SEND]`, emails the operator, and waits. It also guarantees
the item leads the next scheduled digest regardless of length. If you later
decide P1s should auto-send, wire a separate `FLEET_P1_AUTO` path rather than
widening the allowlist — those are different risks and deserve different
switches.

Tightening it further is a one-line change: set `FLEET_ALLOW_TO` to an address
nobody reads and every send needs `--approve`, which turns the fleet into a
draft-only assistant.

---

### How the orchestrator reaches you

Email, and only email. There is no chat integration — one outbound transport
means one allowlist and one place to audit.

```
lane hits a question it cannot answer
  → posts a line to ~/fleet/board.md addressed to @operator
  → orchestrator emails you on its next beat, with a [FLEET <id>] subject tag
  → you reply to that email, keeping the tag
  → orchestrator reads CTI_REPLY_MAILBOX next beat, posts your answer to the board
  → the waiting lane picks it up
```

Set `FLEET_OPERATOR_EMAIL` for where escalations go, and `CTI_REPLY_MAILBOX`
for where you reply. The default for the second is `GRAPH_MAILBOX`, which is
usually right — the app registration already has `Mail.Read` on it, so no new
permission is needed for the return path.

Escalations to `FLEET_OPERATOR_EMAIL` are **pre-approved**: the orchestrator
has to be able to ask a question without needing permission to ask it. That
address is added to the allowlist automatically. Every other non-scheduled
recipient still requires `--approve`.

```bash
# what the orchestrator runs
python3 ~/fleet/lanes/mailer.py --to-operator --board-id q17 \
  --subject "Approve off-cycle notice?" \
  --message "CVE-2026-1234 is on KEV and present on 305 hosts."
```

---

## Schedule

| When | What | Fired by |
|---|---|---|
| every 30 min | `/checkin` heartbeat — relay, decide, one proactive task | `cti-fleet-checkin.timer` |
| 06:00 daily | ingest → enrich → brief → **send** | `cti-fleet-digest.timer` |
| 00,04,08,12,16,20:15 | scout sweep + correlate new CVEs | `cti-fleet-scout.timer` |
| Mon 07:00 | weekly rollup, includes P4 | `cti-fleet-weekly.timer` |
| Sun 02:00 | scanner KB refresh, vacuum, log rotate | orchestrator, on its beat |

Change the times by editing `OnCalendar=` in the relevant timer, then
`systemctl daemon-reload`.

All timers are `Persistent=true`, so a digest missed because the box was down
fires on boot. A silently skipped digest reads as "no news," which is the worst
possible failure for a system like this.

---

## What lands in the inbox

Subject lines are written to be triaged from a lock screen:

```
[P1] CTI Aug 18: 3 exploited vulns present in the environment
CTI Aug 18: 12 confirmed present, no P1
CTI Aug 18: no new CVEs in the last 24h
```

Body: a one-line lead saying whether to care, P1–P4 count tiles, then findings
grouped by priority. Each carries KEV / ransomware / CVSS / EPSS / status
badges, a plain-English "why it ranks here," the NVD description, and
deduplicated sample hostnames. Table-based layout with inline CSS, because
Outlook. The raw markdown report is attached for anyone who wants every row.

P4 is suppressed from the daily and appears in the weekly. P2 and P3 are capped
at 12 and 10 items on the daily, sorted by host count, with a "+N more in the
full report" note — the attachment has everything. If a run couldn't reach NVD
or EPSS, the digest carries an explicit **DEGRADED** banner naming what was
missing; a digest that hides its own gaps is worse than no digest.

A quiet day still sends. "No new CVEs in the last 24h" is signal; silence is
ambiguous with "the timer died three weeks ago."

**A note on hostnames.** The digest names affected hosts, which makes it a
targeting list if it leaks. Keep `SECURITY_DL` internal, and note that the
upstream report writer redacts hostnames to stable pseudonyms unless
`REPORT_HOSTNAMES=full` — see the repository README. Reports and digests are
written mode `0600` under the fleet home and are gitignored.

---

## Files

```
fleet-kit/
├── README.md                      this runbook
├── install.sh                     idempotent installer (Linux server)
├── bin/dev-run                    local runner: doctor/ingest/enrich/brief/send
└── fleet/
    ├── CLAUDE.md                  orchestrator standing instructions + autonomy gate
    ├── fleet.env.example          all config, superset of the Go agent's .env
    ├── bin/
    │   ├── fleet-board            lock-safe append-only board (post/read/prune/tail)
    │   ├── fleet-db               SQLite memory: findings, tasks, mailbox, digests
    │   ├── run-digest             deterministic ingest→enrich→brief→send
    │   └── run-checkin            resolves the claude binary, fires one beat
    ├── lanes/
    │   ├── enrich.py              NVD + EPSS + KEV → P1–P4, with caching
    │   ├── scout.py               RSS/Atom advisory poller (stdlib XML)
    │   ├── brief.py               HTML + plain-text digest renderer
    │   ├── mailer.py              Graph sendMail + recipient allowlist
    │   └── feeds.txt              feed list — trim to your estate
    ├── skills/
    │   ├── checkin/SKILL.md       the heartbeat's brain
    │   ├── cti-digest/SKILL.md    full pipeline on demand
    │   └── scout-sweep/SKILL.md   feed sweep + correlate
    └── systemd/                   4 service+timer pairs, hardened
tests/
└── test_lanes.py                  33 lane tests: stdlib unittest, no network
```

Run the tests with `task test:lanes`, or `python3 fleet-kit/tests/test_lanes.py -v`.
They stub the NVD, EPSS and KEV fetchers, so they are deterministic offline and
need no API key.

Before first run, edit two files for your environment: `fleet.env` (addresses,
credentials, paths) and `fleet/CLAUDE.md` (the orchestrator's mandate, tone, and
who it escalates to). `CLAUDE.md` is a prompt, not code — rewrite it in your own
words if the shipped voice doesn't fit your team.

---

## Operating it

Substitute your `FLEET_HOME` if you changed it.

```bash
# Health
systemctl list-timers 'cti-fleet-*'
tail -f /home/ctifleet/fleet/logs/{checkin,digest,scout}.log
sudo -u ctifleet /home/ctifleet/fleet/bin/fleet-db recent

# The board
sudo -u ctifleet /home/ctifleet/fleet/bin/fleet-board tail 30
sudo -u ctifleet /home/ctifleet/fleet/bin/fleet-board read @you

# Ask the fleet something directly
sudo -u ctifleet bash -c 'cd ~/fleet && claude "what P1s are open and unremediated?"'

# Force a digest now (dry run first, always)
sudo -u ctifleet /home/ctifleet/fleet/bin/run-digest daily --dry-run

# Query findings
sudo -u ctifleet /home/ctifleet/fleet/bin/fleet-db findings --priority P1
sudo -u ctifleet /home/ctifleet/fleet/bin/fleet-db findings --stale-days 7
```

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403` on sendMail | `Mail.Send` missing or unconsented | `mailer.py --check` shows actual token roles |
| `403` with `MailboxNotEnabled` | Application Access Policy excludes the mailbox | `Test-ApplicationAccessPolicy` |
| Enrich takes ~5 min | No NVD API key → 5 req/30s | Free key at nvd.nist.gov/developers/request-an-api-key → 50 req/30s |
| Everything `UNKNOWN` | KB cache predates the CVEs, so the mapping is missing | The agent now auto-refreshes past `QUALYS_KB_MAX_AGE_HOURS`. To force it: delete the cache JSON and rerun (the full build is large). A stale-cache UNKNOWN says "coverage UNVERIFIED" in its reason; a real one says "No Qualys KnowledgeBase mapping" |
| Digest didn't arrive | Timer disabled, or already-sent guard tripped | `systemctl status cti-fleet-digest`; `fleet-db was-sent $(date +%F) daily` |
| Duplicate digest | Clock change or manual run after the timer | The guard is per `(kind, day)` — check the `digests` table |
| Heartbeat never runs | `claude` not found, or not authenticated as the service account | `journalctl -u cti-fleet-checkin`; run `sudo -u ctifleet -i claude doctor`; pin `CLAUDE_BIN` |
| Every other beat skipped | Stale `.checkin.lock` from a killed beat | `rmdir ~/fleet/.checkin.lock` (auto-breaks after 30m) |
| Board not growing | Stale lock | `rmdir ~/fleet/.board.lock` (auto-breaks after 60s) |
| Scout finds nothing | Feeds 404'd | `logs/scout.log` names failed feeds; a dead feed is a blind spot that looks like good news |

---

## Rollout — one primitive at a time

The fleet guide's advice applies here: don't stand up all four lanes on day one.

**Week 1 — pipeline only.** Install, run `run-digest daily --dry-run` by hand,
read the HTML yourself. Confirm the P1/P2 calls match your judgment. Tune the
thresholds in `enrich.py::prioritize()` before anyone else sees the output. A
digest that cries wolf in week one gets filtered forever.

**Week 2 — auto-send.** Enable `cti-fleet-digest.timer`. Only the daily. Leave
scout off; you want to know the mailbox path is solid before adding a second
source of CVEs.

**Week 3 — heartbeat.** Set `FLEET_OPERATOR_EMAIL` and enable
`cti-fleet-checkin.timer`. Now an orchestrator is doing proactive work between
digests: chasing UNKNOWNs, nudging stale P1s, and emailing you when it needs a
decision. Watch `checkin.log` for a few days and judge whether its proactive
picks are useful or busywork.

**Week 4 — scout.** Enable `cti-fleet-scout.timer` after trimming `feeds.txt` to
vendors you actually run. Expect a noisy first sweep as it backfills; the dedupe
against `findings` and `scout_items` settles it within a day.

**Later — a fifth lane, when a bottleneck forces it.** The obvious next one is
asset/exposure correlation: map hostnames to owners and criticality so a P1 on a
database server routes differently than one on a workstation. A real report puts
servers, laptops and Macs across several domains in one flat list, and sorting
that by hand gets old fast. Add the lane when you catch yourself doing it, not
before.

---

## Adapting it

**A different scanner.** Presence is decided by the Go agent's
`vulnlookup.LookupProvider` interface, so swapping Qualys for CrowdStrike,
Defender, Tenable or Rapid7 is a change upstream in the Go code, not in the
fleet. The lanes only ever see `PRESENT` / `NOT_PRESENT` / `UNKNOWN` plus
normalized evidence, so nothing here needs to know which scanner answered.

**A different mail transport.** `lanes/mailer.py` is the only component that
sends. Swap Graph for SMTP by replacing `token()` and `graph_post()` — keep the
`FLEET_ALLOW_TO` allowlist and the `--approve` gate, since those are the control,
not the transport.

**A chat channel instead of email.** The orchestrator reaches you by email and
nothing else — one transport, one allowlist, one thing to audit. Adding Teams,
Slack, or SMS means a second sender in `mailer.py`'s place; keep the
`FLEET_ALLOW_TO` gate and the `--approve` flag wherever it lands, since those
are the control and the transport is not.

Note if you reach for Teams: Microsoft retired Office 365 connectors in Teams
between 18–22 May 2026, so `outlook.office.com/webhook/...` URLs no longer
work. The current mechanism is a Power Automate **Workflows** webhook with an
Adaptive Card payload, and it is one-way — replies would still have to come
back by another route.

---

## Upstream changes worth making

Both remove parsing fragility from the fleet.

**1. Emit JSON alongside markdown.** `enrich.py` parses the markdown report
table, which works, but it's a regex contract that breaks the day a column is
added. A `REPORT_JSON_PATH` env var writing `[]vulnlookup.Result` straight out
of `main.go` would be roughly 15 lines in `internal/report/`, and `enrich.py`
would read it directly instead.

**2. Port the mailer to Go.** `lanes/mailer.py` implements the "email the report
to a distribution list" feature request, but in Python. The same logic ports to
Go using the token already fetched in `internal/graph`; the endpoint is
`POST /users/{mailbox}/sendMail`. Worth doing alongside the Docker packaging
request, since one binary containerizes more cleanly than a binary plus four
Python lanes.

---

## Sources

- [Build Your Own Claude Code Agent Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet) — orchestrator/executor/heartbeat/board pattern
- [How agent memory works](https://www.limitededitionjonathan.com/docs/how-agent-memory-works) — the companion memory deep-dive
- [NVD API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) · [FIRST EPSS](https://api.first.org/data/v1/epss) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
