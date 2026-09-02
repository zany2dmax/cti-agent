# CTI Agent Fleet — Build Runbook

An always-on threat-intel fleet running on a Linux server, wrapping your existing
[`cti-qualys-agent`](https://github.com/zany2dmax/cti-qualys-agent) and mailing a
prioritized digest to **cybersecurity@crhomeusa.com**.

This applies the fleet pattern from [Build Your Own Claude Code Agent
Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet) —
orchestrator, executors, heartbeat, board, persistent memory — to a CTI workload
instead of a personal-assistant one.

---

## The idea in one paragraph

Your Go agent already does the hard part: read the CTI mailbox, pull CVEs, ask
Qualys whether you're actually exposed, write markdown. What it doesn't do is
decide what matters, or tell anyone. The fleet wraps it. An orchestrator wakes
every 30 minutes, three executor lanes add exploitability context and find CVEs
the mailbox missed, and a digest lands in the security inbox at 06:00 with P1
items at the top. Nobody has to remember to run anything, and nobody has to read
a 50-row table to find the four rows that matter.

---

## Architecture

```
LINUX SERVER · your Claude subscription · user: ctifleet
│
├── ORCHESTRATOR ─ the analyst on duty
│   /checkin every 30 min (systemd timer)
│   · reads the board, memory, lane logs
│   · relays questions to Jeff's phone (Telegram)
│   · fires lanes, decides what's worth sending
│   · THE ONLY AGENT THAT SENDS MAIL
│
├── @ingest   cti-qualys-agent (Go)   mailbox → CVEs → Qualys → markdown
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
                            cybersecurity@crhomeusa.com
```

Two things are worth calling out because they're where most fleets go wrong.

**Lanes never mail and never talk to Jeff.** They post to the board; the
orchestrator relays. One outbound channel means one place to audit and one place
where the recipient allowlist lives.

**Delivery doesn't depend on the LLM noticing the clock.** The 06:00 digest runs
from a plain systemd timer calling `bin/run-digest` — a deterministic shell
pipeline. The orchestrator's heartbeat does judgment work: chasing UNKNOWNs,
nudging stale P1s, correlating scout backlog. If the model has a bad day, the
digest still goes out. If the timer is disabled, the orchestrator notices on its
next beat and says so.

---

## Why P1–P4 instead of CVSS

CVSS answers "how bad is this vulnerability in the abstract," which is close to
useless for deciding what to do on a Tuesday. Your own sample report makes the
point: `CVE-2026-33829` is PRESENT on **305 hosts**, and `CVE-2022-0492` — a
container escape you almost certainly don't run — is NOT_PRESENT with 118 QIDs
of noise attached. Sorting by severity buries the first behind the second.

The enrich lane crosses **exploitability in the wild** with **presence in your
environment**:

| | Definition | What it means for you |
|---|---|---|
| **P1** | `PRESENT` with hosts > 0 **and** (on CISA KEV **or** EPSS ≥ 10%) | Being exploited right now, and you have it. Today. |
| **P2** | `PRESENT` with hosts > 0, any severity — or `UNKNOWN` on something with KEV / EPSS ≥ 50% | You have it, or you can't prove you don't. This patch cycle. |
| **P3** | Exploited or EPSS ≥ 10% but not detected here — or `UNKNOWN` with CVSS ≥ 9.0 | Verify your scan coverage actually reaches it. |
| **P4** | Everything else | Awareness. Suppressed from the daily; appears in the weekly. |

Three deliberate choices, all of which came out of testing this against your
committed sample report:

**Presence alone earns P2, regardless of CVSS.** The first cut gated P2 on
CVSS ≥ 7.0, which put `CVE-2026-45659` — present on **186 hosts**, CVSS 5.5 — in
P3, *below* a NOT_PRESENT CVE. That inverts the exact thing this scoring exists
to fix. If it's on your machines, it's a patching obligation.

**`UNKNOWN` + actively exploited lands in P2, and `UNKNOWN` + CVSS ≥ 9.0 lands
in P3.** In your sample, eight CVEs came back UNKNOWN because the Qualys
KnowledgeBase had no QID mapping. That is not "we're clean" — it's "we didn't
look." Letting missing data sink to P4 is the failure mode that shows up in a
post-incident review.

**Host count breaks ties before CVSS does.** A 6.5 on 305 hosts outranks a 9.8
on one.

**EPSS** (FIRST's Exploit Prediction Scoring System) is the probability a CVE
will be exploited in the next 30 days. Verified live against
`api.first.org/data/v1/epss`. **KEV** membership comes from NVD's
`cisaExploitAdd` field, with CISA's catalog feed layered on for the remediation
due date and ransomware association — so if the catalog fetch fails, KEV
detection degrades but doesn't disappear.

---

## Install

### Prerequisites

- Linux server that stays on. RHEL 8+/Ubuntu 22.04+, 2 vCPU / 4 GB is plenty.
- Python 3.9+ (stdlib only — no pip installs anywhere in this kit).
- Go 1.21+ *or* a prebuilt `cti-qualys-agent` binary.
- Claude Code installed at `/usr/local/bin/claude`, authenticated as your
  subscription user.
- Outbound HTTPS to: `login.microsoftonline.com`, `graph.microsoft.com`, your
  Qualys pod, `services.nvd.nist.gov`, `api.first.org`, `www.cisa.gov`, and
  whichever advisory feeds you keep in `feeds.txt`.

### Steps

```bash
# 1. Get the code onto the box
sudo mkdir -p /opt/cti-fleet && sudo chown $USER /opt/cti-fleet
# copy this cti-fleet/ directory to /opt/cti-fleet

# 2. Build the Go agent as the service user
sudo useradd -m -s /bin/bash ctifleet
sudo -u ctifleet git clone https://github.com/zany2dmax/cti-qualys-agent \
     /home/ctifleet/cti-qualys-agent
cd /home/ctifleet/cti-qualys-agent && sudo -u ctifleet go build -o cti-qualys-agent ./cmd/cti-qualys-agent

# 3. Install the fleet
cd /opt/cti-fleet && sudo ./install.sh

# 4. Fill in secrets
sudo -u ctifleet vi /home/ctifleet/fleet/fleet.env    # mode 600

# 5. Verify Graph permissions BEFORE trusting the 06:00 timer
sudo -u ctifleet python3 /home/ctifleet/fleet/lanes/mailer.py --check

# 6. Dry run the whole pipeline — renders and validates, sends nothing
sudo -u ctifleet /home/ctifleet/fleet/bin/run-digest daily --dry-run

# 7. Enable the timers
sudo systemctl enable --now cti-fleet-checkin.timer cti-fleet-digest.timer \
                            cti-fleet-weekly.timer cti-fleet-scout.timer
systemctl list-timers 'cti-fleet-*'
```

### Entra permissions

Your app registration currently has `Mail.Read` (Application). Add one:

| Permission | Type | Why |
|---|---|---|
| `Mail.Read` | Application | already there — read the CTI mailbox |
| `Mail.Send` | Application | **add this** — send the digest as the mailbox |

Entra ID → App registrations → your CTI app → API permissions → Add permission
→ Microsoft Graph → Application permissions → `Mail.Send` → **Grant admin
consent**. Consent is the step people skip; `mailer.py --check` decodes the
token and tells you exactly which roles are actually present.

Then scope it. `Mail.Send` as an application permission is tenant-wide by
default — that app could send as *any* mailbox in the tenant. Restrict it:

```powershell
New-ApplicationAccessPolicy -AppId <CLIENT_ID> `
  -PolicyScopeGroupId ctifleet-mailboxes@crhomeusa.com `
  -AccessRight RestrictAccess `
  -Description "CTI fleet: cybersecurity mailbox only"

Test-ApplicationAccessPolicy -Identity cybersecurity@crhomeusa.com -AppId <CLIENT_ID>
```

Do this even though it's optional. A leaked client secret that can send as
anyone in the company is a phishing platform; one scoped to a single mailbox is
a contained incident.

---

## Autonomy — where the gates are

You chose: **auto-send scheduled reports, gate everything else.** That's
enforced in three independent places, deliberately, because a prompt alone isn't
a control.

| Layer | Enforces |
|---|---|
| `CLAUDE.md` | The orchestrator's standing instructions — what it may and may not do |
| `mailer.py` recipient allowlist | `FLEET_ALLOW_TO` in `fleet.env`. Any recipient not on it **exits non-zero** unless `--approve` is passed. Not advisory. |
| systemd hardening | `ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths` limited to `~/fleet` |

**No approval needed:** running lanes; reading mailbox/Qualys/NVD/EPSS/KEV/feeds;
writing to memory, reports, logs, board; **sending the daily and Monday weekly
digests to the DL.**

**Approval required:** any off-cycle email, including an "urgent" one; any
recipient outside the allowlist; tickets, Qualys config, scan exceptions;
deleting anything outside logs and archive; touching a production host.

The P1 case is worth being explicit about, because it's the one you'll be
tempted to loosen. A new P1 does *not* buy the fleet an off-cycle blast. It
posts to the board tagged `[P1 APPROVE-TO-SEND]`, pings your phone, and waits
for you. It also guarantees the item leads the next scheduled digest regardless
of length. If you later decide P1s should auto-send, add
`cybersecurity@crhomeusa.com` to a separate `FLEET_P1_AUTO` path — don't just
widen the allowlist.

---

## Schedule

| When | What | Fired by |
|---|---|---|
| every 30 min | `/checkin` heartbeat — relay, decide, one proactive task | `cti-fleet-checkin.timer` |
| 06:00 daily | ingest → enrich → brief → **send** | `cti-fleet-digest.timer` |
| 00,04,08,12,16,20:15 | scout sweep + correlate new CVEs | `cti-fleet-scout.timer` |
| Mon 07:00 | weekly rollup, includes P4 | `cti-fleet-weekly.timer` |
| Sun 02:00 | Qualys KB refresh, vacuum, log rotate | orchestrator, on its beat |

All timers are `Persistent=true`, so a digest missed because the box was down
fires on boot. A silently skipped digest reads as "no news," which is the worst
possible failure for this system.

---

## What lands in the inbox

Subject lines are written to be triaged from a lock screen:

```
[P1] CTI Aug 18: 3 exploited vulns present in the environment
CTI Aug 18: 12 confirmed present, no P1
CTI Aug 18: no new CVEs in the last 24h
```

Body: a one-line lead telling you whether to care, P1/P2/P3/P4 count tiles, then
findings grouped by priority. Each one carries KEV/ransomware/CVSS/EPSS/status
badges, a plain-English "why it ranks here," the NVD description, and
deduplicated sample hostnames. Table-based layout with inline CSS, because
Outlook. The raw markdown report is attached for anyone who wants all 50 rows.

P4 is suppressed from the daily and appears in the weekly. P2 and P3 are capped
at 12 and 10 items on the daily, sorted by host count, with a "+N more in the
full report" note — the attachment has everything. If a run couldn't reach NVD
or EPSS, the digest carries an explicit **DEGRADED** banner naming what was
missing; a digest that hides its own gaps is worse than no digest.

A quiet day still sends. "No new CVEs in the last 24h" is signal; silence is
ambiguous with "the cron job died three weeks ago."

---

## Files

```
cti-fleet/
├── README.md                      this runbook
├── install.sh                     idempotent installer
└── fleet/
    ├── CLAUDE.md                  orchestrator standing instructions + autonomy gate
    ├── fleet.env.example           all config, superset of the Go agent's .env
    ├── bin/
    │   ├── fleet-board            lock-safe append-only board (post/read/prune/tail)
    │   ├── fleet-db               SQLite memory: findings, tasks, mailbox, digests
    │   └── run-digest             deterministic ingest→enrich→brief→send
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
```

---

## Operating it

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

# Force a digest now
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
| Everything `UNKNOWN` | Qualys KB cache empty or stale | Delete `state/qualys_kb_cache.json`, rerun; the first build is large |
| Digest didn't arrive | Timer disabled, or already-sent guard tripped | `systemctl status cti-fleet-digest`; `fleet-db was-sent $(date +%F) daily` |
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
scout off; you want to know that the mailbox path is solid before adding a
second source of CVEs.

**Week 3 — heartbeat.** Enable `cti-fleet-checkin.timer` and wire Telegram. Now
you have an orchestrator doing proactive work between digests: chasing UNKNOWNs,
nudging stale P1s. Watch `checkin.log` for a few days and see whether its
proactive picks are useful or busywork.

**Week 4 — scout.** Enable `cti-fleet-scout.timer` after trimming `feeds.txt` to
vendors you actually run. Expect a noisy first sweep as it backfills; the dedupe
against `findings` and `scout_items` settles it within a day.

**Later — a fifth lane, when a bottleneck forces it.** The obvious next one is
asset/exposure correlation: map hostnames to owners and criticality so a P1 on a
database server routes differently than one on a CAD workstation. A real report
puts servers, workstations and Macs across several domains in one flat list, and
sorting that by hand gets old fast. Add the lane when you catch yourself doing
it, not before.

---

## Two upstream changes worth making

Both are small, and both remove parsing fragility from the fleet.

**1. Emit JSON alongside markdown.** `enrich.py` currently parses your markdown
table, which works and is tested against your committed sample — but it's a
regex contract that breaks the day you add a column. A `REPORT_JSON_PATH` env
var writing `[]vulnlookup.Result` straight out of `main.go` would be maybe 15
lines in `internal/report/`, and `enrich.py` would read it directly. This is
already on your feature-request list in spirit.

**2. Your README lists "email the final report back to a distribution list" as a
feature request.** `lanes/mailer.py` is that, done, with an allowlist gate — but
in Python rather than Go. If you'd rather keep it single-binary, the same 60
lines port to Go easily using the token you already fetch in `internal/graph`;
the endpoint is `POST /users/{mailbox}/sendMail`. Worth doing if you also want
the Docker packaging from your feature list, since one binary containerizes more
cleanly than a binary plus four Python lanes.

---

## Sources

- [zany2dmax/cti-qualys-agent](https://github.com/zany2dmax/cti-qualys-agent) — the ingest lane
- [Build Your Own Claude Code Agent Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet) — orchestrator/executor/heartbeat/board pattern
- [How agent memory works](https://www.limitededitionjonathan.com/docs/how-agent-memory-works) — the companion memory deep-dive
- [NVD API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) · [FIRST EPSS](https://api.first.org/data/v1/epss) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
