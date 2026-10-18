# CTI Agent Fleet

**An always-on junior analyst for a security team.** It does the recurring,
tedious work that has to happen every day, every week or every month - read
the mail, check the scanner, chase the tickets, look over the domains, write up
Patch Tuesday - on schedule, without being reminded, and without a sick day, a
vacation or a Friday afternoon. It started as a counter-threat-intelligence
digest, which is where the name comes from; it is now a general way to hand
routine security chores to software and get a report a person can act on.

Each chore is a **lane**: a small, deterministic program on a systemd timer
that gathers facts, decides what matters, and writes it up for the right
people. Today's lanes:

- **Threat intel, daily and weekly** - reads the CTI advisories that land in a
  shared Microsoft 365 mailbox, pulls out the CVEs, asks the vulnerability
  scanner which are *actually present* here, and mails a prioritised digest
  with CISA KEV deadlines.
- **Jira follow-through** - files one ticket per confirmed KEV or critical
  exposure, re-checks every open ticket against the scanner each morning, says
  when the hosts are clean, and lists every ticket's status in the daily.
- **Patch Tuesday** - a monthly synopsis of Microsoft's release from
  Microsoft's own data, measured against what the scanner sees on our machines.
- **Application security** - a weekly roll-up of the web-application scanner's
  findings for the people who own the code.
- **Domains** - a weekly check of every domain we own: registrar expiry and
  locks, what is in the registrar account but not on our list, which domains
  have a live website, TLS, and whether each domain's mail records match what
  it is for - with the exact DNS changes filed for IT as one ticket.
- **Housekeeping** - keeps the shared mailbox tidy, alerts the operator when
  any lane fails, and an orchestrator heartbeat that watches the lanes and
  escalates what it cannot settle on its own.

Adding a lane for the next tedious thing is the point:
[AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md) is the recipe.

It behaves like a careful junior analyst rather than an autonomous one.
**Every claim has a source**: presence comes only from the scanner, registration
only from the registrar, a release's contents only from Microsoft, and the
report says plainly what it could not check - because a report that cannot
tell "we looked and found nothing" from "we never looked" will publish the
reassuring one. **It does the legwork; people make the calls**: email goes only
to allowlisted audiences, tickets only to an allowlisted project, anything else
waits for a human's approval. No lane needs a model to write its report, and
the AI orchestrator that watches them can read and escalate but is not given
the runners or the mailer. Go throughout, with Python only where a standard-library SQL
driver is needed - [why that split is a security
decision](SECURITY.md#why-two-languages-and-why-that-is-the-security-decision).

---

## Documentation map

| If you want to… | Read |
|---|---|
| **explain it to someone in one page** — each lane, when it runs, whether it uses AI | **[LANES.md](LANES.md)** |
| **understand what this is and why, in two pages, with diagrams** — start here | **[ARCHITECTURE.md](ARCHITECTURE.md)** |
| **get it running**, from empty checkout to a box that mails every morning | **[RUNBOOK.md](RUNBOOK.md)** |
| **check it is up and working** from an SSH session: health, version, timers, dry runs, logs | **[CHEATSHEET.md](CHEATSHEET.md)** — `task cheatsheet:pdf` prints it to `CHEATSHEET.pdf` |
| understand *why* it is shaped this way — orchestrator, executor lanes, heartbeat, message board, persistent memory | **[AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md)** |
| the full fleet reference: every command, every setting, the schedule, troubleshooting | **[fleet-kit/README.md](fleet-kit/README.md)** |
| **one command's every flag, environment variable, file and exit code** | **[man/man1/](man/man1/)** — `man cti-domains` on the box; `man ./man/man1/cti-domains.1` in a checkout. Conventions: [man/STYLE.md](man/STYLE.md) |
| know what the always-on orchestrator is allowed to do, and what it must never do | [fleet-kit/fleet/CLAUDE.md](fleet-kit/fleet/CLAUDE.md) |
| the individual agent playbooks | [skills/](fleet-kit/fleet/skills/): [checkin](fleet-kit/fleet/skills/checkin/SKILL.md), [cti-digest](fleet-kit/fleet/skills/cti-digest/SKILL.md), [scout-sweep](fleet-kit/fleet/skills/scout-sweep/SKILL.md), [patch-tuesday](fleet-kit/fleet/skills/patch-tuesday/SKILL.md) |
| the non-CVE triage agent's standing instructions, and the org profile it reads | [fleet-kit/fleet/agents/triage/](fleet-kit/fleet/agents/triage/): [CLAUDE.md](fleet-kit/fleet/agents/triage/CLAUDE.md), [ORG-PROFILE-TEMPLATE.md](fleet-kit/fleet/agents/triage/ORG-PROFILE-TEMPLATE.md) — the filled-in profile lives at `/etc/cti-agent/ORG-PROFILE.md` and is gitignored. **Extraction is built; the agent is not yet wired in** |
| **the threat model** — trust boundaries, why the AI triage agent is separate and has no tools, credential handling, the send gate, known gaps | **[SECURITY.md](SECURITY.md)** |
| **know what changed and what an upgrade asks of you**, and how to ask a deployed box its version | **[CHANGELOG.md](CHANGELOG.md)** |
| see what a report looks like before running anything | [examples/sample-report.md](examples/sample-report.md) |

Quick jumps into the runbook: [Entra app
registration](RUNBOOK.md#1-microsoft-entra-app-registration) ·
[configuration](RUNBOOK.md#4-configuration) · [the two-box
workflow](RUNBOOK.md#7-the-two-box-workflow-mac-to-fedora) · [enabling
timers](RUNBOOK.md#9-enabling-the-timers-in-order) · [verifying a
run](RUNBOOK.md#12-verifying-a-run) · [taking a host off the
schedule](RUNBOOK.md#11e-taking-a-host-off-the-schedule) · [known
gaps](SECURITY.md#known-gaps-and-accepted-risks)

---

## What it produces

**A daily digest.** Reads the mailbox, extracts CVEs, asks the scanner what is
present, enriches with NVD CVSS, EPSS and CISA KEV, prioritises Sev5–Sev1, and
mails an HTML digest with the exploited-and-present findings at the top. A
FLEET TICKETS section lists every open fleet ticket in Jira (and those closed
in the last 30 days) with its status, the hosts the scanner sees today and what
that morning's re-check did.

**A monthly Patch Tuesday synopsis.** Reads Microsoft's own release data,
cross-checks it against BleepingComputer (and the Qualys blog when it can be
read), correlates the release against Host Detection, and answers the question
neither public write-up can: what landed on *our* machines. One table row per
QID, the Qualys Detection Score, and the Qualys review's own QQL verbatim (when
the review was read) so somebody can paste it into the console and see the
same set. **Run by hand for now:** both article sites refuse the server, so the
operator saves the two articles into the release's inbox folder and starts the
run ([CHEATSHEET.md](CHEATSHEET.md) section 7a); the timer stays disabled.

**A weekly AppSec report.** Mondays, to a separate list — the people who own
application code, not the people who patch servers, and the split is enforced
in code. Built from the DAST scanner's own scan-completion mail (Qualys WAS
today, any scanner behind `internal/appscan`) plus its API for per-finding
detail. Open counts per application, what is new since the last scan, and a
label on every count saying whether that scan logged in. A scanner credential
that stops working alerts the operator rather than the developers.

**A weekly domains check.** Mondays, security team only. For every domain in an
operator-maintained inventory (`/etc/cti-agent/domains.txt`, never in this
repository): still registered in the GoDaddy account, and is the account
holding domains nobody listed (INVENTORY vs GODADDY); which domains have a live
website (WEBSITES); does the certificate verify; and do the mail records match
the domain's row in the security team's decision chart, chosen by markers in
the inventory (`send`, `receive`, `saas`, `unknown`, `legacy`; no marker means
no mail at all) — a sender needs SPF, DKIM and an enforcing DMARC, a domain
with no mail must publish `v=spf1 -all`, `p=reject` and a null MX so nobody can
send as it. The difference is listed as DNS CHANGES FOR IT and filed as one
Jira lock-down ticket per run. Then what changed since last week. A failed DNS
lookup is reported as *not checked*, never as a missing record.

**KEV deadline tracking.** CISA remediation deadlines, but only for CVEs the
scanner actually found in the estate — a deadline for something you do not have
is noise.

**A tidy mailbox.** Processed advisories to Archive, header-confirmed
auto-replies to Deleted Items, and *everything else left exactly where it is.*

**Noise when something breaks.** A failed unit emails the operator and posts to
the message board, because the whole premise is that a quiet inbox means a
quiet day — which only holds if a broken pipeline is loud.

---

## The ten binaries

| Binary | Run by | Purpose |
|---|---|---|
| `cti-agent` | `run-digest`, or by hand | Reads the mailbox, extracts CVEs, asks the scanner what is present, writes markdown. Holds back CVEs already covered by a **sent** Patch Tuesday synopsis, and lists every one it held |
| `cti-alert` | systemd `OnFailure=`, and `run-appscan` | Makes a failed unit loud. Always exits 0 — a non-zero exit would mark the *alerter* failed and make `systemctl --failed` misleading |
| `cti-appscan` | `run-appscan`, weekly | The application-security report, from the DAST scanner's own completion emails. Labels every count *authenticated* or *unauthenticated* scan, because a zero from a scan that never logged in is not the same number. Raises a fault only when a configured credential **failed**, or a scan did not finish |
| `cti-domains` | `run-domains`, weekly | The domains check: registrar (read-only GoDaddy token, never auth codes), DNS, web, verified TLS, and mail posture by role, diffed against last week's state. Sends nothing; chained to `cti-mailer --lane dom`. `--actions-out` writes the DNS changes for `cti-jira --domains-actions` |
| `cti-budget` | `run-checkin`, before each beat | Rations the orchestrator's share of a shared Claude subscription: window and daily ceilings, exponential backoff after a rate limit |
| `cti-kev` | by hand, or a quiet heartbeat | CISA KEV remediation deadlines for CVEs the scanner actually found |
| `cti-patchtuesday` | `run-patchtuesday`, monthly (by hand for now) | The Patch Tuesday synopsis from Microsoft's release data (MSRC API), cross-checked against BleepingComputer: correlates the release against Host Detection using both the KnowledgeBase CVE→QID mapping **and** the QIDs Qualys publishes in the review's own QQL. One row per QID. Writes the release manifest the daily digest reads |
| `cti-mailer` | every lane, and by hand | The **single outbound channel**. Holds the `VM_ALLOW_TO` recipient gate, which covers Cc as well as To. `--check` decodes the token and reports the roles the tenant actually consented to. `--to-dev` sends a preview to `FLEET_DEV_EMAIL` only, subject prefixed `[DEV TEST]`. A port of `mailer.py`; see [SECURITY.md](SECURITY.md#why-two-languages-and-why-that-is-the-security-decision) |
| `cti-mailbox` | `run-mailbox-cleanup`, daily | The only binary that **modifies** the mailbox. Dry-run unless `--for-real`. Needs `Mail.ReadWrite`; cannot permanently delete. Archives the fleet's own reports only when their `X-CTI-Agent-Sent` header carries a valid signature |
| `cti-jira` | `run-digest`, between enrich and brief; `run-domains`, after the send | Files one Jira ticket per confirmed KEV or Sev5 CVE, with every QID and host, and tracks it by a label on the ticket so the same CVE is never ticketed twice. `--domains-actions` files the domains lane's DNS changes as one lock-down ticket, commenting on the open one only when the list changed. Writes nothing — no ticket, comment or attachment — without `--for-real` and a project in `JIRA_ALLOW_CREATE` |

All ten are stdlib-only. `go.mod` has no dependencies, and adding one would make
a C toolchain or a large generated tree a build-time requirement on the
deployment host.

```bash
task build              # all ten into bin/
task test               # Go tests + Python lane tests
task ship               # fmt, build, test, lint, scan, gosec, govulncheck, then push
task --list             # everything else
```

Go is gated by `gofmt`, `go vet`, `staticcheck`, `golangci-lint`, `gosec` and
`govulncheck`. The Python lanes are gated by their own unit tests and a syntax
check — **no linter, formatter, type checker or security scanner**. That
asymmetry is known and tracked in
[SECURITY.md → known gaps](SECURITY.md#known-gaps-and-accepted-risks).

---

## Design decisions worth knowing

These are the ones that will surprise you if you read the code without them.

**Presence comes only from the scanner.** An advisory saying a CVE is exploited
is context. Whether it is *here* is a separate question with a separate source,
and the report never conflates them. Every CVE comes back as one of
`PRESENT`, `NOT_PRESENT` or `UNKNOWN` — and `UNKNOWN` is load-bearing: it means
the scanner had no answer, not that the estate is clean.

**A QID is the unit of work, not a CVE.** Qualys maps every CVE in a monthly
cumulative update to the same QID, so 353 "present" CVEs can be twelve missing
patches. Keyed by CVE, the Patch Tuesday table was 353 rows stating one fact
hundreds of times; keyed by QID it is a dozen rows that each mean *patch this*.

**The vendor's own query leads.** The QQL Qualys publishes with each review,
reproduced byte-for-byte, returns every QID in the release with assets against
it. A query built from whatever this lane managed to correlate is a subset, and
is labelled as one.

**Four states, not three.** Exposure distinguishes "not measured" (the scanner
was never reached) from "not yet measurable" (no QID mapping exists yet) from
"measured, nothing open" from a real finding. An early version printed a
confident diagnosis of a KnowledgeBase it had never contacted.

**Suppression requires evidence.** The daily digest holds back a Patch Tuesday
release's CVEs only when a manifest says that synopsis was *delivered* — never
on a heuristic about vendors and dates, and never on a manifest from a run
whose email failed.

**Mailbox cleanup leaves things alone by default.** Only two kinds of message
ever move: an advisory the agent took a CVE from, and a message whose own
headers declare it an automatic reply. "The agent read it looking for CVEs and
found none" is not "this has been dealt with."

**Nothing can permanently delete mail.** `internal/graph` exposes
move-to-folder and nothing else; Graph's `DELETE` and purge endpoints are
deliberately not implemented.

**Every failure falls open.** A missing manifest, an unreadable state file, an
absent `FLEET_HOME` — each means *report more*, never *report less*. The
recurring bug in this system was never a crash; it was a check that ran and had
no effect, or a refusal indistinguishable from a quiet day.

**Reports are targeting lists.** They pair "exploitable" with "these machines",
are written `0600`, are gitignored, and go only to an allowlisted internal
distribution list. See [RUNBOOK → Report
sensitivity](RUNBOOK.md#13-report-sensitivity).

---

## The lookup provider boundary

The important abstraction is `internal/vulnlookup.LookupProvider`:

```go
type LookupProvider interface {
    Name() string
    LookupCVE(ctx context.Context, cve string) (Result, error)
}
```

The rest of the app does not know whether a CVE was checked in Qualys,
CrowdStrike or something else. Provider-specific identifiers like Qualys QIDs
come back as normalised `ExternalIDs`.

| Provider | State |
|---|---|
| **Qualys VMDR** | Implemented. Two-step: a local KnowledgeBase cache mapping `CVE → QID[]`, then Host Detection List for active detections |
| **CrowdStrike** | Placeholder at `internal/vulnlookup/crowdstrike`; returns `UNKNOWN` until a real lookup is added |
| **noop / none** | Exercises mailbox reading and CVE extraction without calling a scanner. Useful for separating two failures that otherwise look identical |

### Adding another

1. Create a package under `internal/vulnlookup/<provider>`.
2. Implement `Name()` and `LookupCVE(ctx, cve)`.
3. Return normalised `vulnlookup.Result` values.
4. Add the provider to `buildLookupProvider()` in `cmd/cti-agent/main.go`.
5. Add provider-specific config to `internal/config` only if needed.

### The application-security boundary

The weekly AppSec lane is built the same way, around `internal/appscan`. The
rest of the lane works with normalised `appscan.ScanResult` and
`appscan.Finding` values - application, scan, authentication state, counts by
severity, per-finding detail - and does not know which web-application
scanner produced them. Two interfaces, deliberately separate:

```go
// Provider parses one vendor's scan-completion notification email.
// No credentials needed: a new scanner is useful the day its email arrives.
type Provider interface {
    Name() string
    Recognises(sender, subject string) bool
    Parse(body string) (ScanResult, []string) // result, plus problems worth reporting
}

// DetailFetcher is the optional half, for providers with an API:
// per-finding detail for a scan's application.
type DetailFetcher interface {
    Findings(ctx context.Context, s ScanResult, since time.Time) ([]Finding, error)
}
```

Keeping them apart means the counts in the report come from the email alone
and survive an API outage, an expired credential, or a scanner that has no API
at all; detail is added when it can be fetched and its absence is stated, never
read as "nothing found".

| Provider | State |
|---|---|
| **Qualys TotalAppSec (Web Application Scanning)** | Implemented in `internal/appscan/qualys`. `Provider` parses the WAS completion notification (`qualys-was`); `*qualys.API` implements `DetailFetcher` from the WAS Findings API, and adds a scan-list reconciliation that supplies the application's stable ID and flags scans whose notification never arrived |
| **Others** (Invicti, Burp, ...) | Not yet. `ScanResult.Provider` is already a free-form key, and the renderer is provider-neutral |

What is still Qualys-specific: `cmd/cti-appscan` calls the Qualys scan-list
reconciliation and detail fetch directly, for scans whose provider is
`qualys-was`. A second scanner's detail would go through `DetailFetcher` the
same way; reconciliation against a scan list is an optional extra a provider
with such an API can add.

#### Adding another scanner

1. Create `internal/appscan/<provider>` and implement `Provider` against the
   vendor's completion email: `Recognises` from sender and subject, `Parse`
   returning a normalised `ScanResult` with `Provider` set to its key.
2. Add it to the `providers` list in `cmd/cti-appscan/main.go`. The email path
   is complete at this point - counts, authentication state, attention.
3. If the vendor has an API, implement `DetailFetcher` for per-finding detail
   and call it in `attachDetail` for that provider's scans.
4. Credentials, if any, go in `internal/config` and `fleet.env`.

---

## The design pattern

If you want to understand *why* this is shaped the way it is — what an
orchestrator, executor lanes, a heartbeat, a message board and persistent
memory each contribute, and how they compose into something that does a job
rather than runs a task — read
**[AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md)**.

The pattern originates with [Build Your Own Claude Code Agent
Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet)
by Limited Edition Jonathan. This repository applies it to threat intel.

---

## Project layout

```text
cmd/cti-agent/                 the agent: mailbox -> CVEs -> scanner -> markdown
cmd/cti-alert/                 failure alerter, invoked by systemd OnFailure=
cmd/cti-appscan/               weekly application-security report from DAST email
cmd/cti-domains/               weekly domains check: registrar, DNS, web, mail records
cmd/cti-budget/                model-quota ledger for the orchestrator heartbeat
cmd/cti-jira/                  files and updates one ticket per KEV or Sev5 CVE
cmd/cti-kev/                   CISA KEV remediation deadline report
cmd/cti-mailbox/               daily mailbox cleanup (the only writer)
cmd/cti-mailer/                the single outbound channel, and the recipient gate
cmd/cti-patchtuesday/          monthly Microsoft Patch Tuesday synopsis

internal/config/               environment/config loading, per-command requirements
internal/fleetenv/             the single fleet.env reader every command uses
internal/version/              the build stamp every command reports
internal/safelog/              makes attacker-influenced text safe for a log record
internal/cti/                  CTI parsing and CVE extraction
internal/graph/                Microsoft Graph mailbox reader, sendMail, move
internal/mailer/               per-lane recipient resolution and allowlist references
internal/budget/               rolling-window and daily ceilings, backoff
internal/kev/                  deadline bands, present-only filtering
internal/jira/                 Jira client and the one-ticket-per-CVE policy
internal/patchtuesday/         release dates, source parsing, exposure, QQL, manifest
internal/mailbox/              processed-message log and the cleanup decision table
internal/report/               markdown report writer, hostname redaction
internal/triage/              deterministic extractor, and the verifier over model JSON
internal/defender/             Defender for Cloud attack-path notification parsing
internal/safelink/             Proofpoint/redirector unwrapping with a host allowlist
internal/shellgate/            shell lint: the patterns that make a runner exit quietly
internal/appscan/              DAST boundary: scan results, auth state, the report
internal/appscan/qualys/       Qualys WAS: notification parser and Findings API
internal/domains/              inventory, probes, findings by role, week-over-week diff
internal/domains/godaddy/      GoDaddy domain list (read-only PAT, never auth codes)
internal/vulnlookup/           provider-neutral lookup interface and result types
internal/vulnlookup/qualys/    Qualys implementation
internal/vulnlookup/crowdstrike/ placeholder for a future implementation
internal/vulnlookup/noop/      no scanner: exercises extraction only

man/man1/                      a man page for every operator command

fleet-kit/                     the always-on fleet (see fleet-kit/README.md)
fleet-kit/bin/dev-run          local pipeline runner: doctor/ingest/enrich/brief/send
fleet-kit/fleet/lanes/         enrich, scout, brief, mailer
fleet-kit/fleet/bin/           run-digest, run-checkin, run-patchtuesday,
                               run-appscan, run-domains, run-mailbox-cleanup,
                               fleet-board, fleet-db
fleet-kit/fleet/CLAUDE.md      the orchestrator's standing instructions
fleet-kit/fleet/skills/        /checkin, /cti-digest, /scout-sweep, /patch-tuesday
fleet-kit/fleet/systemd/       service + timer pairs, generic layout
fleet-kit/fleet/systemd-fedora/ same, FHS layout for Fedora/RHEL
fleet-kit/install.sh           generic installer, everything under one directory
fleet-kit/install-fedora.sh    FHS installer: /opt, /etc, /var/lib
fleet-kit/tests/               lane tests (stdlib unittest, no network)
scripts/                       history scrub, exposure remediation notes,
                               cheatsheet-pdf.py (task cheatsheet:pdf)
```

---

## Two ways to run this

**The agent alone.** Build it, point it at a mailbox, get a markdown report. No
systemd, no service account. [RUNBOOK → The agent
alone](RUNBOOK.md#5-the-agent-alone).

**The agent inside the fleet** (`fleet-kit/`). An always-on orchestrator plus
executor lanes that add exploitability context, prioritise Sev5–Sev1, render the
HTML digest and mail it on a schedule. [RUNBOOK → Installing the
fleet](RUNBOOK.md#8-installing-the-fleet), and
[fleet-kit/README.md](fleet-kit/README.md) for the complete reference.

---

## Ideas not yet built

- More scanner providers — Defender, Tenable, Rapid7 — behind the same interface
- Qualys severity bands beside the QDS number, once the thresholds are verified
  against Qualys' own documentation rather than guessed
- A container image for deployment
- AppSec lane fully provider-neutral: `cmd/cti-appscan` fetching detail through
  `appscan.DetailFetcher` (and scan-list reconciliation as an optional provider
  capability) instead of calling the Qualys API type directly
- Message trace for the domains lane: which domains actually send mail and from
  where, on a separate read-only app registration
- Domains lane reads mail roles from Proofpoint: which domains Proofpoint
  accepts mail for (receive) and relays outbound for (send), from its API
  with a read-only credential, instead of hand-kept `send` / `receive`
  markers in `domains.txt`. The file would keep the markers no mail system
  knows (`saas`, `legacy`, `unknown`) and act as an override, and the report
  would flag where the file and Proofpoint disagree. First check which
  Proofpoint product is in use and whether its API exposes domain
  configuration
- The AI triage agent wired into the threat-intel digest, and a Defender for
  Cloud attack-path lane
