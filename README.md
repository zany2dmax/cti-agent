# CTI CVE Agent

A threat-intel agent fleet in Go and Python. It reads CTI advisories from a
shared Microsoft 365 mailbox, extracts CVEs, asks a vulnerability scanner which
of them are *actually present in the estate*, and mails a prioritised digest
every morning — plus a monthly Microsoft Patch Tuesday synopsis, CISA KEV
deadline tracking, and a cleanup lane that keeps the mailbox tidy without
touching anything a human still needs to see.

The organising principle: **presence is determined only by the scanner.** CTI
email text provides urgency and context, never proof that a vulnerability
exists here. A report that cannot tell "we looked and found nothing" from "we
never looked" will publish the reassuring one, and most of the design exists to
prevent exactly that.

---

## Documentation map

| If you want to… | Read |
|---|---|
| **get it running**, from empty checkout to a box that mails every morning | **[RUNBOOK.md](RUNBOOK.md)** |
| understand *why* it is shaped this way — orchestrator, executor lanes, heartbeat, message board, persistent memory | **[AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md)** |
| the full fleet reference: every command, every setting, the schedule, troubleshooting | **[fleet-kit/README.md](fleet-kit/README.md)** |
| know what the always-on orchestrator is allowed to do, and what it must never do | [fleet-kit/fleet/CLAUDE.md](fleet-kit/fleet/CLAUDE.md) |
| the individual agent playbooks | [skills/](fleet-kit/fleet/skills/): [checkin](fleet-kit/fleet/skills/checkin/SKILL.md), [cti-digest](fleet-kit/fleet/skills/cti-digest/SKILL.md), [scout-sweep](fleet-kit/fleet/skills/scout-sweep/SKILL.md), [patch-tuesday](fleet-kit/fleet/skills/patch-tuesday/SKILL.md) |
| see what a report looks like before running anything | [examples/sample-report.md](examples/sample-report.md) |
| the story of a secret leak and what was done about it | [scripts/EXPOSURE-REMEDIATION.md](scripts/EXPOSURE-REMEDIATION.md) |

Quick jumps into the runbook: [Entra app
registration](RUNBOOK.md#1-microsoft-entra-app-registration) ·
[configuration](RUNBOOK.md#4-configuration) · [the two-box
workflow](RUNBOOK.md#7-the-two-box-workflow-mac-to-fedora) · [enabling
timers](RUNBOOK.md#9-enabling-the-timers-in-order) · [verifying a
run](RUNBOOK.md#12-verifying-a-run)

---

## What it produces

**A daily digest.** Reads the mailbox, extracts CVEs, asks the scanner what is
present, enriches with NVD CVSS, EPSS and CISA KEV, prioritises Sev5–Sev1, and
mails an HTML digest with the exploited-and-present findings at the top.

**A monthly Patch Tuesday synopsis.** Reads the Qualys and BleepingComputer
wrap-ups, correlates the release against Host Detection, and answers the
question neither public write-up can: what landed on *our* machines. One table
row per QID, the Qualys Detection Score, and the review's own QQL verbatim so
somebody can paste it into the console and see the same set.

**KEV deadline tracking.** CISA remediation deadlines, but only for CVEs the
scanner actually found in the estate — a deadline for something you do not have
is noise.

**A tidy mailbox.** Processed advisories to Archive, header-confirmed
auto-replies to Deleted Items, and *everything else left exactly where it is.*

**Noise when something breaks.** A failed unit emails the operator and posts to
the message board, because the whole premise is that a quiet inbox means a
quiet day — which only holds if a broken pipeline is loud.

---

## The six binaries

| Binary | Run by | Purpose |
|---|---|---|
| `cti-agent` | `run-digest`, or by hand | Reads the mailbox, extracts CVEs, asks the scanner what is present, writes markdown. Holds back CVEs already covered by a **sent** Patch Tuesday synopsis, and lists every one it held |
| `cti-alert` | systemd `OnFailure=` | Makes a failed unit loud. Always exits 0 — a non-zero exit would mark the *alerter* failed and make `systemctl --failed` misleading |
| `cti-budget` | `run-checkin`, before each beat | Rations the orchestrator's share of a shared Claude subscription: window and daily ceilings, exponential backoff after a rate limit |
| `cti-kev` | by hand, or a quiet heartbeat | CISA KEV remediation deadlines for CVEs the scanner actually found |
| `cti-patchtuesday` | `run-patchtuesday`, monthly | The Patch Tuesday synopsis: correlates the release against Host Detection using both the KnowledgeBase CVE→QID mapping **and** the QIDs Qualys publishes in the review's own QQL. One row per QID. Writes the release manifest the daily digest reads |
| `cti-mailbox` | `run-mailbox-cleanup`, daily | The only binary that **modifies** the mailbox. Dry-run unless `--for-real`. Needs `Mail.ReadWrite`; cannot permanently delete |

All six are stdlib-only. `go.mod` has no dependencies, and adding one would make
a C toolchain or a large generated tree a build-time requirement on the
deployment host.

```bash
task build              # all six into bin/
task test               # Go tests + Python lane tests
task ship               # fmt, build, test, lint, scan, gosec, govulncheck, then push
task --list             # everything else
```

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
cmd/cti-budget/                model-quota ledger for the orchestrator heartbeat
cmd/cti-kev/                   CISA KEV remediation deadline report
cmd/cti-patchtuesday/          monthly Microsoft Patch Tuesday synopsis
cmd/cti-mailbox/               daily mailbox cleanup (the only writer)

internal/config/               environment/config loading, per-command requirements
internal/fleetenv/             the single fleet.env reader every command uses
internal/cti/                  CTI parsing and CVE extraction
internal/graph/                Microsoft Graph mailbox reader, sendMail, move
internal/budget/               rolling-window and daily ceilings, backoff
internal/kev/                  deadline bands, present-only filtering
internal/patchtuesday/         release dates, source parsing, exposure, QQL, manifest
internal/mailbox/              processed-message log and the cleanup decision table
internal/report/               markdown report writer, hostname redaction
internal/vulnlookup/           provider-neutral lookup interface and result types
internal/vulnlookup/qualys/    Qualys implementation
internal/vulnlookup/crowdstrike/ placeholder for a future implementation
internal/vulnlookup/noop/      no scanner: exercises extraction only

fleet-kit/                     the always-on fleet (see fleet-kit/README.md)
fleet-kit/bin/dev-run          local pipeline runner: doctor/ingest/enrich/brief/send
fleet-kit/fleet/lanes/         enrich, scout, brief, mailer
fleet-kit/fleet/bin/           run-digest, run-checkin, run-patchtuesday,
                               run-mailbox-cleanup, fleet-board, fleet-db
fleet-kit/fleet/CLAUDE.md      the orchestrator's standing instructions
fleet-kit/fleet/skills/        /checkin, /cti-digest, /scout-sweep, /patch-tuesday
fleet-kit/fleet/systemd/       service + timer pairs, generic layout
fleet-kit/fleet/systemd-fedora/ same, FHS layout for Fedora/RHEL
fleet-kit/install.sh           generic installer, everything under one directory
fleet-kit/install-fedora.sh    FHS installer: /opt, /etc, /var/lib
fleet-kit/tests/               lane tests (stdlib unittest, no network)
scripts/                       history scrub + exposure remediation notes
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
- Pagination and QID batching for very large Qualys environments
- A container image for deployment
