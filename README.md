# CTI Agent Fleet

**An always-on junior analyst for a security team.** Every morning it reads the
advisories, asks your scanner which of those CVEs are *actually on your
machines*, and chases the open tickets. Every week it checks your web
applications and your domains. Every month it measures Patch Tuesday against
your estate. It has no sick days, no vacation and no Friday afternoon, and it
never says "all clear" about something it did not check.

**What lands in your inbox**

- A ranked daily digest of what is really exposed, with CISA KEV deadlines.
- A weekly web-application report, with one Jira ticket per application,
  assigned to its owner and carrying the scanner's fix text (and, if you turn
  it on, the scanner's own report).
- The exact DNS changes IT needs to make, filed as a single ticket.
- A monthly Patch Tuesday synopsis, built from Microsoft's own data.

**Why you can trust it.** Every claim comes from the system that owns it:
presence only from the scanner, registration only from the registrar, a
release's contents only from Microsoft. The report says plainly what it could
not check, because a report that cannot tell "we looked and found nothing" from
"we never looked" will publish the reassuring one. The reports are written by
plain, deterministic code. AI only supervises: the orchestrator that watches
the lanes can read and escalate, and is not given the runners or the mailer.
Email goes only to allowlisted audiences, tickets only to an allowlisted
project, and anything else waits for a person's approval. It does the legwork;
people make the calls.

**Built to be reused.** Each chore is a *lane*: a small program on a systemd
timer that gathers facts, decides what matters and writes it up for the right
people. Today's lanes are threat intel, Jira follow-through, Patch Tuesday,
application security, domains, and housekeeping. Adding a lane for the next
tedious thing is the point: [AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md) is
the recipe. It works with Qualys, Jira, Microsoft 365 and GoDaddy today, and
the scanner, registrar and ticketing tool sit behind swappable Go interfaces:
[INTERFACES.md](INTERFACES.md) shows where to plug yours in. Standard library
only, no dependencies, one box. It started as a counter-threat-intelligence
digest, which is where the name comes from.

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
| **see what is planned**, and what is only an idea | **[BACKLOG.md](BACKLOG.md)** |
| **swap in a different scanner, registrar or ticketing tool** - every Go interface the fleet is built on, how complete each one is, and where new ones could go | **[INTERFACES.md](INTERFACES.md)** |
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

**A weekly AppSec report.** Fridays, to a separate list — the people who own
application code, not the people who patch servers, and the split is enforced
in code. Built from the DAST scanner's own scan-completion mail (Qualys WAS
today, any scanner behind `internal/appscan`) plus its API for per-finding
detail. Open counts per application, what is new since the last scan, and a
label on every count saying whether that scan logged in. A scanner credential
that stops working alerts the operator rather than the developers. Each
application's Jira ticket can also carry the scanner's own report as an
attachment (off by default, `WAS_ATTACH_REPORT=1`), and lists the scanner's
unconfirmed Critical and Urgent findings in a separate "please verify" section.

**A weekly domains check.** Tuesdays, security team only. For every domain in an
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

**A tidy mailbox.** Mail the lane that owns it has read goes to Archive (CTI
advisories after the digest, Qualys WAS scan notices after the AppSec weekly),
automatic replies to Deleted Items, and *everything else is left exactly where
it is.*

**Noise when something breaks.** A failed unit emails the operator and posts to
the message board, because the whole premise is that a quiet inbox means a
quiet day — which only holds if a broken pipeline is loud.

---

## The design pattern

If you want to understand *why* this is shaped the way it is — what an
orchestrator, executor lanes, a heartbeat, a message board and persistent
memory each contribute, and how they compose into something that does a job
rather than runs a task — read
**[AGENT-FLEET-PATTERN.md](AGENT-FLEET-PATTERN.md)**.

The pattern originates with [Build Your Own Claude Code Agent
Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet)
by Limited Edition Jonathan. This repository applies it to an information security 
team's needs.

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
