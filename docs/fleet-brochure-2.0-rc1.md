# CR Agent Fleet 2.0

*Release candidate 1, November 2026*

## The always-on security analyst that never says "all clear" about something it didn't check.

Every morning it reads the threat intelligence and asks your scanner what's *actually on your machines*. Then it chases the tickets nobody closed. Every week it checks your web applications, your domains and your scan coverage. Every month it measures Patch Tuesday against your estate. It has no sick days, no vacation and no Friday afternoon.

**CR Agent Fleet does the legwork. Your people make the calls.**

---

## The problem

Security teams drown in recurring chores. Somebody has to:

- read every overnight advisory, work out which of those CVEs are actually on our machines, and rank them before the first meeting *(Daily Brief)*;
- go back to every open vulnerability ticket and check whether it was really fixed, everywhere *(Ticket follow-up)*;
- pull the week together, including the low-priority items nobody had time for on Tuesday *(Weekly Brief)*;
- watch vendor and government feeds for the advisories that never reached the mailbox *(Feed scout)*;
- read Patch Tuesday's hundred-odd fixes and work out which ones landed on *our* estate *(Patch Tuesday synopsis)*;
- tell the developers what the web application scanner found, and whether the scan even logged in *(AppSec report)*;
- send every website owner, most of whom have no Jira login, their own scan results *(Application owner reports)*;
- confirm every scheduled vulnerability scan actually ran, and find the networks no scan reaches *(VM scan report)*;
- read the supplier form that came in at 4:55 on Friday and decide whether it needs a third-party risk review *(Supplier requests)*;
- notice a lapsed registration, an expired certificate, or a domain anyone could send mail as *(Domains check)*;
- read an advisory that names no CVE and decide whether it affects us at all *(Advisory triage)*;
- keep the shared mailbox from burying the one email that matters *(Mailbox cleanup)*;
- notice when one of these jobs silently stops working *(Failure alert)*;
- keep an eye on all of the above, and chase what nobody resolved *(Analyst on duty)*.

None of it is hard. All of it is relentless. And the cost of skipping a day is invisible until it isn't.

## The answer: a fleet of lanes, supervised by an AI analyst

CR Agent Fleet is a set of focused, scheduled jobs called **lanes**. Each one gathers facts from the system that owns them, decides what matters, and writes it up for exactly the people who need to act. An AI **analyst on duty** watches over the whole fleet every two hours and chases anything nobody resolved.

**Reports are written by deterministic code. AI supervises and judges; it never delivers.** If the AI is down, every report still goes out on time.

---

## What lands in your inbox

### Threat intelligence that knows your estate

**The Daily Brief, every morning at 06:00.** The fleet:
- reads the overnight advisory mail and polls vendor and government feeds every four hours;
- extracts every CVE and asks the vulnerability scanner which are **present on your machines**;
- enriches each one with CVSS from NVD, EPSS exploit likelihood, and CISA KEV federal deadlines;
- ranks everything from **Sev5 (exploited *and* present)** down to Sev1.

The finding that matters is at the top, every time.

- **Tickets filed for you.** Every exploited or CVSS 9.0+ vulnerability that's confirmed present gets a Jira ticket carrying every affected host.
- **Tickets chased for you.** Each morning every open ticket is re-checked against the scanner. When new machines are affected, IT gets a comment, at most once a week and with the host list attached. When a vulnerability is fixed everywhere, IT is told the ticket can be closed. The fleet never closes or reopens a ticket itself; that's IT's call.
- **FLEET TICKETS:** one section listing every ticket every lane has filed, with its status, so nothing falls through the cracks.
- **KEV deadlines that matter:** federal remediation dates only for CVEs you actually have. A deadline for something you don't run is noise.
- **The Weekly Brief** rolls up the week, including the lower-priority items the dailies leave out.

**Advisory triage, "does this affect us?"** An advisory without a CVE used to be a dead end. Now the fleet reads it, extracts the vendors, products, versions and ATT&CK techniques, and checks them against **CrowdStrike Falcon**:
- installed applications, and how many hosts are below the fixed version;
- hosts that have seen the advisory's indicators;
- alerts naming its techniques.

A second AI judge weighs only those facts and must cite them. Code then checks every verdict. Any host that saw an indicator is reported first, whatever the AI says. Results appear in the Daily Brief as **FLEET ADVISORIES**.

**NEW in 2.0: the week's advisories in the Weekly Brief.** The weekly rolls up every daily's triage: what was seen on your hosts, then what was judged likely or possible, each with its day. It names any day triage didn't report, so a silent failure never passes for a quiet week, and it calls no model of its own.

**Shadow IT discovery.** `cti-falcon --new-apps` lists software that appeared in the estate for the first time: **the systems nobody told you about**. Each comes with host type, internet exposure, criticality and Falcon's suspicious-app flag.

### Patch Tuesday, measured against *your* machines

The morning after Microsoft's monthly release, one synopsis answers the question no public write-up can: **what landed on our machines?** It's built from Microsoft's own release data and cross-checked against independent news coverage. It shows one row per scanner detection with the detection score, plus the exact scanner query so anyone can reproduce the numbers in the console. *(For now, the operator saves the two news articles and starts the run, because both news sites block automated reads.)*

### Application security, delivered to the people who fix it

- **Results straight to each application's owner, by email, every day.** Most website owners are outside the company or have no Jira login, so the fleet doesn't make them go looking for a ticket. For every scan that finished, the owner and any watchers get the scanner's own report of what is open on their application, with the scan account's session details removed. Only allowlisted domains can receive these reports. A scan that failed, couldn't log in or reached no host is held back and the operator is told.
- **The weekly AppSec report** goes to the application developers, not the server team. It shows open findings per application, what's new since the last scan, and whether each scan actually logged in. A broken scanner login alerts the operator, not the developers.
- **An owners list that maintains itself.** `fleet-owners sync` asks the scanner which applications exist and flags every one with no owner, along with the exact command to fix it.
- **Coverage gaps are found for you.** Live websites with no application scan are listed in the weekly domains report.

### Scan coverage you can prove

**The weekly VM scan report** asks Qualys which scans ran and which *should* have, according to every active schedule. A scan that quietly stopped launching is named, even if nobody noticed. For each scan it shows:
- when it started and how long it took;
- how many addresses it scanned and how many were alive;
- which groups of addresses it covered.

Then it checks the **network team's subnet spreadsheet** against what the scans actually reached, address by address, and lists:
- **networks no scan reaches**;
- **spreadsheet rows that can't be read**;
- **clean-up the sheet needs**: overlapping networks, a public IP under two sites, misspelled decommissions;
- **oddities in the scanner**: scans spent on closed sites, address groups nothing targets.

Corrections go to the help desk as **one Jira ticket** for the network team, updated only when the list changes. A CSV worksheet comes with a column for the teams to explain each gap.

### Domain and email security

**The weekly domains check** covers every domain you own:
- **Registration:** is it still registered, and is the registrar account holding domains nobody is checking?
- **Website:** is it live, parked or broken, where does it redirect, and does its certificate verify?
- **Mail server:** does it accept encrypted connections?
- **Mail records:** do SPF, DKIM, DMARC and MX match the domain's role? A domain that never sends mail is locked down so **nobody can send as it**.
- **Mail gateway:** Proofpoint's delivery logs show which domains really send mail, so a lock-down never breaks a live sender.

The result is the **exact DNS changes IT needs to make**, filed as one Jira ticket, plus what changed since last week, like a nameserver swap.

### Third-party risk at the front door

**Supplier request triage, daily.** Every new supplier request is read, including the request form but **never the W-9 or bank attachments**, and judged against one question: *will this supplier touch company data, systems or networks, or provide technology?*

- **Yes** or **Unsure** goes on the security team's Kanban board for third-party risk review.
- **Unsure** is treated as critical until a person decides.
- If the AI is down, or its answer can't be backed by quotes from the request, the answer becomes Unsure. **A supplier is never waved through by a failure.**
- When the requester replies in the thread, the request is judged again and its item updated.

### A mailbox that keeps itself

Processed advisories, scan results already reported, and handled supplier requests are archived. Auto-replies and the scanner's companion notices go to Deleted Items. Quarantine digests are cleaned up too, unless they're holding mail the fleet needs, in which case the operator is alerted. **Everything else, like reported phishing and people writing to the team, is left for a human.**

### Loud when it breaks

Any job that fails emails the operator immediately. **A quiet inbox means a quiet day, not a broken pipeline.**

---

## AI, done responsibly

Most "AI security tools" put a model in the path and hope. CR Agent Fleet puts the model where being wrong is recoverable, and keeps it out of the path where being absent is not.

**The analyst on duty** is a Claude session that wakes every two hours. It reads what every lane did and chases what nobody resolved:
- a critical finding still open after a week;
- a vulnerability the scanner can't check;
- a schedule that was switched off.

It escalates to the operator when a decision is needed. It **cannot send any report, run any job, or choose who it emails.** Those limits are enforced in code, not merely requested in its instructions.

**The agent harness.** The tooling that makes an AI agent trustworthy enough to run unattended:

| | Capability | The question it answers |
|--|------|-----|
| **Traces** | Every run recorded: each tool call, each denial, turns, tokens, cost | *What did the analyst actually do?* |
| **Evals** | The real analyst runs against invented fleets: quiet days, failed checks, **prompt-injection attacks**, overdue KEVs. Each scenario runs three times and gets a pass rate | *Does it make the right call?* |
| **Verdicts** | Every run ends with a structured report, checked against counts the AI cannot touch | *Is what it reports true?* |
| **Shared rules** | One library of model-call controls for every AI lane | *Does every AI lane follow the same rules?* |

**Baseline: 30 of 30 must-pass checks met, and no critical failures, at about $0.13 per run.** Every future change to the analyst's instructions, permissions or model is measured against it. The supplier judge has its own eval suite of 53 invented requests.

**Every AI call is contained:**
- no tools for the judging models;
- no access to the fleet's secrets;
- an empty home directory;
- a vetted binary;
- a budget gate that rations model spend and tells a rate limit from an empty account.

---

## Security you can audit

**Least privilege, by design.**
- Every report has its own recipient allowlist, enforced in code, with no default and no fallback.
- Tickets go only to allowlisted Jira projects.
- Every command that changes something must be told `--dry-run` or `--for-real`. There is no default.
- The fleet never patches, changes or touches a system. It reports; IT remediates.

**Truth from the source.**
- Presence comes only from the scanner, registration only from the registrar, and a release's contents only from Microsoft.
- An advisory supplies urgency, never proof.
- Every report says plainly what it couldn't check, because a report that can't tell "we looked and found nothing" from "we never looked" will publish the reassuring one.

**NEW in 2.0: every secret locked to the machine, and to the job that needs it.**
- **Secrets are systemd credentials,** encrypted to the machine (TPM-bound where present), never in a settings file and never printed.
- **Each scheduled job is granted only the secrets it reads,** generated from the code so the grants can't drift. The domains check never sees the CrowdStrike key; a program a lane starts doesn't inherit what it doesn't use. Usernames, client IDs and API hosts are protected the same way, so a lane that doesn't use a system doesn't even know its address.
- **Hand runs get the same grants** as the scheduled job, as a short-lived systemd unit the journal records with who ran it.
- **Settings are split per lane** too: one shared file plus one per lane, so a lane doesn't see another lane's recipients or switches.

**NEW in 2.0: one language for the whole runtime.** Every lane, runner and analyst step that was Python, about 4,900 lines, is now Go or shell. Each rewrite was held byte for byte to golden files the Python wrote before it was deleted: 22 digests, 4,064 scoring cases, 279 command-guard decisions, 17 hostile and malformed feeds. One language means one HTTP client with the TLS floor, one JSON writer, one set of tests, and no interpreter for an attacker to reach from a lane.

**Hardened end to end.**
- **Encryption in transit everywhere:** a TLS 1.2 minimum and https only for every outbound call, through one audited helper. A build test fails if new code bypasses it.
- **A full audit trail:** every email sent, ticket filed and owner changed is recorded as an RFC 5424 syslog line, kept 120 days and ready to forward to any SIEM. Message bodies and credentials are never logged.
- **Data minimisation:** AI models see less, and what they see has tax IDs, bank and card numbers redacted. Traces keep decisions, not copies of your mail.
- **Validated writes:** every state file and database write is checked before it lands.
- **Sender authentication:** forged email from a "trusted" scanner or feed is not believed.
- **A supply chain you can prove:** zero third-party dependencies, enforced on every build, and a **CycloneDX SBOM** attached to every release.
- **Independently reviewed:** every release is scanned by PrimeSec AI, and findings are fixed or formally dispositioned in the changelog.

---

## Built for the operator

- **One command updates the box:** `cti-agent-update --for-real` pulls, builds, installs and checks connectivity in the right order.
- **NEW in 2.0: standard *IX, everywhere.** Code in `/opt`, settings in `/etc`, secrets in the systemd credential store, state in `/var/lib`, logs in `/var/log` and the journal, man pages and tab completion where Linux keeps them, and a system account with no login shell. Anyone who knows Linux knows where to look, and the default SELinux policy fits with no custom module. The installer prints the full list on every run.
- **NEW in 2.0: know exactly what you've configured.** `fleet-config check` reports missing settings, typos, duplicates, settings that can go, and any secret still in a settings file, without ever printing a value. `cti-agent-secrets` and `cti-agent-settings` move the secrets and split the settings, and refuse rather than guess.
- **Ask the CLI, don't memorise it:** `sudo cti-agent` lists every command, `--help` works everywhere, and tab completion shows what each flag does and how risky it is.
- **45 man pages**, an operator cheat sheet (also available as a PDF), and a full runbook.
- **A health check in one command**, plus `--check` on every integration, which tests credentials without changing anything.
- **Test sends to the operator only** (`--to-dev`), so a new report can be rehearsed before the real audience sees it.
- **Releases on rails:** every push passes the `task ship` gate (tests, static analysis, security scan, SBOM). Every tag becomes a GitHub Release with notes taken from the changelog, and a release candidate is marked Pre-release.

---

## Integrations

| Platform | What the fleet uses it for |
|----|----------|
| **Qualys VMDR** | Vulnerability presence, host detections, the Knowledge Base, scan schedules and scan history |
| **Qualys WAS** | Web application findings, scan status, the scanner's own reports |
| **CrowdStrike Falcon** | Installed software, indicator sightings, alerts, host context |
| **Microsoft 365** | The shared mailbox, sending reports, the network team's spreadsheet |
| **Jira Cloud** | Vulnerability, DNS and network tickets; the supplier Kanban |
| **GoDaddy** | The domain registration inventory |
| **Proofpoint on Demand** | Mail gateway logs, to decide which domains really send |
| **CISA KEV, NVD, FIRST EPSS** | Exploitation status, severity, exploit likelihood |
| **Microsoft Security Response Center** | Patch Tuesday release data |
| **Anthropic Claude** | The analyst on duty, the supplier judge, advisory triage |
| **Any SIEM** | The audit trail, over syslog |
| **systemd** | Scheduling, sandboxing, and the encrypted credential store *(new in 2.0)* |

**Bring your own tools.** The scanner, registrar and ticketing system sit behind clean interfaces, so you can plug in a different one.

---

## By the numbers

| | |
|---|---|
| **12** scheduled lanes, plus advisory triage | **26** purpose-built Go commands |
| **26** releases in under **8 weeks** (1.0 on 2 October 2026) | **~2,000** automated tests |
| **0** third-party dependencies | **45** man pages |
| **0** lines of Python in the lanes, runners or analyst steps | **~4,900** lines of Python retired in 2.0 |
| **10** analyst eval scenarios, **53** supplier eval cases | **1** box to run it all |

---

## Release history

| Version | Date | Headline |
|--|--|----------|
| **1.0** | 2 Oct 2026 | Daily and weekly threat-intel briefs, Patch Tuesday, KEV deadlines, Jira ticketing, mailbox cleanup, failure alerting, and the AI analyst on duty |
| **1.1** | 6 Oct | Weekly application-security lane; per-report recipient allowlists that fail closed; tickets re-checked every day |
| **1.2** | 10 Oct | Weekly domains check: registration, websites, certificates, mail security |
| **1.3** | 17 Oct | Patch Tuesday built from Microsoft's own data; domains follow the mail-security decision chart; one DNS ticket for IT; FLEET TICKETS; man pages for every command; the cheat sheet |
| **1.4** | 25 Oct | Application owners named on every finding; the scanner's own report per application; CVSS 9.0+ ticketing; Qualys rate limiting; pluggable interfaces |
| **1.5** | 3 Nov | AppSec results go to each owner by email daily, replacing Jira tickets most owners couldn't open; Proofpoint-aware domain lock-down; operator health check; the analyst locked down further |
| **1.6** | 8 Nov | Supplier request triage; weekly VM scan coverage; run traces for the analyst; a self-maintaining owners list; the guided CLI; one-command updates |
| **1.6.1--1.6.7** | 9--18 Nov | VM scan straight from Qualys schedules; network spreadsheet tickets; every fleet ticket in the Daily Brief; GitHub Releases for every tag |
| **1.7** | 20 Nov | Advisory triage with CrowdStrike Falcon; shadow-IT discovery; the complete agent harness; an audit trail; TLS everywhere; data minimisation for AI; SBOMs |
| **1.7.1--1.7.2** | 21 Nov | PrimeSec AI findings fixed across mail, domains, Jira and the scanner-evidence redactor; installer fixes |
| **2.0-rc1** | 23 Nov | **Secrets in systemd credentials, granted per job; settings per lane; the runtime entirely Go and shell; the week's advisories in the Weekly Brief; standard *IX locations throughout** |

---

## Built on a proven pattern

CR Agent Fleet follows the **agent fleet pattern**: an always-on orchestrator, executor lanes, a heartbeat, a message board and persistent memory, composed so the system does a *job*, not just a task. That makes adding a lane for the next tedious chore the whole point, not an afterthought.

> **Every claim from the system that owns it. Every limit enforced in code. Every report on time, with or without the AI.**
>
> **CR Agent Fleet 2.0. The legwork, handled.**
