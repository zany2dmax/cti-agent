# The Agent Fleet Pattern

**How a handful of boring parts, composed carefully, becomes something that
does a job rather than runs a task.**

---

## Credit where it's due

The pattern described here — an **orchestrator**, **executor lanes**, a
**heartbeat**, an **append-only message board**, and **persistent memory** — is
not mine. It comes from [Build Your Own Claude Code Agent
Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet)
by **Limited Edition Jonathan**, who worked it out for a personal-assistant
workload.

What follows is that pattern applied to cyber threat intelligence, plus what we
learned deploying it to a real production server and getting it wrong several
times along the way. The structure is his. The bruises are ours.

If you only read one thing, read his guide first. This document assumes it.

---

## The claim

You can build something that behaves like a junior-to-mid-level InfoSec analyst
out of parts that are individually unremarkable: a systemd timer, a markdown
file, a SQLite database, four hundred lines of Python, and a language model
called once every two hours.

The interesting part is not the model. It's **where you put the model**, and
what you refuse to let it do.

---

## The five primitives

| Primitive | In this fleet | Why it exists |
|---|---|---|
| **Orchestrator** | `/checkin`, a Claude session every 2h | Judgment. Decides what matters, what to chase, what to say nothing about |
| **Executor lanes** | `enrich.py`, `scout.py`, `brief.py`, the Go agent | Deterministic work. Each does one thing and cannot talk to a human |
| **Heartbeat** | `cti-agent-checkin.timer` | Turns a program into a presence. It wakes up whether or not you asked |
| **Message board** | `board.md`, append-only, lock-safe | How parts that never run at the same time talk to each other |
| **Persistent memory** | `state/memory.db` (SQLite) | Continuity. Without it, every beat is a stranger starting over |

Every one of these is boring on its own. A timer is boring. A text file is
boring. That's the point: each part can be understood, tested, and repaired by
someone who has never read the others.

---

## Why threat intel fits this shape

Threat intel is a batch problem pretending to be a real-time one.

Vendor advisories, CVE mailing lists, and CERT bulletins arrive continuously
and matter occasionally. The work is not reacting in seconds — it's making sure
that out of the fifty things that arrived overnight, the four that affect
machines you actually run reach a human who can act, and the forty-six that
don't stay out of their way.

That is a filtering and correlation problem with a daily rhythm. It has a clear
deliverable (a brief), a clear rhythm (mornings), and a clear failure mode
(something important got buried). All three suit a fleet.

---

## The lanes, and what each one adds

This is the part worth understanding, because the lanes are not a pipeline of
steps. Each one adds **an independent axis of judgment**, and the value
compounds rather than accumulating.

### Axis 1 — signal: *what is being talked about?*

`@ingest` — the Go agent. Reads a shared CTI mailbox over Microsoft Graph,
extracts CVE identifiers, writes markdown.

On its own this is a regex with a mail client. It tells you what arrived. It
tells you nothing about whether any of it matters.

### Axis 2 — presence: *do we actually have it?*

The vulnerability scanner, via the same lane. For each CVE: is this present in
our estate, on how many hosts, and when was it last seen?

This is the axis most intel programs skip, and skipping it is why so many
security teams drown. An advisory about a product you don't run is not a
finding. It's noise wearing a finding's clothes.

**Presence is never inferred.** Only the scanner decides. Advisory text,
vendor bulletins and feed items give you urgency and context — never proof of
exposure. When the scanner says `UNKNOWN`, the report says `UNKNOWN`, because
"we didn't look" and "we're clean" are opposite facts and collapsing them is
the failure that shows up in a post-incident review.

### Axis 3 — exploitability: *is the world attacking this?*

`@enrich` — adds NVD CVSS, FIRST EPSS (probability of exploitation in the next
30 days), and CISA KEV membership.

Now something appears that neither axis had alone. Cross **exploitability** with
**presence** and you get a priority that means something:

| Band | Exploitability × presence | What it means |
|---|---|---|
| **Sev5** | exploited **and** confirmed present | Today |
| **Sev4** | confirmed present, nobody exploiting it | This patch cycle |
| **Sev3** | exploited, **coverage unverified** | We cannot say whether we are exposed |
| **Sev2** | exploited but confirmed absent, or unverified critical | Check the scanner reaches it |
| **Sev1** | everything else | Awareness |

Five bands rather than four because the earlier version put "confirmed
present" and "we cannot tell" in the same band, which forced the digest
heading to claim presence the scanner had never established. Splitting them
lets every label be true on its own — and gives `Sev3` a home in the middle
of the scale, where a coverage gap on an actively-exploited CVE gets read
instead of filed with the awareness items.

The scale is deliberately **not** P1–P4: that is the incident-reporting scale
in this organisation, and a CTI digest labelled "P1" reads as a live incident
to anyone on the rota. Different scale, different meaning, no collision.

That two-by-two is the whole argument for this system. CVSS answers "how bad is
this in the abstract," which is close to useless on a Tuesday. A CVE present on
305 hosts with a CVSS of 6.5 outranks a container escape scoring 8.8 that you
don't run — and sorting by severity buries the first behind the second.

Two axes already beat the industry default. That's the compounding.

### Axis 4 — aperture: *what didn't arrive in the mailbox?*

`@scout` — polls vendor advisory feeds and RSS for CVEs the mailbox never
carried, then routes them through the *same* presence check.

The mailbox is reactive: it tells you what a vendor decided to tell you, when
they got around to it. This lane widens the input without widening the trust
boundary, because scout findings still have to pass the scanner to become
findings at all.

### Axis 5 — obligation: *has someone external set a deadline?*

`cti-kev` — CISA publishes a remediation due date with every KEV entry under
BOD 22-01.

This is a different kind of fact from the other four. CVSS, EPSS and host
counts are all *our* assessment of *our* risk. A due date is **somebody else's
deadline**, which makes it the most persuasive thing in the entire system.
"This is severity 9.1" invites debate. "This was due three weeks ago and it's
on 12 of our machines" ends it.

Notably, this axis costs nothing new: the catalogue was already being downloaded
for the KEV flag, and the due date was sitting unused in the enriched output for
months.

### Axis 6 — translation: *what does a human do with this?*

`@brief` — renders the enriched findings as an HTML digest: Sev5 at the top, host
counts visible, deadlines banner-ed, Sev1 suppressed from the daily and saved for
the weekly.

This lane does no analysis. It exists because analysis nobody reads is
indistinguishable from analysis nobody did. The digest is written for someone
reading on a phone before they're fully awake.

### Axis 8 — the vendor's clock: *what did this release land on us?*

`cti-patchtuesday` — once a month, on the morning after Microsoft's Patch
Tuesday, reads the two public wrap-ups everyone already reads and adds the one
thing neither can provide: how much of that release is on our machines,
according to the scanner, with the exact query to see it yourself.

This axis is different in kind from the others. Axes 1–4 are continuous: mail
arrives, feeds update, scores move. This one is a **cadence** — a vendor
publishes on a fixed schedule, and the interesting work is aligning to
someone else's calendar rather than watching a stream.

It is also the clearest example of the compounding. The public article says
"966 flaws fixed". Crossed with axis 2 it becomes "and 14 of them are on 777
of our hosts". Crossed with the scanner's own identifiers it becomes a query
the patching team can paste into a console. Same article, three levels of
usefulness, and only the third one gets acted on.

The scheduling turned out to be the subtle part. "The second Wednesday of the
month" is how everyone describes the day after Patch Tuesday, and it is wrong
in roughly one month in seven: when the 1st falls on a Wednesday, the second
Wednesday arrives six days *before* the second Tuesday. A lane on that
schedule wakes up before the thing it summarises exists. The correct
expression is the Wednesday after the second Tuesday, which is always the
9th–15th.

The correlation had a subtlety of its own, and it is a good illustration of
reading a source properly. The obvious route from an article to our estate is
CVE → QID via the scanner's KnowledgeBase, and on the morning after a release
that mapping is at its least complete — precisely when the email goes out. But
the Qualys review *publishes the release's QIDs itself*, inside the QQL it
prints for readers to paste. Those QIDs are a vendor-curated statement of what
this release introduced, available on day one, and the lane parses them back
out of the published query and asks the scanner about them alongside the
mapping. The first version used only the mapping, so it announced "exposure is
not yet measurable" in one paragraph while printing fifteen perfectly usable
QIDs in the next. The source was telling us the answer in a format we were
treating as decoration.

### Axis 7 — self-knowledge: *is the fleet itself healthy and affordable?*

Two lanes that watch the fleet rather than the estate:

- `cti-alert` — systemd fires it on any unit failure. Makes a broken pipeline
  loud on two channels (the board, and email), and always exits 0 so it never
  becomes the thing that looks broken.
- `cti-budget` — rations the orchestrator's share of a shared Claude
  subscription: a ceiling per rolling window, a ceiling per day, exponential
  backoff after a rate limit.

These feel like plumbing. They're the difference between a demo and something
you leave running.

---

## The two decisions that make it survivable

Everything above is composition. These two are load-bearing.

### 1. Delivery is deterministic. Judgment is not.

**The morning digest does not go through the model.**

`cti-agent-digest.timer` runs a shell script that ingests, enriches, renders and
sends. No language model is involved. If the model is slow, rate-limited,
having an off day, or refuses for reasons nobody can reproduce, **the brief
still lands at 06:00.**

The orchestrator's heartbeat does the work that actually needs judgment:
chasing an `UNKNOWN` nobody resolved, noticing a Sev5 that's been open eleven
days, correlating scout backlog, spotting that a timer got disabled.

This split is the single most important thing in the architecture, and it is a
general principle: **put the model where being wrong is recoverable, and keep it
out of the path where being absent is unacceptable.** A fleet that routes its
guaranteed deliverable through a probabilistic component has a probabilistic
deliverable.

### 2. Silence has to mean something

The fleet's premise is that a quiet inbox means a quiet day. That premise is
only true if a broken fleet is loud — otherwise "no email" means both "nothing
to report" and "the pipeline died three weeks ago," and you cannot tell which.

Nearly every bug we hit during deployment was a variant of this:

| What we found | Why it was invisible |
|---|---|
| A permissions check comparing an octal mode as a decimal integer | `0604` sorted below `640` and passed. The check ran, reported success, and protected nothing |
| The pipeline worked by hand and every timer failed | `sudo -u` uses plain file permissions; systemd reads the same file as `init_t`. SELinux denies only the second. We tested the easy subject |
| An installer reported three wrong paths, then printed "Installed" | Path errors were warnings. The next command failed on the first of them |
| The alert unit never started | Its template was the one unit `systemd-analyze verify` never checked — because a template needs an instance name. The one unit whose job is reporting failure was the one nobody verified |
| The first automated digest arrived at 2am | `OnCalendar=` uses the *system* timezone, and servers are UTC. A "morning" brief landed in the middle of the night |
| A test of the alert path posted `ERROR: digest failed (result=success exit=0)` | Testing the alerting manufactured the incident it was testing for. The orchestrator reads the board and would have opened a case for it |
| A count matched a pattern written for raw HTML but run against stripped text | The pattern required a literal `<`, so it could never match. Both figures read "not stated in the sources" in every email, which looks like a publisher who did not say |
| A headline count of 400 where the primary source says 421 | The page separates the number from the word with a non-breaking space, and Go's `\s` is ASCII-only. The pattern failed, the parse fell through to the *other* publisher, and produced a number that was plausible, sourced, and wrong |
| "Exposure is not yet measurable — the KnowledgeBase has no QID mapping" printed above fifteen usable QIDs | Correlation had failed outright, leaving a zero-value struct whose zero state was indistinguishable from a real measurement. The report diagnosed a system it had never contacted |
| A product list published as "Windows HTTP, and more." | The sentence was terminated at the first `.`, which fell inside `HTTP.sys`. Truncation at a plausible point reads as a short list, not as a bug |
| A verification script that printed "ALL CHECKS PASS" with a field extracted as empty | It counted the failures it had been taught to count. An empty result was not one of them |

None of these were logic errors. Every one was a **check that ran and had no
effect**, or a **failure with no observable difference from success**. If you
build one of these fleets, budget more time for making failure visible than for
making success work. Success is easy — you can see it.

Two corollaries earned the hard way, both about the tools rather than the
system:

**A fixture written in clean ASCII cannot test a publisher's typography.** The
parser fixtures were hand-written to look like the real pages and passed
completely while two patterns could not match the actual HTML at all. Fixtures
now carry the published bytes — the curly apostrophe, the non-breaking space,
the wrapped paragraph, and a slab of the site's own navigation — because those
are the things that break parsers, and a tidy fixture is a test of your
assumptions rather than of the page.

**Validating in the wrong language validates nothing.** A regex was checked by
compiling it as a Python pattern. Python accepts backreferences; Go's RE2 does
not, and because the pattern was a package-level `MustCompile` it panicked
during `init()` — so the package failed to load and the test binary died
before running a single test. "It compiles in Python" had stood in for "it
compiles." Where a toolchain is genuinely unavailable, a simulation is worth
running only if it is forced into the target's semantics (here, Python's
`re.ASCII`, because the ASCII-vs-Unicode `\s` difference *was* the bug) and
only if it is honest that it cannot catch a compile error at all.

---

## What emerges

Here is a junior-to-mid InfoSec analyst's actual job description, in the words
a hiring manager would use. Against each, the part of the fleet that does it:

| The job | The fleet |
|---|---|
| Monitor the threat-intel inbox and vendor advisories daily | `@ingest` + `@scout`, every day and every four hours |
| Write up Patch Tuesday for the patching team each month | `cti-patchtuesday`, with our own exposure and the scanner query |
| Cross-reference advisories against our asset inventory | The scanner presence check, never inferred |
| Prioritize findings for the patching team | The Sev5–Sev1 matrix: exploitability × presence, host count as tiebreak |
| Track known-exploited vulnerabilities and compliance deadlines | `cti-kev`, against CISA's published due dates |
| Produce a daily brief for the security team | `@brief` → Graph sendMail, 06:00 local |
| Produce a weekly summary including lower-severity items | The Monday weekly, where suppressed Sev1s surface |
| Follow up on items nobody has actioned | The heartbeat's quiet-beat work: stale Sev5 nudges, unresolved `UNKNOWN`s |
| Escalate what's urgent; don't escalate what isn't | The autonomy gate: scheduled sends pre-approved, everything else drafted and held |
| Flag gaps in scan coverage | `UNKNOWN` never sinks to Sev1; `coverage UNVERIFIED` is reported as its own count |
| Keep notes so context isn't lost between shifts | `memory.db` — findings, decisions, what was sent, what was deferred and why |
| Say when you're stuck instead of guessing | It has. Its first-ever beat found no config and escalated: *"I am not fabricating these without a real source."* |

Read that table again and notice what it isn't: it isn't eleven scripts. It's
one set of behaviours with a rhythm, a memory, and a sense of what it's
responsible for.

The thing that makes it feel like a colleague rather than a cron job is
**continuity**. A cron job emails you a report. This remembers it told you
about CVE-2026-1234 on Tuesday, notices on Friday that nobody has marked it
remediated, and nudges — once, on the board, escalating only if it keeps being
ignored. That behaviour is not intelligence. It's memory plus a heartbeat plus
the discipline to stay quiet the other eleven times.

### What it is not

Being clear-eyed about this matters more than the pitch.

**It has no judgment about consequence.** It knows a CVE is on 305 hosts. It
does not know that 4 of them are the ERP system and 301 are conference room
displays. A mid-level analyst knows the estate; this knows the inventory. Those
are different things, and the gap is exactly where a human's value is.

**It cannot accept a risk.** Deciding that a finding is tolerable because of a
compensating control, a business deadline, or a vendor's roadmap is a decision
with accountability attached. The fleet can record that you made it. It cannot
make it.

**It does not do incident response.** Everything here is about the period before
something happens. The moment an incident starts, the cadence, the authority
model, and the tolerance for a wrong answer all change completely.

**It has no political awareness.** A real analyst knows which findings to raise
in which meeting and which to walk over and mention quietly. This one has one
channel and one tone.

**It holds credentials and it costs money.** A service account with Graph
access, scanner credentials, and a model token, running unattended on a VM.
That is a real attack surface and a real bill, and both need someone's name
against them.

So: a capable junior who never forgets, never gets bored, works weekends, and
needs a senior to tell them what actually matters. Which — to be fair — is a
useful thing to have.

---

## Adding a lane

The pattern's real payoff is that extension is cheap and bounded. To add one:

1. **Name the axis.** What question does this answer that no existing lane can?
   If it doesn't add an axis, it's a feature on an existing lane, not a new one.
2. **Write it as a script that cannot talk to a human.** Input from files or an
   API, output to a file and the board. No mail, no chat, no exceptions.
3. **Decide the cadence honestly.** Some signals are daily. Some are
   incidents. Do not put an incident on a daily timer.
4. **Give it a failure mode that is loud.** `OnFailure=cti-agent-alert@%n`.
5. **Tell the orchestrator it exists.** `CLAUDE.md` and the skills are the
   agent's actual instructions. A tool the orchestrator doesn't know about is a
   tool that never gets used — and stale instructions produce wrong decisions,
   not just bad documentation.
6. **Write the test before the integration.** Stub the network. The lane tests
   here run offline and deterministically, which is why they can be trusted to
   fail for real reasons.

A worked example of step 3, from this fleet's own backlog: Proofpoint TAP
exposes both a *Very Attacked People* list and *clicks permitted* events. The
first is slow-moving and belongs in the weekly. The second means somebody
clicked a malicious link and it went through — an incident in progress. Putting
both on the daily digest would mean routinely learning about a compromise twelve
hours late. Same vendor, same API, two different lanes with two different
cadences. That distinction is the design work; the code is the easy part.

---

## The transferable lesson

If you take one idea from this, it shouldn't be about threat intelligence.

**The pattern is not about AI. It's about where you put the AI.**

This fleet is mostly deterministic shell and Python. The language model is
invoked in exactly one place — a heartbeat that does judgment work — and
everything with a guaranteed deliverable is written so it works when the model
doesn't. Around that, five boring primitives do the structural work: something
to wake it up, something to remember, something to pass messages, something to
do the work, and something to shout when the work fails.

Compose those carefully and you get a system that does a job. Skip the boring
parts and route the deliverable through the clever part, and you get a demo.

---

## Sources

- **[Build Your Own Claude Code Agent
  Fleet](https://www.limitededitionjonathan.com/docs/build-your-own-agent-fleet)**
  — Limited Edition Jonathan. The original pattern: orchestrator, executors,
  heartbeat, board, memory. Everything structural here is his idea.
- [CISA Known Exploited Vulnerabilities
  Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — BOD
  22-01, and the remediation due dates that make axis 5 work.
- [FIRST EPSS](https://www.first.org/epss/) — exploitation probability.
- [NVD 2.0 API](https://nvd.nist.gov/developers/vulnerabilities) — CVSS and the
  `cisaExploitAdd` KEV flag.
- [Microsoft Graph application
  permissions](https://learn.microsoft.com/en-us/graph/permissions-reference) —
  `Mail.Read` and `Mail.Send` as application permissions, plus an Exchange
  Application Access Policy to scope them to one mailbox.

Implementation details, install instructions and the full configuration
reference live in [`fleet-kit/README.md`](fleet-kit/README.md).
