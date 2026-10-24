# What the fleet does

A set of scheduled jobs — lanes — that do the security team's recurring chores:
read the threat-intelligence mail, chase the tickets, write up Patch Tuesday,
check the web applications and the domains, keep the mailbox tidy. Each checks
what it finds against our own systems and sends each team only the email it
needs to act on. **One part uses AI, and none of the reports pass through it** —
if the AI is down, every report still goes out on time.

| Lane | What it does | When | AI? | Who gets it |
|---|---|---|:---:|---|
| **Daily brief** (threat intel) | Reads the overnight advisory mail and feeds, asks the vulnerability scanner which CVEs are actually on our machines, ranks them Sev5 (exploited *and* present) to Sev1, adds federal remediation deadlines, and opens a Jira ticket for each exploited vulnerability confirmed on our machines | Daily, 06:00 | N | Security team |
| **Ticket follow-up** *(part of the daily)* | Re-checks every open ticket against the scanner each morning, whether or not that vulnerability is in the news. Comments when machines IT hasn't been told about are affected — at most once a week per ticket, batched, with the new host list attached — and tells IT *"no detections remain, this ticket can be closed"* when it is fixed everywhere. If IT closes a ticket the scanner still sees, says so once. Stays quiet when nothing changed, and never closes or reopens a ticket — that is IT's call. The brief shows each ticket's Jira status beside the finding, and a FLEET TICKETS section lists every fleet ticket with its status, the hosts the scanner sees today and what the re-check did | Daily, 06:00 | N | IT, on the ticket |
| **Weekly brief** (threat intel) | The week's findings rolled up, including the lowest-priority items the dailies leave out | Monday, 07:00 | N | Security team |
| **Feed scout** | Polls vendor and government advisory feeds for vulnerabilities that never arrived in the mailbox, so coverage doesn't depend on who subscribed us to what | Every 4 hours | N | Feeds the brief |
| **Patch Tuesday synopsis** | The morning after Microsoft's monthly release: what was fixed, how much of it is on our machines, and the exact scanner query to see it yourself. Built from Microsoft's own release data, cross-checked against a news write-up | Monthly — the Wednesday after the second Tuesday. **Run by hand for now:** both article sites block the server, so the operator saves the articles and starts it | N | Security team |
| **AppSec report** | What the web application scanner found open on each of our sites, what is new since the last scan, and whether each scan logged in | Friday, 07:30 | N | Application developers |
| **Domains check** | For every domain we own: is it still registered in our GoDaddy account (and is the account holding domains nobody is checking), is it live, parked or broken, where does it redirect, does its certificate verify, does its mail server accept encrypted connections, and do its mail records match what it should do — each domain's role (sends, receives, both, a SaaS service sends as it, or no mail at all) decides what it should publish, so nobody can send as a domain that never sends. Lists the exact DNS changes for IT and files them as one Jira ticket. Flags what changed since last week, like a nameserver swap | Tuesday, 08:00 | N | Security team; IT, on the ticket |
| **Mailbox cleanup** | Files processed advisories, moves auto-replies to Deleted Items, and leaves everything else — reported phishing, people writing to the team — for a human | Daily, 07:00 | N | — |
| **Failure alert** | Any job that fails emails the operator, so a quiet inbox means a quiet day rather than a broken job | Whenever a job fails | N | Operator |
| **Analyst on duty** | Wakes up, reads what every job did, and chases what nobody resolved: a critical finding still open after a week, a vulnerability the scanner can't check, a schedule that was switched off. Asks the operator when it needs a decision | Every 2 hours | **Y** | Operator only |
| *Advisory triage* *(not live yet)* | Reads advisories that name no CVE and judges whether they concern us, against a profile of what we run. Every claim it makes is checked against the source before anyone sees it | — | Y | Would feed the brief |

Times are the server's local time.

## The AI, in one paragraph

The analyst on duty is a Claude session. It can read the jobs' results, keep
notes, and email one person — the operator — but it **cannot send any report,
run any job, or choose who it emails**. Those limits are enforced in code, not
just requested in its instructions, and a test fails if its instructions ever
ask for something it isn't allowed to do. The model is used where being wrong
is recoverable (deciding what to chase next) and kept out of the path where
being absent is not (delivering the reports).

## What it never does

- **Patch, change or touch any system.** It reports; IT remediates, from the
  ticket.
- **Decide on its own that a vulnerability is present.** Only the scanner says
  that. An advisory supplies urgency, never proof.
- **Email anyone not on that report's list.** Each report has its own
  recipient list, enforced in code, with no default and no fallback to another
  report's list.

More detail: [ARCHITECTURE.md](ARCHITECTURE.md) (two pages, with diagrams) ·
[RUNBOOK.md](RUNBOOK.md) (running it) · [SECURITY.md](SECURITY.md) (the threat
model).
