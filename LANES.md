# What the fleet does

A set of scheduled jobs — lanes — that do the security team's recurring chores:
read the threat-intelligence mail, chase the tickets, write up Patch Tuesday,
check the web applications and the domains, confirm the vulnerability scans ran
and that they cover every network we have, keep the mailbox tidy. Each checks
what it finds against our own systems and sends each team only the email it
needs to act on. **Three parts use AI, and no report's delivery depends on it** —
if the AI is down, every report still goes out on time (the supplier digest then
marks every request Unsure, and the Daily Brief goes out without its advisory
triage section).

| Lane | What it does | When | AI? | Who gets it |
|---|---|---|:---:|---|
| **Daily brief** (threat intel) | Reads the overnight advisory mail and feeds, asks the vulnerability scanner which CVEs are actually on our machines, ranks them Sev5 (exploited *and* present) to Sev1, adds federal remediation deadlines, and opens a Jira ticket for each exploited vulnerability confirmed on our machines | Daily, 06:00 | N | Security, Infrastructure and M&A teams |
| **Ticket follow-up** *(part of the daily)* | Re-checks every open ticket against the scanner each morning, whether or not that vulnerability is in the news. Comments when machines IT hasn't been told about are affected — at most once a week per ticket, batched, with the new host list attached — and tells IT *"no detections remain, this ticket can be closed"* when it is fixed everywhere. If IT closes a ticket the scanner still sees, says so once. Stays quiet when nothing changed, and never closes or reopens a ticket — that is IT's call. The brief shows each ticket's Jira status beside the finding, and a FLEET TICKETS section lists every ticket the fleet has filed, from any job — each vulnerability ticket with its status, the hosts the scanner sees today and what the re-check did; the domains and spreadsheet tickets with their status; and a one-line count of the supplier requests waiting for third-party-risk review | Daily, 06:00 | N | IT, on the ticket |
| **Weekly brief** (threat intel) | The week's findings rolled up, including the lowest-priority items the dailies leave out, and the week's advisory triage: anything seen on our hosts or judged likely or possible | Monday, 07:00 | N | Security team |
| **Feed scout** | Polls vendor and government advisory feeds for vulnerabilities that never arrived in the mailbox, so coverage doesn't depend on who subscribed us to what | Every 4 hours | N | Feeds the brief |
| **Patch Tuesday synopsis** | The morning after Microsoft's monthly release: what was fixed, how much of it is on our machines, and the exact scanner query to see it yourself. Built from Microsoft's own release data, cross-checked against a news write-up | Monthly — the Wednesday after the second Tuesday. **Run by hand for now:** both article sites block the server, so the operator saves the articles and starts it | N | Security, Infrastructure and M&A teams |
| **AppSec report** | What the web application scanner found open on each of our sites, what is new since the last scan, and whether each scan logged in | Friday, 07:30 | N | Application developers |
| **Application owner reports** | Each morning, for every web-application scan that finished since the last run, emails the application's owner (and watchers) the scanner's own report of what is open on it, with the scan account's session details removed. A scan that did not finish, whose login failed or that reached no host is held back and the operator is told; so is an application with nobody on file. A scan Qualys finished with service errors is sent, with a warning that it may be incomplete, and the operator is told. Many owners are outside the company and have no Jira login, which is why this is email and not a ticket. The owners list is kept in step with the scanner (`fleet-owners sync` reports every web application with no owner). Off until an allowed-domain list is set | Daily, 07:15 | N | Each application's owner and watchers, at allowed domains only |
| **VM scan report** | Asks the vulnerability scanner which scans ran this week and which should have — every active schedule — so a scan that stopped launching is named, even if nobody noticed. For each scan: when it started, how long it took, how many addresses it scanned and how many were alive, and which groups of addresses it covered; a scan whose results email was lost (as in the Microsoft outage of 11-13) is still reported. Then checks the network team's spreadsheet of subnets against what the scans covered, by address. Each site's network is its usual 10.X.30 range, whatever the row is called (the 30 is a setting, `VMSCAN_USER_OCTET`). It lists **networks no scan reaches** (the security team records only that a network is not scanned, because why differs by site; the teams named in `VMSCAN_GAP_TEAMS`, by default the network team, are asked to say why), **spreadsheet rows the check cannot read** (a blank or invalid network, one outside its site's own block), **spreadsheet clean-up** (two sites claiming one network, a misspelled DECOMMISSIONED, the same public IP under two sites, and findings from checking the sheet against the M&A network designs), and anything odd in the scanner: scans spent on closed sites, address groups no scan targets. Each line names the site and the spreadsheet row; the same list comes as a CSV worksheet with a blank column for the teams' answers. The spreadsheet corrections and clean-up also go to the help desk as **one Jira ticket** for the network team, updated only when the list changes, named with its link in this report, and listed in the daily and weekly briefs. It carries no vulnerability counts: the scans overlap and the audience does not act on them from this email. If a scheduled scan did not run, that is the first thing it says | Monday, 08:00 | N | The vulnerability-management audience, plus the network and M&A teams if you add them; the network team, on a help-desk ticket |
| **Supplier requests** | The shared mailbox is on the supplier-request distribution list. Each new request (a conversation with that address in To or Cc) is read — the message text and the supplier request form, **never the W-9 or bank attachments** — and judged against one question: will this supplier touch company data, systems or networks, or provide technology? A **Yes** means the supplier is critical and has to go through third-party risk management; a **No** is a supplier of materials or other non-technology goods. A Yes, and an **Unsure** (the lane could not determine a certain Yes, so it is treated as critical until a person decides), each get an item on the security team's Kanban board; a No appears in the digest only, and a thread that is not a supplier request at all (staff updating an existing vendor, say) is **set aside**: no item, listed last in the digest, and never accepted for a thread an outside sender started. One digest email points the team at the board and ends with a list of every email the lane read; a day with no new requests sends nothing. Items are filed in the To Do status so they show on the board. A form shared as a link instead of attached is not opened: that request is Unsure, with the reason. Each item lists what is still needed from the requester (the lane never contacts them), and when they answer in the same email thread the request is judged again and a comment added to its item; the lane never closes or reopens one. Code checks the model's answer against the request and can only move it toward Unsure | Daily, 07:45 (off until armed) | **Y** (the judgement only) | The security team |
| **Domains check** | For every domain we own: is it still registered in our GoDaddy account (and is the account holding domains nobody is checking; `DOMAINS_REGISTRAR=none` turns these checks off for a registrar the lane can't read), is it live, parked or broken, where does it redirect, does its certificate verify, does its mail server accept encrypted connections, and do its mail records match what it should do — each domain's role (sends, receives, both, a SaaS service sends as it, or no mail at all) decides what it should publish, so nobody can send as a domain that never sends. Lists the exact DNS changes for IT and files them as one Jira ticket. Flags what changed since last week, like a nameserver swap | Tuesday, 08:00 | N | Security team; IT, on the ticket |
| **Mailbox cleanup** | Files processed advisories, the scan results the reports used (two days after the report went out) and the supplier requests the supplier lane has dealt with (judged not critical, or given a Kanban item), including on days with no new CVEs. Moves auto-replies and Qualys's companion notices ("scheduled to start", "Scan Completed") to Deleted Items. Deletes the mail filter's quarantine digest too, unless it lists held mail from a sender the fleet reads: then it keeps the digest seven days and alerts the operator, and never follows its Release links. Leaves everything else — reported phishing, people writing to the team, scan notices nothing uses — for a human | Daily, 07:00 | N | — |
| **Failure alert** | Any job that fails emails the operator, so a quiet inbox means a quiet day rather than a broken job | Whenever a job fails | N | Operator |
| **Analyst on duty** | Wakes up, reads what every job did, and chases what nobody resolved: a critical finding still open after a week, a vulnerability the scanner can't check, a schedule that was switched off. Asks the operator when it needs a decision. The operator picks its model (`CHECKIN_MODEL`), it hands anything needing judgement or a person back to the operator, and each run is recorded in a trace the operator can read (`fleet-trace`) | Every 2 hours | **Y** | Operator only |
| **Advisory triage** *(part of the daily)* | Reads the day's threat-intel mail, whoever sent it (a colleague's forward counts), and answers "does this affect us?" for the advisories the CVE report can't: items with no CVE. A reader model lists each advisory's vendors, products, versions and attack techniques, and code removes every claim the advisory doesn't support. The rest are looked up in CrowdStrike Falcon: installed software and roughly how many hosts are below the fixed version, hosts that saw the advisory's indicators, and alerts naming its techniques in the last 30 days. A second model sees only those facts, never the advisory, and says likely, possible, unlikely or unknown, citing the facts it used; code checks every verdict against those facts and corrects one they don't support (a "likely" with no affected host becomes "possible"; software installed and not known to be fixed is never below "possible"). Any host that saw an indicator is listed first, from code, whatever the model says. Results are the Daily Brief's FLEET ADVISORIES section, with the day's model cost. The Weekly Brief rolls up the 7 days up to yesterday: sightings, then likely and possible, each with its day, and a count of the rest, with no model run. Supplier requests, W-9 and bank threads and auto-replies never reach a model; a failure costs the section, never the brief. On with `TRIAGE_ENABLED=1` | Daily, 06:00 | **Y** | Security, Infrastructure and M&A teams, in the Daily Brief |

Times are the server's local time. A box can run only some of these lanes
(`FLEET_LANES`); the rest are off on purpose, and the analyst on duty treats
them that way. [docs/lanes.md](docs/lanes.md) is the generated reference for
each lane: its units, schedule, settings file and credential checks.

## The AI, in one paragraph

The analyst on duty is a Claude session. It can read the jobs' results, keep
notes, and email one person — the operator — but it **cannot send any report,
run any job, or choose who it emails**. Those limits are enforced in code, not
just requested in its instructions, and a test fails if its instructions ever
ask for something it isn't allowed to do. The model is used where being wrong
is recoverable (deciding what to chase next) and kept out of the path where
being absent is not (delivering the reports).

The supplier-request lane has one more model use of the same kind. Each request
is shown to a Claude session started with **no tools, no MCP servers, no session
file and no settings from the host**: it reads one file and writes one JSON
object. Code then checks every quote against the request and can only move an
answer toward Unsure; a missing, failed or unusable answer is Unsure too. So a
model that is down or fooled makes more work for a person, never a supplier
waved through.

Advisory triage uses two more sessions set up the same way, with no tools. The
reader sees only the advisory; the judge sees only the numbered facts the
Falcon lookups returned, never the advisory, so text planted in an advisory
cannot steer the verdict. Code removes anything the reader made up, drops any
fact the judge invented, and reports hosts that saw an indicator itself, so a
model that is down or fooled can cost the section but cannot hide a sighting.

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
