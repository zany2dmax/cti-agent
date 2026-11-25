# The application-security lanes

The weekly application-security report, the owners' reports, and the Jira
tickets per application.

Moved here from the RUNBOOK. Each section keeps its number, so a "RUNBOOK 11n"
pointer still names it.

- [11f. The weekly application-security lane](#11f-the-weekly-application-security-lane)

---

## 11f. The weekly application-security lane

`cti-agent-appscan.timer`, Fridays 07:30. Reads the DAST scanner's own
completion notifications out of the CTI mailbox, pulls per-finding detail from
the Qualys WAS Findings API where credentials allow, and mails the result
through `cti-mailer --lane was`.

```bash
sudo cti-agent run-appscan --dry-run   # render, print the subject, send nothing
sudo cti-agent run-appscan --for-real  # render and send
```

A dry run leaves the rendered report at
`$FLEET_HOME/state/appscan-YYYY-MM-DD.html`, mode 0600. Open it before enabling
the timer: it names which applications have open Urgent findings, so it is a
map of where to look, and it is handled like the VM reports for that reason.

### The weekly VM scan report (run-vmscan)

`cti-agent-vmscan.timer`, Mondays 08:00 by default (`FLEET_VMSCAN_DAY` and
`FLEET_VMSCAN_TIME`, applied by the installer when `FLEET_TIMEZONE` is set),
runner `run-vmscan`. The scheduled Qualys VM scans (in 2026-11, two weeklies
for different groups of sites, both starting Thursday 13:00 UTC; the longer
one runs about a day, so its notice arrives Friday around 13:00 UTC) each email a "Qualys:
Scan Results" notice when they finish. This lane reads those notices from the
CTI mailbox and sends **one** email with every scheduled scan, kept
in separate sections: that it ran, when and for how long, addresses scanned and
alive, and the locations it covered (its Qualys Target Groups). It carries no
severity counts, on purpose: the audience does not act on them from this email,
and the two scans overlap.

```bash
sudo cti-agent run-vmscan --dry-run   # render, print the subject, send nothing
sudo cti-agent run-vmscan --to-dev    # the same email to FLEET_DEV_EMAIL only
sudo cti-agent run-vmscan --for-real  # send, and record the notices as used
```

Recipients are `VMSCAN_TO`, checked against `VMSCAN_ALLOW_TO`; neither has a
fallback (unset = refuses). To send to the VM audience, reference it in both:
`VMSCAN_TO=$VM_ALLOW_TO` and `VMSCAN_ALLOW_TO=$VM_ALLOW_TO`. Every scheduled scan that ran in the last week is included, and its Target Groups count for the coverage check, whatever it is called; a scan launched by hand is listed, not counted. With no scan at all the subject says `[NO RESULT]` and the coverage check says it was not run, rather than calling every location unscanned.

**Which scans ran comes from Qualys, not the mailbox.** The lane lists the VM
scans launched in the last week through the Qualys API (read-only, the same
account as the other Qualys lanes), with the Asset Groups each targeted, and
then looks for each scan's results notice by its scan reference. A scan Qualys
lists whose notice never arrived (mail lost in an outage, or late) is still
reported and still counts for coverage; its card says the notice did not arrive
and shows no host counts. If the scan list cannot be read, the report is built
from the notices alone and says so. `cti-vmscan --check` lists the scans too.

**Which scans should have run also comes from Qualys:** its scan schedules.
Every active schedule whose last launch fell in the week is expected by its
real title, so a schedule that silently stopped launching is reported, and
nothing has to be kept in step when a scan is renamed. A schedule switched off
is named as such; a monthly one is not judged. `VMSCAN_SCANS` only adds titles
and is rarely needed.

What the subject can say first: `[NO RESULT]` when an active schedule (or a
title in `VMSCAN_SCANS`) launched no scan in the week, or no scheduled scan ran
at all, `[INCOMPLETE]` when one did not finish, otherwise
how many scans ran and how many locations they covered.

**Getting the notices into the mailbox.** Qualys sends them to the people on
each schedule's notification list and, for the owner-only notice, to the scan's
owner. A schedule owned by a user whose email is not `cybersecurity@` does not
reach this mailbox. Reassign the schedule to the scan service account, add
`cybersecurity@` to its notification recipients, and set the notification From
Address to `qualys@qualys.net`: a notice that looks as if it came from
`cybersecurity@` is treated as the fleet's own mail, and the lane logs it and
reads nothing.

**The coverage check.** The same email checks the network spreadsheet against the
Qualys Asset Groups the scans cover, by address (the scans' group names and the
spreadsheet's location names do not match, so names are only for display).
Each location's network is its **10.X.30 network** inside the /16 its header
names, whatever the row is labelled (the sheet's own convention: HQ and 3000
Pine label it `inside`); a location with none falls back to the row labelled
`corp`. A location is closed only when its header **starts** with
DECOMMISSIONED (the misspelling DECOMISSIONED counts too); a header that only
mentions an old site it replaced stays open. It reports three things, each line naming the location, the spreadsheet row and
what to do, so the email can go to the network and acquisitions teams as well as
security: **not scanned** (a corp network in no Asset Group, in a group no scan
covers, or only partly covered; the lane records only that, because why differs
per location and it cannot check, so the network and M&A teams are asked to say,
in a blank column of the CSV), **fix in the spreadsheet** (a corp row
with no network, one that is not a valid CIDR, one outside its location's own
block, an overlap, or no clear corp row), and **check in Qualys** (a Target Group
Qualys does not list, a scanned group whose addresses are only under
decommissioned locations, a scanned group whose addresses are nowhere in the
sheet, and every Asset Group with addresses that no scan targeted this week). The same findings are attached as a CSV worksheet,
and the email ends with a note on how the spreadsheet has to be laid out.

**The spreadsheet fixes are also a Jira ticket.** The "fix in the spreadsheet"
rows go to the help desk as ONE ticket, filed by the fleet, unassigned, for the
help desk to route to the network team (`cti-jira --vmscan-fixes`, labels
`cti-agent` and `cti-vmscan-sheet-fixes`). The domains lock-down ticket's
cadence: a new ticket only when none is open, a comment only when the list
changed (rows moving in the sheet is not a change), one "nothing is left"
comment when it empties, and nothing when the coverage check did not run. It
goes to `JIRA_PROJECT_KEY` unless `JIRA_VMSCAN_PROJECT_KEY` names another
project, and is written only when that project is in `JIRA_ALLOW_CREATE`. A dry
run and a test send print the ticket; check it before the first real run with
`sudo cti-agent run-vmscan --dry-run`. The "not scanned" networks are not in
it: they are for the network and M&A teams to explain, in the email.

**The weekly email names the ticket.** After the network team's sections it
says which ticket and what happened to it this week, with a link: "filed
HD-12", "HD-12 - the list changed, so this week's version was added as a
comment", "HD-12 already has this exact list", "HD-12 was NOT updated this run -
why". The report is rendered with a slot (`cti-vmscan --ticket-slot`), the
ticket step writes what it did (`cti-jira --vmscan-fixes --ref-out`), and
`cti-vmscan --stamp-ticket` fills the slot before the send, the way the domains
lane names its lock-down ticket. A dry run and a test send show the would-be
line ("Jira (preview): would add this week's changed list to HD-12"). If Jira
fails the line says so, and the report still goes. The link appears only when
Jira's browse URL is https and for that ticket's key.

The ticket is also in every **Daily Brief's FLEET TICKETS** list (the daily's
follow-up finds it by its label and lists it, never re-checking or commenting),
and in the **Weekly Brief's**, which uses the newest daily's list. On a day the
scanner cannot be loaded the daily still lists every ticket, headed "not
re-checked against the scanner this run".

The same ticket has a second section, **clean-up (does not stop the check)**:
what is wrong or unclear in the sheet although it can still be read. The lane
finds some itself every week: two locations listing overlapping networks, a 10.x
row outside its location's block, the same public IP under two sites,
DECOMMISSIONED misspelled or not at the start of a header, a header marked "??"
or without its /16, and rows with a VLAN but no network. The rest are findings
from cross-checking the sheet against other records (an acquisition's network
design, the incident-response contacts list), which the lane cannot read every
week because each has its own layout. Record those in
`/etc/cti-agent/sheet-notes.txt` (root-owned, optional, `NETNOTES_FILE`), one
per line; each stays in the ticket until you delete the line:

```text
# location (the start of its header, or a site the sheet does not have) | what to check
Example Site | the acquisition's network design gives it 10.55.0.0/16; the sheet gives that block to another site
Missing Co | no location in the sheet; it is in the incident-response contacts list
```

It only reads, and beyond the 10.X.30 convention it never guesses which row is
a location's network. The
spreadsheet belongs to the network team and the security team is only a consumer
of it, so when it is wrong or unclear (a location with no `corp` row, a corp
network that is not a valid CIDR, one outside its location's block, an overlap)
the email lists it for the network team to correct, by row, and does not check
that location until they do. Nothing is escalated to the operator. If the
security team decides to treat a location differently in the meantime it can
record that in `/etc/cti-agent/netrules.txt` (root-owned, optional):

```text
# location (the start of its header in the sheet) | what to do
HQ - Example Site - GA | use inside,corp     # a rule replaces the 10.X.30 choice
Datacenter - Example - GA | use Servers,VMs
Azure - 172.16.0.0/16 | ignore
```

To turn it on, set `SUBNETS_DRIVE_ID` and `SUBNETS_ITEM_ID` in `fleet.env` (the
drive and item of the spreadsheet) and give the Graph app registration an
application permission that reaches the file: `Sites.Selected` with a read grant
on the site (preferred), or `Files.Read.All`. Without them the report says the
check did not run. Listing Asset Groups uses the same Qualys account as the other
lanes and is read-only. Try it by hand with a downloaded copy first:

```bash
sudo cti-agent cti-vmscan --subnets-file /tmp/subnets.xlsx --out /tmp/vm.html --text-out /tmp/vm.txt
```

The notices it uses are archived by the mailbox cleanup 48 hours after a real
send. For a scan that finished, its Scan Completed and Completed Vulnerability
Scan Notification go to Deleted Items on the same timing; they are matched to
the run (report reference, or title and launch time), never by subject alone.
An unfinished scan's notices stay in the inbox for a person.


### The supplier-request lane (run-supplier)

`cti-agent-supplier.timer`, every day 07:45 (`FLEET_SUPPLIER_TIME`), runner
`run-supplier`. **Off until you enable it, and it does nothing until
`SUPPLIER_ADDRESS` is set.** The shared mailbox is on the supplier-request
distribution list; each new request (a conversation with that address in To or
Cc) is read and judged against one question: will this supplier touch company
data, systems or networks, or provide technology? A **Yes** means the supplier
is critical and has to go through third-party risk management; a **No** is a
supplier of materials or other non-technology goods. A Yes, and an **Unsure**,
each get a Kanban item in `SUPPLIER_JIRA_PROJECT`, counted in one line under the
Daily Brief's FLEET TICKETS ("N Supplier request tickets opened for TPRM
evaluation"); a No appears in the digest only. One digest to the security team points at the board; a day with nothing
new sends nothing.

What it reads: the message text and the supplier request form, an `.xlsx`
attachment read by its labels (so a second version of the form still works).
It **never opens the W-9 or bank attachments**: only `.xlsx` files are read, and
a name containing w9, bank, routing, void, tax, irs or ach is refused whatever
its type. A form shared as a link in the message instead of attached is not
opened; that request is Unsure, with the reason on the item. It never replies to
the requester, and it never moves mail itself.

**Filing the mail away.** Once a request is dealt with - judged not critical, or
critical or unsure with its Kanban item filed - the lane records its messages in
`state/processed-supplier.json` (`cti-supplier --commit-owned`, after every real
run), and the daily mailbox cleanup moves them to Archive after its usual grace.
A request set aside as not a supplier request stays in the inbox for a person,
and so does one whose item could not be filed. A reply that arrives after the
judgement is not recorded: it is judged again, and its mail is filed away then.
The first run after the upgrade also hands over mail settled earlier, as long as
the cleanup's window still reaches it (`MAILBOX_LOOKBACK_HOURS`, 14 days).

A fourth answer, **Set aside**, is for a thread that is not a request to set up a
supplier at all: staff changing an account number, merging duplicate vendor
profiles, a customer's credit application. It files no item. Code accepts it only
when the model quotes the request, no supplier form came with the thread, the
thread was started by someone at your own domain (the one in `SUPPLIER_ADDRESS`,
plus `SUPPLIER_INTERNAL_DOMAINS`), and nothing in it points to technology or
tries to steer the reader; anything else stays Unsure. Set-aside threads are
listed last in a digest that goes out for another reason, and a day with only
set-aside threads sends no digest, so **read the lane's log (`journalctl -u
cti-agent-supplier`) now and then** to see what was set aside. They are recorded as
reported, so they are not judged again unless the thread gets a newer message.

An **Unsure** is not a failure: it says the lane could not determine a certain
Yes, so a person decides. It is also what every request becomes when
`SUPPLIER_MODEL` is unset, `claude` is missing, or the model's answer cannot be
used, so a broken model means more to-dos, never a supplier waved through.

```bash
sudo cti-agent run-supplier --dry-run   # judge and render into state/; file, send and record nothing
sudo cti-agent run-supplier --to-dev    # the digest to FLEET_DEV_EMAIL only; no items filed
sudo cti-agent run-supplier --for-real  # file the items, send the digest, record the requests as reported
```

**To turn it on**, in `/etc/cti-agent/fleet.env` (see `fleet.env.example`): set
`SUPPLIER_ADDRESS`, `SUPPLIER_TO` and `SUPPLIER_ALLOW_TO` (own pair, no
fallback), `SUPPLIER_JIRA_PROJECT` (also in `JIRA_ALLOW_CREATE`) with
`SUPPLIER_OWNER_EMAIL`, and `SUPPLIER_BOARD_URL`. Set `SUPPLIER_MODEL` (an alias
such as `sonnet`) and make sure `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`
is set. Then run `--dry-run` and read the digest and the items it says it would
file (only the digest is kept, in `dryrun/supplier/`; the request text is
removed when the dry run ends), then `--to-dev`, then enable the timer. The
installer builds `cti-supplier` and puts the model's instructions at
`/opt/cti-agent/agents/supplier/CLAUDE.md`, root-owned.

A request is reported once. `state/supplier-seen.json` remembers, per request, a
label, dates, the verdict and the Kanban item's key (no names, no text from the
request), and the item is found again by its label rather than filed twice. If an
item cannot be filed (the project is not in `JIRA_ALLOW_CREATE`, Jira is down)
the digest still goes out and the run fails after it, so the failure alert
fires; that request is **not** recorded, so the next run collects it again and
files it then.

**New information.** When a request already reported gets a newer message in
its email thread (the requester sends the website, or the form arrives), it is
judged again. If the verdict changed, or the form was unreadable and is now
read, the lane adds a **comment** to the item it already has saying what
changed, and the digest lists the request under "Updated". If nothing changed
it stays quiet. The lane **never closes, reopens or edits an item**: when a
request turns out not critical, the comment says a person can close it.

**Information still needed.** Each Yes or Unsure item lists what is missing,
worked out by code: the form (not attached, linked, or not the form), required
fields left blank, and what the supplier will provide when the notes are empty.
The wording is fixed, so nothing a requester wrote reaches it. The lane never
contacts the requester; the items on the board are what prompt whoever runs
supplier set-up to ask for the rest. The digest repeats it in one line per
request.

**Emails read.** Under the cards the digest lists every email the lane read in
the window, newest first: time, sender, subject and what came of it (the verdict
for a request judged now, "reported earlier, nothing new" for one already on the
board, "left out" for the mail filter's own messages). Sixty rows at most, the
rest counted. It answers "what did the lane actually look at?" and appears only
on a day a digest is sent.

The mail filter's quarantine digest ("End User Digest") also lands on the list. It is left out, using the address already in `MAILBOX_DIGEST_SENDERS` (exact sender and subject, so a person's reply to a digest still counts), and the digest says how many were skipped. Unset, nothing is skipped. No other sender is ever skipped, and nothing a request says can get it skipped.

`SUPPLIER_WINDOW_DAYS` (default 3) is how far back to look for requests with a new message. A conversation is read whole - back a further 21 days - so a request is judged with the message that carries its form, not just the latest reply. For a first trial, set it to 30 to see a realistic batch.

The wording is yours: `SUPPLIER_QUESTION`, `SUPPLIER_MEANING`, `SUPPLIER_TPRM` and
`SUPPLIER_UNSURE_TEXT` (generic defaults apply), and `SUPPLIER_TECH_TERMS`, the
words that stop a No from standing (a supplier whose name, subject or notes hold
one is Unsure, not No).

**Threads the model never sees.** A thread whose subject, text, or form name or
notes holds a phrase from `SUPPLIER_HOLD_PHRASES` (default: credit application,
credit app, application for credit, customer credit, personal guarantee,
personal guaranty, guarantor; whole words, any case) is not shown to the model at
all: it goes to a person as an Unsure, with the reason "not sent to the AI", and
gets the same Kanban item as any Unsure. It is never a No or a "not a request",
because "credit application" can be a customer applying to you or you applying to
a new supplier, and code cannot tell which without reading what the model must
not see. Set the variable empty to hold nothing; set it to your own list to
replace the default.

**Testing the judgement.** `task eval:supplier` runs the real model on 53 invented
requests (clear materials, clear technology, blank and vague forms, linked and
unreadable forms, and hostile ones: injected instructions, a request that tries
to close the untrusted block, fake authority, bait to fabricate a quote), calls it
exactly as the runner does, passes each answer through the same checks as
production, and prints how often the final verdict was the one wanted. Each case
runs 3 times, so the result is a rate. It fails only on a **dangerous** result (a
final No where No was not wanted) and reports being **too cautious** separately,
which is what tuning the instructions is for. It costs tokens, so it is run by
hand before changing the instructions or `SUPPLIER_MODEL`, never in `task ship`;
it needs `claude` logged in or `ANTHROPIC_API_KEY`. `SUPPLIER_EVAL_MODEL`,
`SUPPLIER_EVAL_RUNS`, `SUPPLIER_EVAL_ONLY` (case-name substrings) and
`SUPPLIER_EVAL_REPORT` (full results as JSON) adjust it. The cases are in
`internal/supplier/testdata/eval/cases.json`; add one whenever a real request
surprises you, with invented names only.

**Not yet verified:** the `claude` flags the runner passes (no tools, no MCP, no
session file) were checked against `claude --help`, not run against the API; the
tests use stub programs. The first `--dry-run` with `SUPPLIER_MODEL` set is the
real check.

**The model's environment.** `claude` runs with only `PATH`, the locale, the
proxy and CA-bundle variables, and `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN`. Its `HOME` is an empty folder inside the work
directory. So it authenticates only through one of those two settings in
`fleet.env`. A login stored in the service account's home isn't seen. If the
judgements suddenly all come back Unsure after an upgrade, check that one of
them is set.

### Reports to application owners, by email

`cti-agent-appowners.timer`, daily 07:15, runner `run-appowners`. For every
scan that finished since the last run, it builds the fleet's own report of the
application's open findings from the Qualys WAS API and mails it to the owner
(To) and watchers (Cc) on the application's line in
`app-owners.txt`. Many owners and watchers are outside the company and not in
Jira, which is why this is email and not a ticket.

The security team is copied on every one of these emails through
`WAS_OWNER_CC` in `fleet.env`, a separate list from `WAS_TO` (the AppSec
weekly's audience). Each address must be at an allowed domain, like a watcher.
`run-appowners --dry-run` prints how many addresses it will copy and names any
it will leave off. Unset means no copy.

The report is one self-contained HTML file: no scripts, no external resources,
every value escaped. It costs one finding search per application and one
knowledge-base lookup per 1,000 kinds of finding. It shows the scan facts and severity tiles, the
worst open finding with its fix, charts, and one card per kind of finding with
every place it was found. Request headers are never read. Cookie values,
session identifiers, tokens and login headers are removed. The payloads that
prove a finding are kept so developers can reproduce it. The email names the
URL scanned. `--deliveries` creates nothing in Qualys, so `--keep` does not
apply.

```bash
sudo cti-agent run-appowners --dry-run   # plan, check every recipient; fetch and send nothing
sudo cti-agent run-appowners --to-dev    # every email and report to FLEET_DEV_EMAIL only
sudo cti-agent run-appowners --for-real  # fetch, redact, send, record
sudo cti-agent cti-appreport --owner-report 123456 --out-dir /var/lib/cti-agent/state/preview   # preview one app; nothing sent or recorded (the service account writes it: not /root)
```

Preview one application and read its report before the first `--for-real`
send. The payloads are in it on purpose.

**Who receives it.** `cti-mailer --lane owner` reads the owners itself, from
`owners.db` (below) or, until that exists, `app-owners.txt`, and sends only to
that application's owner and watchers, and only to addresses at an allowed
domain: `fleet-owners domain list` with `owners.db`, or `OWNER_ALLOW_DOMAINS`
without it (exact domains; a subdomain is a different domain). A watcher at
another domain is dropped and the operator is alerted; an owner at another
domain stops that application's send. It takes no `--to` or `--cc`, and
`--approve` does not widen it. With no allowed domain the runner logs that the
lane is off and exits 0 (`cti-mailer --lane owner --armed` decides). Replies go
to `GRAPH_MAILBOX`.

### Application owners in owners.db

The owners, watchers, staging links (`covers=`), websites with no scan yet and
the allowed domains live in **`/etc/cti-agent/owners.db`**, edited with
`fleet-owners`, instead of a hand-edited `app-owners.txt`. Every change is
recorded with who made it (`SUDO_USER`) in a history that cannot be edited.

Why it is shaped this way:

- **Python, not Go.** The Go module takes no dependencies and Go has no SQLite
  driver in its standard library (SECURITY.md, Supply chain), so `fleet-owners`
  is Python, like `fleet-db`. After every change it rewrites
  **`/etc/cti-agent/owners.json`** from the same transaction, and that snapshot
  is what `cti-appscan` and `cti-mailer` read. Nothing else writes the
  database, so the snapshot cannot fall behind it.
- **Root only.** `owners.db` is root:root 0600 and `owners.json`
  root:ctiagent 0640. These rows decide who outside the company gets our
  vulnerability reports, and the service account runs an agent that reads
  untrusted mail: it can read them and cannot change them. `fleet-owners` is
  the one wrapper command that runs as root.
- **No silent fallback.** The lanes read `app-owners.txt` only while there is
  no `owners.json`. Once there is one, a snapshot that cannot be read stops
  the owners lane; it never goes back to the file.

**Moving from app-owners.txt** (once):

```bash
sudo cti-agent fleet-owners init
sudo cti-agent fleet-owners import /etc/cti-agent/app-owners.txt \
     --allow-domains "$(sudo sed -n 's/^OWNER_ALLOW_DOMAINS=//p' /etc/cti-agent/fleet.env)"
sudo cti-agent fleet-owners check          # BLOCKS lines stop a send; notes do not
sudo cti-agent run-appowners --dry-run     # same plan as before the move
sudo mv /etc/cti-agent/app-owners.txt /root/app-owners.txt.pre-db
```

The import reports every line it could not use (`watchers=` on a `site:` line,
a placeholder owner, an address that is not one) and imports the rest: fix
those with the commands below rather than in the file. Delete the
`OWNER_ALLOW_DOMAINS` line from `fleet.env` afterwards; with `owners.db` in use
it is ignored, and `cti-mailer` says so.

**Day to day:**

```bash
sudo cti-agent fleet-owners list           # id, scanner name, owner, watchers, covers
sudo cti-agent fleet-owners show id:123456
# after adding or removing web apps in Qualys: names, apps with no owner,
# site: rows a web app now scans, ids Qualys no longer has - with the fix for each
sudo cti-agent fleet-owners sync
sudo cti-agent fleet-owners sync --apply   # makes the set/site rm pairs it printed
sudo cti-agent fleet-owners set id:123456 --owner lead@example.com
sudo cti-agent fleet-owners watcher add id:123456 qa@devshop.example
sudo cti-agent fleet-owners covers add id:123456 www.example.com
sudo cti-agent fleet-owners site set brochure.example.net --owner web@example.com
sudo cti-agent fleet-owners domain allow devshop.example --note "builds the shop"
sudo cti-agent fleet-owners history
```

`fleet-owners sync` runs `cti-appscan --list-apps` itself, so there is no file
to write or feed back. Without `--apply` it changes nothing. With it, it makes
only the changes that follow from owners already on file: a new web app that
scans a `site:` row's domain takes that row's owner (when exactly one unowned
app matches) and the row goes. An app with no owner to inherit, a site the
domains lane no longer lists, and an id Qualys has dropped are reported with
the command, never acted on, because who is mailed our findings is a decision.

**Backup and restore.** `owners.db` is the record; take a copy with SQLite's
backup API, and keep an export you can read and diff:

```bash
sudo cti-agent fleet-owners backup /root/owners-$(date +%F).db
sudo cti-agent fleet-owners export | sudo tee /root/app-owners-$(date +%F).txt >/dev/null
```

To restore, copy a backup over `/etc/cti-agent/owners.db` (root:root 0600), then
`sudo cti-agent fleet-owners snapshot` and `check`. To go back to the file,
`export` to `/etc/cti-agent/app-owners.txt` and move `owners.json` away.

**What is held back.** A scan that did not finish, whose login failed, or that
reached no host, and an application with no line in `app-owners.txt`. The
owners get nothing for that scan; the operator gets one `cti-alert` HOLD
listing them, once per scan. A scan with no web app id (the WAS API was down)
is tried again the next day. Each hold names its reason: for a scan whose notice
says only "Finished", that is what the Qualys scan list says about the run.

**Sent with a warning.** A scan that Qualys finished with **Service Errors
Detected** (the scanner hit errors, so parts of the application may not have
been tested) is not held. Its email and report say plainly that the scan may be
incomplete, with no green "clean" result even when nothing was found; the
AppSec weekly lists it under SCANNER FAULTS and still counts what it found; and
the operator's HOLD alert names it so somebody checks why the scanner hit
errors (often a host or WAF blocking the scanner).

**What is sent.** A short covering email (open findings by severity, what this
scan found, authenticated or not, and a do-not-forward note) with the report
attached as HTML, or as a zip when Qualys's report has images or other files.
Every text file in the report goes through the same redaction as the probe
output (`Cookie`, `Set-Cookie`, `Authorization` and similar headers, token
fields in JSON, session and token parameters in URLs); a file type it cannot
check is left out. A report over 3 MB after redaction is not attached and the
email says so - send that one by hand. The unredacted zip is deleted as soon as
it is redacted, and the whole working directory when the run ends.

**Each scan is sent once.** `$FLEET_HOME/state/appowners-sent.json` holds the
last scan sent or held per application, written only after a real send. The
runner looks back 48 hours, so a late or failed run loses nothing. A test send
and a dry run record nothing, so the real run still sends.

**Before enabling the timer**, read the redacted report from one `--to-dev`
run end to end - search it for `Cookie`, `Authorization`, `sid=` and
`token=`. The redaction was written against Qualys's API output, not a real
HTML report, so check that the evidence sections came through redacted before
any outside address gets one.

```bash
sudo systemctl enable --now cti-agent-appowners.timer
```

### Why remediation is tracked by email, not a Jira project

Decided 2026-11-07. Most application owners have no Jira login and don't work
in Jira, so a separate AppSec project would track work nobody can update. The
owner report and the weekly report are the tracking: each finding stays in
them until a scan no longer sees it. The tickets the lane files (below) stay
where they are. If this proves too passive, the next step, not yet designed,
is a reminder in the owner's email for findings open past a set age, and an
escalation line to the AppSec team for ones that stay open.

### One Jira ticket per application

**Off unless `WAS_TICKETS=1`** in `fleet.env`. The help desk does not want
AppSec tickets in CR and many owners are not in Jira, so the reports now go by
email (above). With it off, `run-appscan` asks for no ticket input and calls
no `cti-jira`; the weekly email has no JIRA TICKETS section. What follows
applies when it is on.

Before the weekly email goes, `cti-jira --appscan-tickets` keeps ONE open
ticket per application (label `cti-appscan-<web app id>`), and the email's
**JIRA TICKETS** section names each one:

- **What is on it:** every active, confirmed finding of Qualys severity 5-3
  (Urgent, Critical, Serious) - not ignored, not fixed - grouped
  by QID, with every URL and parameter, and for each: **Risk**, **What the
  scanner found** and **How to fix it**, from the Qualys KnowledgeBase entry
  for the QID. Medium and Minimal are a count. The full list is attached.
- **Potential findings, listed on purpose:** the scanner's own
  **unconfirmed** findings of severity 4 (Critical) and 5 (Urgent) get a
  separate "POTENTIAL - please verify" section under a callout saying they are
  not confirmed - and that not confirmed does not mean not there. Each line is
  labelled `POTENTIAL <sev> - unconfirmed, please verify`, and the ticket header
  and email count them apart ("To verify: ..."). Potential Serious and below
  are still left out. They are part of the findings fingerprint, so an open
  ticket gets one comment the first time a potential appears or goes away.
- **Who it is assigned to:** the owner in `/etc/cti-agent/app-owners.txt`
  (`APPSCAN_OWNERS_FILE`), looked up in Jira by email. Not listed, or not
  exactly one active Jira user with that address: filed **unassigned**, and the
  email says so. If Jira refuses the assignee or component, it is filed
  without them.
- **Each week:** a comment only when the findings changed (what is new, in
  full; what is no longer detected); nothing when they did not; "nothing of
  Serious or above left - it can be closed" once.
- **Built from every open finding** Qualys holds (NEW, ACTIVE, REOPENED),
  however long ago last detected - not just this week's detections, which would
  read a page the week's scan did not reach as fixed.
- **Left alone** that week when the scan did not complete, failed to
  authenticate, was a discovery scan, was not matched to the WAS scan list, or
  the open findings could not be fetched - a scan that did not cover the
  application must not tell its ticket everything was fixed.
- **Optionally, the scanner's own report is attached** (`WAS_ATTACH_REPORT=1`,
  off by default): see "Attaching the scanner's report" below.
- `--dry-run` and `--to-dev` preview only, writing the would-be ticket text to
  `state/appscan-tickets-preview-DATE.txt` (0600), not the journal. Jira
  trouble never stops the email.

Owners come from `owners.db` (see "Application owners in owners.db" above).
Before the move, they came from the file, set up from the scanner's own list:
`--list-apps` keeps every owner already on file, adds each new web app with
`OWNER@example.com`, and lists stale lines at the end; the weekly email also
names any web app with no owner, so re-run it when one appears:

```bash
sudo cti-agent cti-appscan --list-apps > /tmp/app-owners.txt
vi /tmp/app-owners.txt                     # replace every OWNER@example.com
sudo install -o root -g ctiagent -m 0640 /tmp/app-owners.txt /etc/cti-agent/app-owners.txt
rm /tmp/app-owners.txt
sudo cti-agent run-appscan --to-dev        # the JIRA TICKETS section previews every app
```

The Jira API account needs the **Browse users and groups** global permission
to look owners up; without it every ticket is filed unassigned.

**Watchers.** A line may add `watchers=a@example.com,b@example.com` (up to 10,
any field order) to copy others on the application's ticket. The owner field
stays ONE email - the assignee. `cti-jira` adds each watcher on create and on
every weekly comment, so watchers added to the file later are picked up. Each
is looked up by email like the owner; one not found, invalid, or refused is
logged and skipped and never blocks the ticket. Needs the **Manage watcher
list** permission on the Jira API account. Watchers are not shown in the
weekly email. Separate emails with commas, spaces or `;`. Adding is one-way:
removing someone from the file does not remove them in Jira, and someone who
unwatches there is re-added at the next weekly comment. `watchers=` on a
placeholder-owner line is ignored until a real owner is set (and lost when
`--list-apps` regenerates the file); on a `site:` line it is ignored with a
problem line. `--list-apps` keeps it on lines with a real owner.

```
id:123456 | dev.lead@example.com | Web Portal | watchers=a@example.com,b@example.com
```

**Coverage: live websites nothing scans.** The domains lane writes our live
websites to `state/domains-websites.json` each week (redirects, registrar
landers, parked pages and domains marked `landing` in `domains.txt` left out).
The weekly AppSec email lists any that no Qualys WAS web app points at under
**NOT SCANNED**, and `--list-apps` adds a `site:<domain>` line for each - the
owner there is who should get a web application scan set up. The line drops
out once a web app covers the site; the `site:` row in `owners.db` does not,
until `fleet-owners sync --apply` hands its owner to the new web app and removes
it. If a listed site is really a landing page,
mark it `landing` in `domains.txt` instead.

Recurring tickets link back. When a new ticket is filed for an application
that already had a closed one, the new ticket says "Recurring: this
application's previous ticket, KEY, is done", says how many of its findings
were on that ticket when it was last updated, and is linked to it with a Jira
"Relates" link. The preview prints the same note and a "would link to" line.
This needs the Jira "Link issues" permission, shown by `cti-jira --check` as
`LINK_ISSUES`. Without it the link is skipped and logged; the ticket is still
filed. A comment on an open ticket never looks for an earlier one.

### Staging copies that stand in for production

Some production sites are scanned through a staging or test copy instead of
directly - a WordPress site on WP Engine, say, whose Qualys WAS web app points
at the `*.wpenginepowered.com` staging install, because intrusive DAST tests
belong on staging, not on the live site. Without telling the fleet, the
production site shows under NOT SCANNED, which is wrong, and the staging web
app's ticket reads as if staging were the thing to fix, which is also wrong.

**Record it on the staging web app's line** in `app-owners.txt`:

```
id:777777 | dev.lead@example.com | Web | covers=www.example.com
```

(`covers=` takes several hosts, comma-separated; `www.` is ignored. It can sit
with or without a Jira component.) From then on:

- **The weekly email** moves the production site from NOT SCANNED to
  **COVERED VIA STAGING**, naming the staging host and web app id, with
  "production not scanned directly".
- **The staging web app's ticket** carries a *Stands in for* line: fix it in
  the code, plugins or configuration, then deploy - and check anything
  configured only on production.
- **`--list-apps`** keeps `covers=` when it regenerates the file (even on a line
  whose owner is still the placeholder), lists the covered-via-staging sites
  as comments, and flags any web app whose URL *looks* like staging (a
  hosting provider's staging domain, or a host starting `staging`, `dev`,
  `test`, `uat`, `qa`...) that has no `covers=` yet.
- A site that a web app also scans **directly** is reported as scanned, never
  as via staging.

**What a stand-in does not tell you.** It tests the code and plugins. It does
not test production's own edge, CDN, WAF, TLS settings, security headers,
caching, or anything installed or changed only on production. Two things are
worth doing for every stand-in:

1. **Lock the staging copy down.** A public staging site with production
   content is a second, less-watched copy of the site - drafts, debug output,
   old plugins. Put it behind the host's password protection (WP Engine has a
   per-install switch) and `noindex`.
2. **Add a light scan of production** - a Qualys WAS web app for the live URL
   on a crawl-only / non-intrusive option profile. It catches configuration
   drift without attack payloads against the live site. The production site
   then shows as scanned directly, and the stand-in still carries the
   intrusive tests.

### A different audience, enforced in code

This mail goes to the people who own application code — not the people who
patch servers. The split is not a convention: `cti-mailer --lane was` resolves
`WAS_TO` against `WAS_ALLOW_TO` and **refuses if either is unset**. It does not
fall back to the digest audience, and `--approve` does not override an empty
allowlist.

### Authenticated and unauthenticated scans are both normal

Every count in the report is labelled with the kind of scan that produced it.
That is a statement of scope, not a defect:

- **unauthenticated scan** — covers what a visitor can reach without logging
  in. For a site with no login that is the whole application.
- **authenticated scan** — the scanner logged in, so the pages behind the login
  were tested too.

The report does **not** treat an unauthenticated scan as a coverage gap. An
earlier version did, and named three public sites with no login as having one
— a standing complaint with nothing behind it and nothing anybody could do.

### What does raise a fault

`SCANNER FAULTS` appears only for two things, and both are yours rather than
the App Dev team's:

| Fault | Means | Where to look |
|---|---|---|
| `authentication failed` | A credential **is** configured and did not work. The scan covered the public surface while still looking configured, so this week's counts are not comparable with last week's | The authentication record in Qualys WAS |
| `scan did not complete` | Cancelled, errored, or hit a time limit. Its counts describe a crawl that stopped partway, so none are reported | The scan schedule and the scan's own log in Qualys |

An authentication failure also **emails you** through `cti-alert`, kind `HOLD`,
because the people receiving the report cannot fix a scanner login. The runner
sends the report first; an alerting problem never costs the weekly mail.

```bash
# which applications failed to authenticate on the last run
sudo cat "$FLEET_HOME"/state/appscan-authfail-$(date -u +%F).tsv
```

The file is written on **every** run. Empty means "checked, none failed";
absent means the binary predates `--auth-fail-out` and nothing was checked. The
runner says which in its log, because those two look identical from the mail.

### Links in the report

Each application shows one report link, under OPEN NOW. A link that came from
the scanner's email is **plain text** — the mail arrived at a published
address, and the findings name attackable paths on our own sites. A link the
lane builds from the scanner's API record is **clickable**, after an https and
host check: `https://qualysguard.<pod>/was/#/reports/online-reports/email-report/scan/<scan id>`,
the same page Qualys's own email links to, with the pod taken from
`QUALYS_BASE_URL`. A built link that fails the check is not printed; the
email's link is used instead. Without Qualys credentials there are no built
links.

### What the scan list adds

With Qualys credentials the lane also reads the WAS scan list and joins it to
the mailbox on the scan reference. The run logs one line saying what it found:

```text
[appscan] scans  : 20 in the WAS scan list, 9 matched a notification, 1 added with no notification, 10 skipped (discovery, in flight, or on-demand faults)
```

- **Real application names**, and per-finding detail looked up by the
  application's id. A `note : ... has no application id` line means a
  notification did not match, and its detail was looked up by name instead.
- **SCANNED, NO NOTIFICATION** lists vulnerability scans Qualys ran whose
  completion email never arrived — usually a scan with no notification
  configured. They have no counts; the report says so rather than printing
  zeroes.
- Discovery scans, scans still running, and on-demand runs that failed or were
  cancelled with no email are skipped. A **scheduled** scan that fails to log
  in is a fault and alerts you, email or not.

### A different window

`run-appscan` takes only `--dry-run`. For a two-week test, run the binary and
send it yourself:

```bash
S=/var/lib/cti-agent/state
sudo cti-agent cti-appscan --since 336h --out $S/appscan-14d.html --text-out $S/appscan-14d.txt
sudo cti-agent cti-mailer --lane was --to you@example.com --for-real \
  --html $S/appscan-14d.html --text $S/appscan-14d.txt --subject "[TEST 14d] AppSec"
```

The copy still says "this week", and each application still gets one row from
its newest scan. An address outside `WAS_ALLOW_TO` needs `--approve`.

### How the scanner found it

Tickets now show how the scanner found each finding: the request it sent, the
payload (when it injected one), the pages it crossed to reach it, and an
excerpt of the response. The ticket shows one place in full; the attached file
has it for every place. Request headers are never read, and `Cookie`,
`Set-Cookie` and `Authorization` lines in a response excerpt are redacted, so
this works without `WAS_ATTACH_REPORT`.

### Attaching the scanner's report

`cti-appreport` fetches the scanner's own per-application report (Qualys WAS:
create, poll, download as HTML_ZIPPED, delete) and `cti-jira --appscan-reports`
attaches it when the ticket is filed or its findings change. Each report is
about five API calls, so only the applications about to be filed or commented
are fetched. **The report contains the scan account's session cookies**: it is
`0600` in a `0700` directory, deleted from Qualys after download, and the
runner deletes the directory after `cti-jira` has attached it.

The Qualys Report API element names are not verified against a live account in
this repository, so test on the box in this order before turning it on:

```bash
sudo cti-agent cti-appreport --list-ids                    # app ids from the last weekly run; no API calls
sudo cti-agent cti-appreport --check                       # credentials, API budget
sudo cti-agent cti-appreport --app-id <id> --dump-request  # the body it would send; nothing sent
sudo cti-agent cti-appreport --app-id <id> --out-dir /tmp/r --keep   # one real report, left in Qualys to inspect
sudo cti-agent cti-appreport --app-id <id> --out-dir /tmp/r          # again, now deleted from Qualys
(umask 077; sudo cti-agent cti-appreport --probe-findings <id> > /tmp/probe.xml)   # raw finding fields, redacted, 0600
sudo rm -rf /tmp/r /tmp/probe.xml
```

If the request is rejected, correct the field in a copy of the dumped body and
send it with `--request-file FILE` (`{{APP_ID}}` and `{{NAME}}` are filled in)
instead of rebuilding. Check the unzipped report opens and the probe shows the
fields you expect, then set `WAS_ATTACH_REPORT=1` in `fleet.env` and run
`sudo cti-agent run-appscan --to-dev` (previews only; nothing is attached).
`--to-dev` fetches the reports, as a real run does (created and deleted in
Qualys), so `appscan-tickets-preview-<date>.txt` names each attachment and its
size; `--dry-run` fetches nothing and says so. Friday's real run attaches. A report that cannot be
fetched is logged and the ticket goes out without it; it never stops the email.

To see exactly what a developer would receive, file one clearly-labelled test
ticket for a single application:

```bash
sudo cti-agent run-appscan --dry-run     # leaves /var/lib/cti-agent/dryrun/appscan/appscan-tickets-<date>.json
sudo cti-agent cti-appreport --app-id 1234 --out-dir /tmp/report
T=/var/lib/cti-agent/dryrun/appscan/appscan-tickets-$(date -u +%F).json
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --appscan-reports /tmp/report --dry-run    # preview
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --appscan-reports /tmp/report --for-real  # files it
sudo rm -rf /tmp/report
```

The test ticket is "[TEST] ...", labelled `cti-agent-test` only (the weekly
run never finds or comments on it, the follow-up skips it), unassigned, with no
component or watchers, and nothing is recorded in state. The fleet notifies
nobody, though Jira's own notification scheme (or a default assignee, if the
project sets one) still applies to any new issue. It carries the findings
text and the scanner report. `JIRA_ALLOW_CREATE` still gates it; an id not in
the file, or one the weekly run would leave alone, is refused. Afterwards delete
the ticket in Jira and `/tmp/report`: the report holds the scan account's
session cookies. If you used `--keep`, also delete that report in Qualys under
WAS > Reports.

The other settings are in `fleet.env` section 2 and rarely need touching.
`QUALYS_RL_RESERVE` (default 5) is how many API calls the report work leaves for
the VM lane and KnowledgeBase lookups; when only that many remain, reports give
way. `QUALYS_RL_MAX_WAIT` (default 5m) is the longest it sleeps out a rate-limit
refusal. It follows the limits Qualys reports in its response headers, so there
is nothing to change when the contract's limits are raised.
`APPSCAN_REPORT_PROVIDER` (default `qualys-was`) names the scanner; another
one implements `appscan.ReportFetcher` and is added in `cmd/cti-appreport`.

### Closing the ticket of a deleted web app

When a web app is deleted in Qualys WAS, the Friday run closes its open Jira
ticket with an explanatory comment (the domains lane still only reports a
retired or redirecting site; deleting the web app and its scheduled scan is a
manual step). Guards:

- only when `cti-appscan` fetched the scanner's complete web-app list that run
  (`scannerApps` in the `--tickets-out` file); a failed or skipped fetch closes
  nothing;
- only open tickets labelled `cti-appscan` and `cti-appscan-<numeric id>` that
  also carry the fleet's own `cti-appscan` state property (a label alone can be
  added by anyone who may edit a ticket); name-keyed apps are never closed;
- the list must agree with the run: if an application scanned this week is
  missing from it, nothing is closed; a tickets file more than 24 hours old
  closes nothing;
- at most 3 per run, and never more than half of the open AppSec tickets when
  more than one: more would-be closures than that close NONE and log a warning
  (that looks like lost scanner visibility, not retirements); a full search page
  (100 open tickets) also skips;
- the gate is `JIRA_ALLOW_CLOSE` (project keys, empty = never close),
  independent of `JIRA_ALLOW_CREATE`, plus `--for-real`. `run-appscan --dry-run`
  prints "===== would close KEY via transition ...";
- the transition is the one whose destination status category is Done, not
  picked by name; if several lead there set `JIRA_CLOSE_TRANSITION`
  (case-insensitive). A transition needing a required field other than
  resolution or comment is refused; a resolution field is set to "Done"; the
  comment goes in the same request.

The service account needs "Transition issues" in the project (`cti-jira
--check` lists TRANSITION_ISSUES once `JIRA_ALLOW_CLOSE` is set). Closing is
reversible by reopening; if the app returns with findings a new ticket is filed
and linked (Relates) to the closed one. Afterwards the app's owners-file line
can go (a line matching nothing is a harmless warning).

Rehearse first, on a test ticket (it refuses any other, including the weekly
run's own):

```bash
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --for-real   # files a [TEST] ticket, say CR-NNN
sudo cti-agent cti-jira --list --all                                          # finds the test ticket's key (kind "test")
sudo cti-agent cti-jira --appscan-close-test CR-NNN --dry-run                 # preview
sudo cti-agent cti-jira --appscan-close-test CR-NNN --for-real                # closes it
```

### When Jira refuses the weekly comment (HTTP 403, an HTML page)

`commenting on CR-NNN failed: ... HTTP 403: <!DOCTYPE HTML ... ERROR: The request
could not be satisfied` is a firewall's page in front of the Atlassian gateway,
not a Jira permission. It can refuse a comment's text even though the same text
was accepted as a ticket description. To find which lines, rehearse on a test
ticket (it refuses any other, including the weekly run's own):

```bash
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --for-real            # files a [TEST] ticket, say CR-NNN
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --appscan-comment-probe CR-NNN --dry-run   # preview
sudo cti-agent cti-jira --appscan-tickets $T --appscan-test 1234 --appscan-comment-probe CR-NNN --for-real  # posts, bisects
```

It posts a one-line control, then the whole comment the weekly run would post
for that application, and if that is refused it halves it by line until it names
the refused lines (at most 80 comments on the test ticket). "Refused only as a
group" means size or a combination, not one line. Delete the test ticket after.

### Adding a second scanner

`internal/appscan` is a provider boundary, like `internal/vulnlookup` for host
VM. A new scanner needs a `Provider` — `Name`, `Recognises(sender, subject)`,
`Parse(body)` — and nothing else; no credentials are required to implement one,
so Invicti or Wiz becomes useful the day its email arrives rather than the day
somebody negotiates API access. A provider that *does* have an API additionally
implements `DetailFetcher`, and losing that costs per-finding detail and not
the report.
