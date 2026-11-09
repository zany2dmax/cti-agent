# Changelog

## How this is versioned

Not SemVer. This is an internal tool with one operator, not a library with API
consumers, so "breaking change" in the SemVer sense means very little here.

The version answers a different question — **does upgrading require you to do
something?**

| Bump | Means | What you do |
|---|---|---|
| Patch — `1.0.1` | Fixes. Behaviour you already relied on now works | Pull, reinstall |
| Minor — `1.1` | New lanes, new output. Nothing existing changes meaning | Pull, reinstall. Read the entry in case a new feature wants configuring |
| Major — `2.0` | **The fleet will not work correctly until you act** | Read the entry first. New credentials, new permissions, a manual migration |

Every entry below ends with **Upgrade** saying exactly that. If it says
"nothing", there is nothing.

### Finding out what is deployed

```bash
sudo cti-agent cti-mailer --check | head -2     # what the binary says it is
sudo cat /etc/cti-agent/version                 # what the last install recorded
```

They should agree. If `--check` warns that they disagree, that binary was not
replaced by the last install and predates whatever else was — which is what a
partial install leaves behind.

A build from a working tree with uncommitted changes reports `-DIRTY`. That is
allowed, and sometimes necessary to test a fix on the box that has the problem,
but such a build cannot be reproduced from its commit, so "production matches
the tag" stops being a true statement until it is rebuilt from a clean tree.

---

## Unreleased

### Added

- **`cti-agent-update` has a man page and tab completion.** `man
  cti-agent-update` covers both modes, what each checks before it pulls, and
  the exit codes. In bash and zsh, `sudo cti-agent-update <TAB>` offers
  `--dry-run` and `--for-real`, tagged or coloured by risk like `cti-agent`'s
  own completion, and offers nothing more once a mode has been given. The
  updater is not in the command manifest, so a test now ties its flags to the
  page and both completions. **Upgrade:** re-run the installer, then open a
  new shell.

- **A record of what each heartbeat did: beat traces.** Every check-in beat
  now runs with the CLI's `stream-json` output, kept as one file per beat in
  `state/traces` (0600, in a 0700 directory, kept 14 days). It holds the model
  and tools the beat started with, every tool call with its arguments, which
  calls failed or were denied, what the beat said, and the turns, tokens and
  cost at the end. `sudo cti-agent fleet-trace show --last` prints a beat as a
  timeline (`--full` adds each tool's output), and `fleet-trace list` gives
  one line per beat. The journal shows the same timeline, without tool
  output, in place of the raw text. A trace holds the untrusted text the beat
  read, so the beat cannot read traces (no grant on `state/`, `fleet-trace` is
  not granted), and `show` strips terminal escapes from it. `cti-budget`
  still classifies only what the CLI's text mode used to print (stderr, API
  errors, the final result), so token counts and tool output cannot turn an
  ordinary beat into a rate-limit or out-of-credit hold. Traces are
  best-effort: if `state/traces` cannot be written the beat runs untraced and
  says so, and a trace that hits `CHECKIN_TRACE_MAX_MB` stops recording, not
  the beat. New command `fleet-trace`, with a man page; HARNESS.md, item H1.
  **Upgrade:** re-run the installer. Optional: `CHECKIN_TRACE_DAYS` (default
  14; 0 turns traces off) and `CHECKIN_TRACE_MAX_MB` (default 20) in
  `fleet.env`.

- **The supplier-request lane: judge each new supplier request and point the
  security team at their Kanban board.** `run-supplier` (timer
  `cti-agent-supplier`, daily 07:45, `FLEET_SUPPLIER_TIME`, off until enabled;
  does nothing until `SUPPLIER_ADDRESS` is set) finds each new request in the
  shared mailbox - a conversation with that address in To or Cc - reads the
  message text and the supplier request form (an `.xlsx`, read by its labels;
  never the W-9 or bank attachments, which a policy refuses by type and by
  name), and judges it: will this supplier touch company data, systems or
  networks, or provide technology? A Yes, and an Unsure (no certain Yes, so
  treated as critical), each get a Jira item in `SUPPLIER_JIRA_PROJECT` (found
  again by a label, never filed twice); a No appears in the digest only. One
  digest email to `SUPPLIER_TO`, checked against `SUPPLIER_ALLOW_TO` (no
  fallback), links the board; a day with no new requests sends nothing. A form
  shared as a link is not opened - that request is Unsure, with the reason.
  A request already reported that gets a newer message in its thread is judged
  again; if the verdict changed (or the form is now read) a comment is added to
  its existing item and the digest lists it as updated - the lane never closes,
  reopens or edits an item. Each Yes or Unsure item says what information is
  still needed (the form, blank required fields, what the supplier provides), in
  fixed wording. A request whose item could not be filed is no longer recorded as
  reported, so the next run files it.
  `task eval:supplier` runs the real model on 42 invented requests (by hand,
  never in ship) and reports how often its verdict is the one wanted, failing
  only when a supplier would have been waved through.
  The mail filter's quarantine digest, which also lands on the list, is left
  out (the address already in `MAILBOX_DIGEST_SENDERS`, exact sender and
  subject) and counted in the digest; nothing else is skipped.
  The judgement is a Claude session with **no tools** (`SUPPLIER_MODEL`); code
  checks its quotes against the request and can only move an answer toward
  Unsure, and with no model, or one that is down, every request is Unsure.
  New commands `cti-supplier` and `run-supplier`, with man pages; new
  packages `internal/supplier` and `internal/xlsx` (the `.xlsx` reader moved
  out of `internal/netmap`, behaviour unchanged). **Upgrade:** re-run the
  installer; set the `SUPPLIER_*` settings in `fleet.env` (see
  `fleet.env.example`), add the project to `JIRA_ALLOW_CREATE`, run
  `sudo cti-agent run-supplier --dry-run`, then `--to-dev`, then enable
  `cti-agent-supplier.timer`.

- **The weekly Qualys VM scan report: the two scheduled scans in one email.**
  `run-vmscan` (timer `cti-agent-vmscan`, Mondays 08:00, `FLEET_VMSCAN_TIME`)
  reads the "Qualys: Scan Results" notices for "Weekly Scheduled Scan for
  Main Sites" and "North/East Weekly" from the CTI mailbox and sends one email to
  `VMSCAN_TO`, checked against `VMSCAN_ALLOW_TO` (no fallback; set both to
  `$VM_ALLOW_TO` to reuse the VM audience - a lane's recipient list may now
  reference another list the way an allowlist always could), with the two scans in separate
  sections: that it ran, when and for how long, addresses scanned and alive, and
  the locations it covered (its Qualys Target Groups). It carries no severity
  counts, on purpose: the audience does not act on them from this email and the
  two scans overlap. A scheduled scan with no result leads the report
  (`[NO RESULT]` in the subject), and one that did not finish is `[INCOMPLETE]`.
  The notices it used are recorded after a real send, so the mailbox cleanup
  archives them 48 hours later; the other Qualys notices for the same scan are
  left alone. `VMSCAN_SCANS` changes which scans are combined. New commands
  `cti-vmscan` and `run-vmscan`, with man pages.
  The report also **checks the network spreadsheet against the Qualys Asset
  Groups the scans cover**, by address, and says which corp networks no scan
  reaches (in no Asset Group, in a group no scan covers, or only partly
  covered), which scanned groups hold addresses the spreadsheet does not, and
  which locations it could not decide. It only reads; it never guesses a
  location's corp network. The spreadsheet is the network team's: where it is
  wrong or unclear (no corp row, a blank or invalid network, one outside its
  location's own block, an overlap) the email lists it for them to correct, by
  row, and that location is not checked until they do. Nothing is escalated to
  the operator. An optional `/etc/cti-agent/netrules.txt` lets the security team
  record how to treat a location meanwhile. The email is written for the network and
  acquisitions teams as well as security: each line names the location, the
  spreadsheet row and what to do (not scanned, fix in the spreadsheet, check in
  Qualys; why a network is not scanned is left to the network and M&A teams, with
  a blank column for them in the CSV), the findings are attached as a CSV worksheet,
  and it ends with how the spreadsheet has to be laid out to be read. It needs
  `SUBNETS_DRIVE_ID` and
  `SUBNETS_ITEM_ID` and a Graph application permission that reaches the file
  (`Sites.Selected` on the site, or `Files.Read.All`); without them the report
  says the check did not run. New: `internal/netmap`, `Client.DriveItemContent`.
  **Upgrade:** re-run the
  installer and set `VMSCAN_TO=$VM_ALLOW_TO` and `VMSCAN_ALLOW_TO=$VM_ALLOW_TO` in
  `fleet.env`, then enable
  `cti-agent-vmscan.timer`. For the North/East scan's notices to reach the mailbox,
  reassign that schedule to the scan service account and set its notification From
  Address to `qualys@qualys.net` (see RUNBOOK).

- **Ask the CLI instead of remembering it: a command list, usage and TAB
  completion.** `sudo cti-agent` with no arguments lists every fleet command
  and whether it only reads, writes its own files, or changes something
  outside (`effect`); `sudo cti-agent <command> --help` shows that command's
  flags and subcommands without running it. The installer adds bash and zsh
  completion, so TAB after `cti-agent` lists the commands and TAB after a
  command lists its flags (and `fleet-db`'s or `fleet-board`'s subcommands).
  With several matches each is shown with a description and how risky it is
  (read-only, writes its own files, CHANGES THINGS), and a command's flags are
  split into REQUIRED (say how to run it) and optional; zsh colours the groups
  green, yellow and red, and bash, which cannot colour a completion list, writes
  the tag out in words. A flag's risk comes from the manifest's `risk:` lines.
  All of it reads one file, `fleet-kit/fleet/commands.manifest`, installed as
  `/opt/cti-agent/commands.manifest`, so it cannot go stale: a test fails the
  build when a command or a flag exists in the code and not in the manifest, or
  the reverse. **Upgrade:** re-run the installer, then open a new shell.

### Changed

- **Quarantine digests are cleaned up, and fleet mail held in quarantine is
  reported.** The shared mailbox receives "End User Digest" mail - its own and
  that of distribution lists it is on - and nobody reviews quarantine through
  it, but the filter can hold something a lane needs: a Qualys notice or a
  threat-intel feed. With `MAILBOX_DIGEST_SENDERS` set to the digest's sending
  address, the mailbox cleanup reads each digest's list of held messages
  (sender and subject text only; every link is discarded). If none is from a
  sender the fleet reads - a Qualys domain, or one in the new
  `MAILBOX_FEED_SENDERS` - the digest goes to Deleted Items on sight, whoever
  it is addressed to. If one is, the digest stays for a week and the operator
  is told, on the board and by `cti-alert` (ESCALATION), the morning it
  arrives, to release it in the quarantine portal. The fleet never releases
  mail: the digest's Release link acts on a bare GET. A digest whose rows
  cannot be read stays, in case its layout changed. `cti-mailbox` now reads
  message bodies as HTML. **Upgrade:** re-run the installer and set
  `MAILBOX_DIGEST_SENDERS` and `MAILBOX_FEED_SENDERS` in `fleet.env`; blank
  leaves the rule off.

- **The scan lanes now clear the other Qualys notices of a scan they reported
  on.** Qualys sends more than the results for each scan: a "scheduled to
  start" notice before a WAS run, and "Scan Completed" plus the task-owner
  "Completed Vulnerability Scan Notification" after a VM scan. None carries
  anything the weeklies use, and nothing claimed them, so they stayed in the
  shared inbox for good (about 14 in the last month). Now, after a real send,
  `cti-appscan` claims the scheduled notice of each WAS run that completed,
  and `cti-vmscan` claims the two companions of each VM scan that finished,
  and the mailbox cleanup moves them to **Deleted Items** (recoverable)
  instead of Archive, after the same grace and not on a held day. Each must
  come from Qualys and match its run: the WAS notice by title and a launch time
  just before the run started, "Scan Completed" by the run's report reference,
  the task-owner notice by an identical title and launch time. A run that did
  not complete keeps its notices in the inbox for a person. New:
  `mailbox.Processed.Delete`, carried through `Merge` from the lane's log.
  **Upgrade:** re-run the installer; it takes effect from the next weekly run of
  each lane.

- **Every command that changes something has to be told how to run.** Each
  one now takes exactly one of `--dry-run` (do everything but the change and
  show what it would do) or `--for-real` (do it), and the ones that have a test
  send also `--to-dev` (which may go with `--dry-run`). With none, the command
  prints usage and exits 2 without touching anything. There is no default,
  because a default is a choice made for you and remembered by nobody: the
  mailbox lane used to rehearse unless told `--for-real` while every other lane
  acted unless told `--dry-run`, so the command an operator typed from habit
  did the opposite of what they meant. The same rule holds for a person, a
  systemd unit and the heartbeat agent. Covered: `run-digest`, `run-appscan`,
  `run-domains`, `run-appowners`, `run-patchtuesday`, `run-mailbox-cleanup`,
  `run-checkin` (`--for-real` fires a beat, `--dry-run` is `--audit`),
  `cti-alert`, `cti-mailer`, `mailer.py`, `cti-mailbox` and `cti-jira`
  (`--check` only reads and needs none). `fleet-owners`, `fleet-db` and
  `fleet-board` write only their own data and are not changed. Every systemd
  unit now passes `--for-real`, so a unit that loses its flag fails loudly and
  `cti-alert` emails you. A test fails the build if an effect command stops
  refusing a missing mode, or a timer stops saying `--for-real`.
  Two things moved because `--for-real` now means "send":
  `run-patchtuesday`'s already-sent guard used to be skipped by `--for-real`, so
  skipping it now takes `--resend` (`--for-real --resend`), and a past
  `--month` is replayed with `--dry-run` (it used to be "rendered, not sent"
  with no flag). The heartbeat's tool grant for the mailbox plan is the exact
  command `cti-mailbox --dry-run`, and its `cti-alert` calls say `--for-real`.
  **Upgrade: this one changes how you type commands.** Re-run the installer.
  Afterwards `sudo cti-agent run-digest daily` (and every `run-*`, `cti-jira`,
  `cti-mailer`, `cti-alert` and `cti-mailbox` without a mode) prints usage
  instead of running; add `--dry-run` or `--for-real`. Notes and scripts of
  yours that call these without a mode need the same.

### Added (updating)

- **`cti-agent-update`: one command to update the box.** There are two checkouts
  on the box: the kit (`install-fedora.sh`, the runners, the units, the manifest)
  and the Go source under `/opt/cti-agent/agent`, which the installer pulls
  itself. Nothing pulled the kit, and the installer runs from it, so the old
  "`git pull`, then the installer" was easy to do halfway or in the wrong order,
  and a tag pushed after the commit it names left a box reporting the wrong
  version. `sudo cti-agent-update --for-real` pulls the kit (with tags), then runs
  the installer from the updated kit; `--dry-run` shows what is incoming and
  changes nothing. It says how to run, like every command that changes
  something. It refuses a kit with local edits or one inside the installed tree,
  says when the result is not an exact release tag, and survives updating its own
  file. The installer puts `cti-agent-update` in `/usr/local/sbin`; before that,
  run `fleet-kit/update-fedora.sh` by path. **Upgrade:** re-run the installer once.

### Fixed

- **A typo on `cti-agent-update` pulled the kit and then installed nothing.**
  Anything other than `--dry-run` or `--for-real` was passed on to the
  installer, which refuses every option it could receive, so `sudo
  cti-agent-update --for-real --foo` fast-forwarded the kit and then stopped.
  An unknown argument is now refused before anything is fetched (exit 2), the
  installer is always run with no arguments, and `--help` prints the usage
  line. **Upgrade:** nothing; it takes effect at the next update.

- **Section headings in the Go lanes' emails showed in lowercase in Outlook.**
  They were typed in normal case and relied on a CSS `text-transform` that
  Outlook ignores, so "Coverage check" and its like appeared as written. The
  capitals are now written into the heading. **Upgrade:** nothing.

- **The mailbox cleanup archived nothing on a day with no new CVEs.** Its
  health check ("has the digest read the mailbox today?") asked for a message
  that carried a CVE, so on a quiet day - newsletters, Qualys notices and
  supplier mail all read, none naming a CVE - it decided the fleet "may not be
  reading the mailbox" and held every archive. The Qualys WAS and VM notices
  the weekly lanes own stayed in the inbox on every such day, and once older
  than `MAILBOX_LOOKBACK_HOURS` (14 days) they were never looked at again. The
  check now counts any message the digest read today except automatic
  replies, so a day of only out-of-office replies still holds. The hold
  message now reads "the digest has read no mail today". Mail already older
  than the lookback is not swept by this; a one-off
  `sudo cti-agent cti-mailbox --lookback 720h --timeout 10m --dry-run` shows
  what a longer window would do. **Upgrade:** nothing; it takes effect at the
  next cleanup.

## 1.5.2 — 2026-11-07

**Upgrade:** pull and re-run the installer. Nothing else is required.

### Fixed

- **The lock-down ticket stopped updating once its list got long.** Jira
  refuses a comment or description over 32767 characters, all or nothing, and
  the weekly list of 206 DNS changes plus 7 to review went over it
  (`INF-590 ... exceeds the allowed limit of 32767 characters (HTTP 400)`), so
  the ticket was not updated and the lane only said so in the journal. Text over
  30000 characters is now posted as several comments at line breaks, each saying
  "part n of m"; a description that long becomes the first part with the rest
  added as comments. This covers every Jira write, not only the domains ticket.
  The report email was never affected. **Upgrade:** nothing; the next domains
  run updates the ticket.

- **The AppSec weekly no longer says "nothing urgent open" about scans it has
  no counts for.** A week with one counted scan and twelve whose completion
  notices never arrived (the scanner account's notices were being sent from the
  team mailbox and, correctly, not read) was subject-lined as an all-clear. The
  subject and the opening paragraph now say how many scans have counts and how
  many do not: "nothing urgent in the 1 scan(s) with counts; 12 scan(s) have
  none", or "no counts for 12 scan(s)" when there are none at all. A week where
  every scan has counts reads as before. **Upgrade:** nothing.

## 1.5.1 — 2026-11-07

**Upgrade:** pull, then re-run the installer (it pins three more timers to
`FLEET_TIMEZONE`, installs `email-tokens.json` and the `FLEET_MAILBOX_TIME`
drop-in). Set `PROOFPOINT_POD_IPS` (comma separated) if the mail admin lists
PoD addresses in SPF. Nothing else is required.

### Added

- **`fleet-owners list` shows each application's name.** An id says which
  application; the name says which one to a person, so you no longer look it up
  in Qualys. Names are kept beside each entry (a new `app_names` table, created
  on first use in an existing `owners.db`, no schema change), shown by `list`
  and `show`, and never written to `owners.json`, so no lane reads them and
  they decide nothing. `fleet-owners names FILE` fills or refreshes them from a
  `cti-appscan --list-apps` listing; `import` takes them from the file it
  loads. Names come from the scanner, so they are stripped of control
  characters and capped before they reach your terminal.

### Changed

- **One place for what a fleet email looks like.** `internal/emailkit` holds the
  palette, the font and the 640px card, and the pieces every email is built
  from: header band, lead block, severity tiles, section headings, cards,
  callouts and a footer that carries the `FLEET_ATTRIBUTION` credit. (A CSS
  file cannot do this: Outlook ignores linked stylesheets, which is why the
  emails are inline-styled tables.) The application-owner email, the AppSec
  weekly, the domains report, the Patch Tuesday synopsis, `cti-alert` and the
  Go mailer's escalation are all built from it, so the domains report, alerts
  and escalations now carry the attribution line too, and Patch Tuesday and
  alerts are the standard 640px instead of 680. An alert keeps a colour-coded
  header band (red failure, amber hold, green test, navy escalation) and now
  has a lead block with its "WHAT THIS MEANS" paragraph.
  `TestNoLaneDrawsItsOwnPageShell` fails the build when a Go lane writes its
  own header band or page background.
- **The daily digest shares the palette.** The colours and font are one file,
  `internal/emailkit/tokens.json`, which the Go lanes embed and `brief.py` reads
  from `lanes/email-tokens.json` (installed by `install-fedora.sh`); a Go test
  fails when the two copies differ, and a Python test pins `brief.py`'s built-in
  fallback (used if the file is missing) to the file. Change the look in
  `tokens.json`, then `cp` it over the lanes copy.
- **The application-owner emails match the rest of the fleet.** They were a bare
  paragraph; they now use the fleet's layout (navy header band with the org
  name, a lead block coloured by the worst finding, the five severity tiles,
  the attachment and confidentiality notes, a footer) and carry the
  `FLEET_ATTRIBUTION` credit line, linked when `FLEET_REPO_URL` is set. The
  AppSec weekly's footer takes the same attribution. The reading of
  `FLEET_ATTRIBUTION` / `FLEET_REPO_URL` for Go lanes is now one package,
  `internal/attribution`.

### Added

- **Static analysis for the Python and shell.** `task ship` and `task check` now
  run `ruff` (`task lint:py`), `bandit` (`task bandit`) and `shellcheck`
  (`task lint:shell`), the counterparts of staticcheck and gosec for the lanes
  and the bash runners; settings are in `pyproject.toml`. `task test:syntax`
  also parses `checkin-bash-guard`, which its hand-written list had missed. The
  first run found real things: `scout.py` opened `file://` and `ftp://` feed
  URLs, read a feed of any size, and parsed one that declared XML entities (all
  three are refused now, with tests); every `run-*` script sources `fleet.env`
  without telling shellcheck; and `run-mailbox-cleanup` had a mis-joined
  string. Thirteen test `subprocess.run` calls now state `check=False`.
- **AppSec: application owners in a database, `owners.db`, edited with
  `fleet-owners`.** Owners, watchers, `covers=`, `site:` entries and the owner
  lane's allowed domains move out of the hand-edited `app-owners.txt` into
  `/etc/cti-agent/owners.db` (SQLite, root:root 0600), with a history of every
  change and who made it. `fleet-owners` is Python (Go has no stdlib SQLite
  driver and `go.mod` stays empty) and rewrites `/etc/cti-agent/owners.json`
  after every change; `cti-appscan` and `cti-mailer --lane owner` read that
  snapshot through the new `appscan.OwnerSource`, and read `app-owners.txt`
  only while there is no snapshot. An unreadable snapshot stops the owners
  lane. New: `cti-mailer --lane owner --armed`, which `run-appowners` now asks
  instead of reading `OWNER_ALLOW_DOMAINS` itself. The wrapper runs
  `fleet-owners` as root, the one command that does.
  **Upgrade:** pull, reinstall. Nothing changes until you run
  `fleet-owners init` and `import` (RUNBOOK 11f, "Application owners in
  owners.db").

### Changed

- **`task cheatsheet:pdf` uses pandoc and pdflatex, not reportlab.** The
  Python renderer (`scripts/cheatsheet-pdf.py`) is removed, so there is no pip
  library to install. `scripts/cheatsheet-header.tex` wraps long lines in code
  blocks. The task checks for pandoc, pdflatex and the `fvextra` LaTeX package,
  and refuses non-ASCII text in `CHEATSHEET.md`, which pdflatex cannot set.
- **Docs: a laptop-to-production diagram** (`docs/cti-agent-flow.svg`) in
  SECURITY.md under "Build and release gates" and in the README, and
  CHEATSHEET 11a describes the release flow (tag on the personal repo; the
  sync workflow copies it to the company GitHub).
- **`CHECKIN_MODEL` picks the heartbeat's model.** Set it in `fleet.env` to
  an alias (`haiku`, `sonnet`, `opus`, `fable`) or a full `claude-...` id;
  blank keeps the account's default, as before. It is the operator's choice,
  read by `run-checkin` and passed as `--model`; the beat cannot change it.
  A value that is not a model name refuses the beat with an ERROR on the board
  rather than quietly running the default, so weeks of beats meant for one
  model are never silently another. Each beat logs `model: ...` and the
  healthcheck shows the last one. Groundwork for escalating hard problems to a
  stronger model (BACKLOG: "Heartbeat escalation to a stronger model").
- **`fleet-owners sync`: owners.db asks Qualys instead of you.** Bringing
  owners.db in step after adding web apps took a `--list-apps` file, `names`,
  reading for `<- no owner`, and a `set` and `site rm` per app - and `names`
  silently skipped ids not yet in owners.db, so running the steps in the
  documented order lost the new apps' names. `sync` runs `cti-appscan
  --list-apps` itself, through the `cti-agent` wrapper so the scanner runs as
  the service account with `/etc/cti-agent/fleet.env` and never as root (run
  straight from root's empty environment it would have read a `fleet.env` from
  the service account's state directory). It keeps every web app's
  name whether or not it has an owner yet (a new `scanner_apps` table,
  display-only, never in `owners.json`), and reports each thing out of step
  with its command: an app with no owner, a `site:` row a web app now scans,
  a site the domains lane no longer lists, an id Qualys no longer has.
  `--apply` makes only the changes that follow from owners already on file -
  the new web app takes the `site:` row's owner when exactly one unowned app
  matches, and the row goes - each recorded in `history`. It reads a new
  `cti-appscan --list-apps --json` (format `cti-applist/1`: id, name and URL
  host as separate fields), so a web app whose name contains a URL cannot pose
  as scanning a site, and refuses the whole listing if any field is off. It
  acts only where cti-appscan's own coverage check agrees; a `site:` row
  several unowned apps match is kept; and with no domains-lane website list it
  only reports. `names` with no
  file does the same as `sync`; `names FILE` now names every listed app too.
- **The User-Agent names a contact: the fleet's own mailbox.** Since 4 Nov
  www.cisa.gov answers every scout fetch with 403, and the agent was a bare
  `cti-agent-fleet/1.0` that gave CISA nobody to ask. Every fetch from a public
  site - scout and enrich (NVD, EPSS, CISA, the feeds), Patch Tuesday
  (Microsoft and the wrap-ups) and the domains web check - now sends
  `<FLEET_USER_AGENT or the component's name> (+mailto:<GRAPH_MAILBOX>)`. The
  address is read from `fleet.env` at run time, never written into the repo,
  and a malformed one is left out rather than reshaping the header. A
  `(...)` comment of your own in `FLEET_USER_AGENT` replaces the contact. One
  helper in Go (`internal/useragent`) and its mirror in the two lanes, tested
  to agree. It never impersonates a browser.

**Upgrade:** nothing on the box beyond the reinstall; `GRAPH_MAILBOX` is
already required, and `owners.db` gains its `scanner_apps` table on first use.
After adding or removing web apps in Qualys, run `sudo cti-agent fleet-owners
sync`. To try the heartbeat on a cheaper model, add `CHECKIN_MODEL=sonnet` to
`/etc/cti-agent/fleet.env`; the next beat picks it up, no reinstall needed. To ask CISA to allow the fleet, quote the
`x-reference-error` value from a 403 response. To build the cheat sheet PDF on
a Mac: `brew install pandoc`, then a LaTeX with pdflatex (`brew install --cask
basictex`, then `sudo tlmgr install fvextra etoolbox framed`, or MacTeX), and
`task cheatsheet:pdf`. To fill the application names once `owners.db` exists
(the listing must be root-owned): `sudo sh -c 'cti-agent cti-appscan
--list-apps > /root/apps.txt' && sudo cti-agent fleet-owners names
/root/apps.txt`, then `sudo cti-agent fleet-owners list`.

- **The AppSec lane no longer calls Qualys directly.** `cmd/cti-appscan` asks
  the scanner for what it can do through interfaces in `internal/appscan`
  (`Scanner`, `Reconciler`, `AppLister`, `OpenFetcher`, with the existing
  `DetailFetcher` and `RemedyFetcher`), and each is optional: a scanner with
  only some of them is used for those and skipped for the rest. Qualys is named
  in one file, `cmd/cti-appscan/wiring.go`, and `TestOnlyWiringNamesAVendor`
  fails the build if that stops being true. Behaviour is unchanged (the
  scan-list log lines now say "scan list" rather than "WAS scan list").
  **Upgrade:** nothing.

### Fixed

- **The AppSec and domains timers ran on the server's clock.** The owner
  report, the Friday AppSec weekly and the Tuesday domains check were left out
  when the other timers were moved onto `FLEET_TIMEZONE`, so on a UTC server
  they fired four or five hours earlier than the unit files say. They are now
  pinned at `FLEET_APPOWNERS_TIME` (07:15), `FLEET_APPSCAN_TIME` (07:30) and
  `FLEET_DOMAINS_TIME` (08:00). The installer also checks every schedule parses
  and fails the install if one does not. The scout (every 4 hours) and the
  heartbeat are left alone: the hour they run at does not matter. **Upgrade:**
  re-run the installer.

## 1.5 — 2026-11-03

### Added

- **Domains: who each SPF include is for.** The weekly gains an "SPF INCLUDES -
  WHO EACH ONE IS FOR" section and the CSV an `spf_includes_described` column:
  each include/redirect in the domains' own SPF records once, with the vendor
  (SMTP2GO, KnowBe4, Mailchimp, Microsoft 365, and about thirty more) and the
  domains that carry it, unrecognised ones first. `DOMAINS_SPF_VENDORS` adds or
  corrects entries, so the mail admin can answer "do we use this vendor?" from
  the report.
- **Domains: Proofpoint listed by address counts.** `PROOFPOINT_POD_IPS` names
  the PoD addresses some SPF records list instead of the include (to stay under
  the 10-lookup limit); an SPF that lists one is no longer reported as not
  authorising Proofpoint.
- **Operator alerts open with what the problem is.** `cti-alert` emails now
  start with a "WHAT THIS MEANS" paragraph, above systemd's verdict and the
  journal: what the unit does, how it ended, a plain cause when the last error
  matches a known one (expired secret, missing permission, timeout, full disk,
  missing setting), and that error line quoted. A hold or an orchestrator
  escalation leads with its own reason.
- **`scripts/healthcheck.sh`** - one read-only command that says whether the
  fleet is up: failed units, every timer enabled with a next run, code
  root-owned (the rule the heartbeat now enforces), `/etc/cti-agent` modes,
  disk, clock sync, SELinux, Go and Python versions, journal errors since
  boot, the last heartbeat's result, and the budget, board and memory db.
  `--deep` adds `cti-mailer --check`, `mailer.py --check`, `cti-jira --check`
  and a comparison with the latest published commit. Exit 1 on any FAIL.

  **Upgrade:** nothing to install; run it from your clone with
  `sudo ~/cti-agent/scripts/healthcheck.sh`.


- **AppSec: each application's report goes to its owners by email, daily.**
  New runner `run-appowners` and `cti-agent-appowners.timer` (07:15). For each
  scan finished since the last run it fetches the scanner's report of open
  findings (`cti-appreport --deliveries`), redacts the scan account's session
  from it, and mails it with a covering note through the new
  `cti-mailer --lane owner`, which takes its recipients only from the
  application's `app-owners.txt` line (owner To, watchers Cc) and only at a
  domain in `OWNER_ALLOW_DOMAINS`. Scans that did not finish, failed their login
  or reached no host, and applications with no owner, are held and reported to
  the operator once. Each scan is sent once (`state/appowners-sent.json`).
  New flags: `cti-appscan --deliveries-out/--delivered-log/--commit-delivered`,
  `cti-appreport --deliveries/--no-fetch`, `cti-mailer --app-id/--app-name`.
  **Upgrade:** pull, reinstall. Off until you set `OWNER_ALLOW_DOMAINS`; run
  `run-appowners --to-dev` and read a report before enabling the timer
  (RUNBOOK 11f).

- **Mailbox cleanup keeps the fleet's own reports for a week.** They used to be
  archived the day they arrived. `MAILBOX_SELF_MIN_AGE_HOURS` (default 168, 0
  for the old behaviour) holds them in the inbox that long, then archives them;
  the dry run states the grace beside the other two numbers.
- **Domains: the mail gateway's log decides who may be locked down.** With
  `DOMAINS_MAIL_GATEWAY=pod` the weekly domains lane reads the Proofpoint on
  Demand log for the last `DOMAINS_GATEWAY_DAYS` days (1 to 28, default 7),
  aggregates only, through the new `domains.MailGateway` interface (`podgw` is
  the first implementation). A domain the inventory says sends nothing that
  has outbound mail gets a High finding and is not asked to be locked down;
  sending domains with none get an Info; a "sends nothing" domain that only has
  inbound mail passing DMARC as it is also left alone (a service is authorised
  to send as it); outbound domains missing from the inventory get a Medium
  (first 10); inbound mail using our domains is counted, with
  DMARC passed and not passed, as the evidence for `p=reject`. If the read
  fails or is incomplete (token in use, network, byte cap, idle, a connection
  dropped without a close frame, undecodable messages, sender-domain overflow,
  an empty window, or events that do not cover the window) no lock-down action is produced, the actions file
  carries `held`, `cti-jira` files, comments on and resolves nothing (ref
  action `held`), and the report has a Medium "(mail gateway)" finding saying
  why. **Upgrade:** pull, reinstall. The feature is OFF until you add these
  lines to `/etc/cti-agent/fleet.env` (the `POD_*` pair is the same one
  `cti-podprobe` uses; nothing changes without the first line):

  ```
  DOMAINS_MAIL_GATEWAY=pod
  DOMAINS_GATEWAY_DAYS=7
  POD_CLUSTER_ID=<cluster id>
  POD_API_TOKEN=<token>
  ```

  Then run `sudo cti-agent run-domains --to-dev` and look for the
  `[domains] gateway:` lines; a run without them did not use the gateway.
  The read takes roughly 15 to 20 minutes for 7 days. Do not run
  `cti-podprobe` while the weekly runs (one session per token).

- **`cti-podprobe` and `internal/podlog`: a read-only probe of the Proofpoint
  on Demand Log API.** One archived window is read over a standard-library
  WebSocket client and printed as aggregate counts only: events per
  direction, route names, DMARC and SPF results, outbound header-From domains
  and DKIM data, and inbound mail using our domains. It shows what the stream
  holds before the domains lane's mail-gateway half is built. No message,
  address or token is printed or stored; the token is read from the
  environment, never a flag. New settings `POD_CLUSTER_ID` and `POD_API_TOKEN`
  (commented in fleet.env.example). **Upgrade:** pull, reinstall. Nothing
  runs it on a timer. To use it, add the two settings (the token must be the
  fleet's own: one session per token) and see RUNBOOK 11g part 7.

- **AppSec: a Qualys notice from the wrong sender is reported, not lost.** A
  scan-results notice whose sender is not a Qualys address was silently
  dropped. One from the mailbox's own address was dropped earlier still, at
  the self-sent skip. Seen on 2026-11-02: a scanner account whose notification
  sender is `cybersecurity@`. It is still not parsed or archived (the sender
  check is what keeps a forged notice out), but the run now logs a warning
  that names the sender and says what to fix in Qualys. **Upgrade:** nothing.
  If the warning appears, change that Qualys user's notification sender.

- **AppSec: more of the notification is read.** The application-status link's
  web app id (kept as `NoticeAppID`: it tells two runs of one application
  apart without the scan list, and the scan list's id still wins, with a
  warning if the two disagree), hosts scanned and active, launch type and
  account, option profile, duration, the links-crawled delta, the comparison
  scan's reference, the first-scan marker, and the sensitive-content and
  information-gathered counts. In the weekly: a scan where no host answered is
  a SCANNER FAULT (`[UNREACHABLE]`) rather than a clean row, and an OPEN NOW
  row is annotated when the scan is a first scan with no baseline, was run by
  hand, or found sensitive content. Run titles ending "Biweekly Run #N" now
  lose the suffix like Weekly/Monthly ones. **Upgrade:** nothing.

- **The daily ignores Qualys's weekly Knowledge Base mail.** "Latest
  Vulnerabilities Added to the Knowledge Base" lists thousands of CVEs (5,292 on
  2026-11-02); the digest tried a live Qualys lookup for each at about 3.5 s,
  hit the one-hour limit and sent nothing. New `DIGEST_SKIP_SUBJECTS`
  (case-insensitive substrings; unset = that mail; empty = skip nothing). Skipped
  mail is named in the log and stays in the mailbox. Matching is on the subject
  only, so confirm the real subject contains "latest vulnerabilities added" or
  "added to the knowledge base". **Upgrade:** nothing; set the variable only if
  other bulk mail needs the same treatment.

- **The domains lock-down ticket can live in another Jira project.** New
  optional `JIRA_DOMAINS_PROJECT_KEY` and `JIRA_DOMAINS_ISSUE_TYPE` send only
  the weekly domains ticket (INF, for IT); unset, it follows `JIRA_PROJECT_KEY`
  and nothing changes. The write gate checks that project, and the digest's
  FLEET TICKETS still lists the ticket from there. A hand-made ticket is
  adopted only if it carries the labels `cti-agent` and `cti-domains-lockdown`.
  **Upgrade:** nothing unless you want INF; see the RUNBOOK ("Filing the
  lock-down ticket in another project").

- **The daily names Sev5s held for approval.** A Sev5 that is neither on KEV nor
  CVSS 9.0+ is still not filed by the scheduled run (the rule is unchanged), but
  the digest now has a "HELD FOR APPROVAL" section with each CVE, its host count
  and the `cti-jira --from-enriched <file> --for-real --approve` command. Before,
  the only trace was a journal line (CVE-2026-111497, 2026-10-27). `cti-jira`
  records them as `held` in the `-tickets.json` map; `brief.py` renders them.
  **Upgrade:** pull and reinstall; nothing to configure.

- **AppSec closes the ticket of a deleted web app.** When a Qualys WAS web app
  is deleted, the weekly `cti-jira --appscan-tickets` closes its open ticket
  with a comment. Guards: only when `cti-appscan` fetched the complete web-app
  list that run (`scannerApps` in the `--tickets-out` file); only open tickets
  labelled `cti-appscan` and `cti-appscan-<numeric id>` that carry the fleet's
  state property (name-keyed apps never); the list must agree with that run's
  scans and the tickets file be under 24 hours old; at most 3 per run and never
  most of the open queue, more would-be closures close none and warn (it looks
  like lost scanner visibility); a full search page (100) skips. Gated by
  the new `JIRA_ALLOW_CLOSE` (project keys, empty = never, independent of
  `JIRA_ALLOW_CREATE`) and `--for-real`. The transition is chosen by its
  destination status category (Done); `JIRA_CLOSE_TRANSITION` picks among
  several; one needing another required field is refused. Needs the Jira
  permission "Transition issues" (`--check` lists it when the gate is set).
  `--appscan-close-test KEY` rehearses on a `--appscan-test` ticket only. Closing
  is reversible; a returning app gets a new ticket linked to the closed one.
  The domains lane is unchanged.

- `cti-jira --appscan-comment-probe KEY` (with `--appscan-tickets` and
  `--appscan-test`): posts the weekly comment for one application onto an
  `--appscan-test` ticket and, if the gateway refuses it (the firewall's HTTP 403
  page seen on 2026-10-30), bisects it by line to name the refused text. Preview
  unless `--for-real`; refuses any ticket that is not a test ticket; at most 80
  comments.

### Changed

- **AppSec: no Jira tickets unless `WAS_TICKETS=1`.** The help desk does not
  want AppSec tickets in CR, and many owners are not in Jira. `run-appscan`
  no longer files or comments on application tickets by default.
  **Upgrade:** nothing, unless you want tickets kept: then add `WAS_TICKETS=1`.
  Close the existing AppSec tickets in CR by hand.

- **One footer for every lane.** The daily and weekly briefs, Patch Tuesday and
  domains emails now end with "Generated by the `<FLEET_ORG>`" instead of
  "Generated by the `<FLEET_ORG>` CTI agent fleet", so setting
  `FLEET_ORG="CR Agent Fleet"` gives the same name in every header and footer.
  `FLEET_ATTRIBUTION` still overrides it.
- **Cheat sheet: retiring a website.** Section 11 says to delete the Qualys web
  app; the Friday run closes its ticket.

**Upgrade:** pull, reinstall. Nothing is required for closing: it stays off
until you grant the service account "Transition issues" in the project, run
`cti-jira --check`, and set `JIRA_ALLOW_CLOSE=<project key>` in fleet.env;
rehearse with `--appscan-close-test` first. To get "CR Agent Fleet" on the first line of the
briefs, set `FLEET_ORG="CR Agent Fleet"` in `/etc/cti-agent/fleet.env`. Note that
it also renames the AppSec, domains and Patch Tuesday headers.

### Fixed

- **Mailbox cleanup ran before the digest.** `install-fedora.sh` moved the
  digest, weekly and Patch Tuesday timers onto `FLEET_TIMEZONE` but not the
  mailbox timer, so on a UTC server cleanup fired at 07:00 UTC (02:00 Eastern),
  four hours before the 06:00 Eastern digest. It found no CTI mail processed
  "today" and archived nothing, every day, while still deleting auto-replies.
  The mailbox timer is now pinned too, at `FLEET_MAILBOX_TIME` (default
  07:00:00). Re-run the installer to apply it.

- **The digest and weeklies were never archived.** `mailer.py` sent them
  without the signed `X-CTI-Agent-Sent` header the Go lanes add, so cleanup,
  which only archives our own reports on a verified signature, left every one
  in the inbox. `mailer.py` now signs them (the same HMAC as
  `internal/graph/selfsign.go`, pinned by a golden-value test). Reports sent
  before this change stay unsigned and have to be filed by hand.

### Security

- **Fixed issues found by PrimeSec AI:**
  - Attack vector 10786586 (High) - generic installer leaves unattended
    fleet code and tool policy service-account-writable. Fixed by the
    heartbeat entry below.
  - Attack vector 10786439 (High) - advisory text steers the orchestrator
    into overwriting CLAUDE.md, the board and the findings database under
    FLEET_HOME. Fixed by the heartbeat entries below: no file-edit tools, a
    root-owned working directory and instructions, the Bash guard, and
    bounded board and database grants.
  - Attack vector 10786503 (High) - subject-line prompt injection makes the
    heartbeat write fleet.env, which every timer-driven wrapper then
    executes as bash (generic install layout). Fixed by the same entries:
    the beat cannot edit files, the generic layout is retired, and
    `fleet.env` is `root:ctiagent` `0640` on the only supported layout.
  - Attack vector 10786525 (High) - wrapper `$1` path traversal to arbitrary
    execution and fleet.env disclosure as ctiagent. Fixed by the
    `cti-agent` wrapper entry below.
  - Attack vector 10786546 (High) - forged automatic-reply headers trigger
    unowned mailbox deletion. Fixed by the auto-reply entry below.
  - Attack vector 10786576 (High) - caller-selected Go toolchain can exclude
    code from `gosec` scanning. Fixed by the `GOSEC_GOTOOLCHAIN` entry below.

- **`sudo cti-agent` runs fleet commands by name only.** The wrapper joined
  its first argument onto `/opt/cti-agent/bin/` as given, so
  `sudo cti-agent ../../../../usr/bin/env` ran `env` as the service account
  with `fleet.env` loaded, printing every secret, and `../../bin/bash` was a
  shell as an account meant to have none. It now refuses (exit 2, before
  `sudo -u`) anything that is not letters, digits, dots and dashes, or not a
  regular, non-symlink file in `bin/` (or `lanes/` for the `.py` lanes).
  Only reachable by someone with sudo rights to the wrapper, so the operator
  already; still worth closing for a narrower sudoers rule.

  **Upgrade:** re-run `install-fedora.sh`, which rewrites
  `/usr/local/bin/cti-agent`.

- **Auto-generated mail is no longer taken for an out-of-office reply.**
  `IsAutoReply` also accepted any `Auto-Submitted` value merely containing
  "auto" when `X-Auto-Response-Suppress: All` was present - which takes in
  `auto-generated`, the value RFC 3834 uses for system notifications and the
  code's own comment said must never be deleted. A vendor or platform
  notification carrying both headers went to Deleted Items ahead of every
  ownership, hold and age check. Only the RFC reply values (`auto-replied`,
  `auto-notified`) count now; out-of-office mail that declares only
  `auto-generated` is still caught by its subject, and that path archives
  instead of deleting when the digest took a CVE from the message. A sender
  who forges `Auto-Submitted: auto-replied` on their own message can still
  have it moved to Deleted Items (recoverable); they cannot do that to anyone
  else's mail. The cleanup now decides on the live headers only, not on the
  auto-reply verdict stored in a processed record, so records the old binary
  wrote cannot delete a notice the new rule keeps.

  **Upgrade:** none beyond the usual reinstall (rebuilds `cti-mailbox`,
  `cti-agent`, `cti-appscan`).

- **`GOSEC_GOTOOLCHAIN` cannot hide code from gosec.** With the override set,
  `task gosec` now lists packages and files (`GoFiles`, `CgoFiles`,
  `IgnoredGoFiles`) under both the current Go and the override, and refuses,
  printing the difference, unless they match. A file behind a build
  constraint only the newer Go honours would otherwise be built, tested and
  shipped but never read by gosec, which would still report `Issues: 0`. A
  package that fails to load under either toolchain (`go list -e` exits 0 and
  still lists its files) is refused too.

  **Upgrade:** nothing; `GOSEC_GOTOOLCHAIN=go1.26.9 task ship` now prints
  "same packages and files ... - checked" before gosec runs.

- **The heartbeat can no longer edit files, and refuses to run code it could
  edit.** A PrimeSec scan found two things that were unsafe together. The beat
  ran `claude` with `--permission-mode acceptEdits`, which auto-approves file
  edits, and the generic `install.sh` left the fleet's runners and tool
  policy owned by the service account. A beat steered by a hostile advisory
  or mail could have rewritten `run-checkin` or a granted binary, and every
  later run would have executed the change with the fleet's credentials.
  - `run-checkin` now uses `--permission-mode default` with
    `--disallowedTools "Edit,Write,NotebookEdit"`. Nothing in `/checkin`
    writes a file, so nothing is lost; the beat keeps its read-only file tools
    for `reports/` and logs.
  - On Linux `run-checkin` fails closed: it exits 1, before posting to the
    board or starting `claude`, unless it, its directory, `$FLEET_CODE`,
    `$FLEET_CODE/bin` and each granted binary are root-owned, not group- or
    world-writable, and not writable by the running account. The unit's
    `OnFailure` alert notifies the operator. On macOS the check is skipped
    with a log line.
  - `fleet-kit/install.sh` and `fleet-kit/fleet/systemd/` are removed.
    `install-fedora.sh` (code in `/opt/cti-agent`, `root:root` `0755`) is the
    only installer. The docs and man pages no longer describe the generic
    layout.
  - Found by the follow-up review: on Linux the beat now uses only a
    root-owned `claude` (`CLAUDE_BIN`, `/usr/bin/claude` or
    `/usr/local/bin/claude`) and checks it like the rest of the code. It used
    to look in `~/.local/bin` first, which is the service account's own HOME.
    `journalctl` and `systemctl list-timers` are granted by absolute path
    (`/usr/bin/...`), so a same-named binary earlier on `PATH` gets nothing.
    `fleet-db` runs as `/usr/bin/python3 -sE`, so `PYTHON*` variables and the
    account's user site-packages cannot load code into it.

  **Upgrade:** on the Fedora box, check `command -v claude` first. If it is
  under `/var/lib/cti-agent/.local/bin`, install the dnf package
  (`sudo dnf install claude-code`, repo in `install-fedora.sh`) and remove the
  per-account copy, or the heartbeat refuses to start. Then pull and
  reinstall with `install-fedora.sh` as usual. After the first beat,
  `journalctl -u cti-agent-checkin.service -n 30 --no-pager` should show
  `disallowed tools: Edit,Write,NotebookEdit` and no `REFUSING to start`.
  Anyone still on an `install.sh` layout must move to `install-fedora.sh`: the
  heartbeat now refuses to start there.

- **Nothing the heartbeat reads its instructions from is writable by its
  account, and its last write and outbound-request paths are closed.** The
  review after the fix above found the beat could still persist a change or
  widen its reach without editing code:
  - **Instructions and settings.** `CLAUDE.md` and the skills were installed
    in `/var/lib/cti-agent`, owned by `ctiagent`, and the beat started there,
    so Claude Code also loaded settings, hooks and MCP servers from a
    directory the account owns. They now live in `/opt/cti-agent/orchestrator`
    (`root:root`, `0644`/`0755`) and the beat starts there, with
    `--setting-sources project`, a root-owned
    `--settings /opt/cti-agent/checkin-settings.json` (one guard hook, see below; no
    project MCP servers, edit and web tools denied) and `--strict-mcp-config`. File
    tools may read `reports/`, `logs/` and `archive/` under `$FLEET_HOME`.
  - **Steering audit.** `run-checkin` refuses to beat (exit 1, board ERROR)
    when Claude Code files nobody installs are in the account's reach:
    `~/.claude/{CLAUDE.md,skills,commands,agents,hooks,rules,...}`,
    `~/.mcp.json`, extra settings in the orchestrator dir, or a
    `~/.claude/settings.json` / `~/.claude.json` that sets hooks,
    permissions, MCP servers, env or allow rules. Its integrity check now
    covers every `$FLEET_CODE/bin/*` entry, the settings file and the
    orchestrator files. `run-checkin --audit` runs the checks alone.
  - **journalctl.** `Bash(/usr/bin/journalctl:*)` allowed
    `--cursor-file=PATH`, which overwrites `PATH` as the account
    (`state/budget.json` resets the quota). The grant is now
    `$FLEET_CODE/bin/fleet-journal`, a root-owned wrapper that accepts only
    `-u cti-agent-*`, `--since`, `-n` and `--no-pager` (new man page).
  - **systemctl list-timers and cti-alert (H2, hardening review).** The
    grant `Bash(/usr/bin/systemctl list-timers:*)` accepted `--host=user@box`
    and `--machine`, which run the query over ssh or into containers, so a
    steered beat could make outbound ssh connections from the box. The grant
    is now `$FLEET_CODE/bin/fleet-timers`, a root-owned wrapper that accepts
    only `--all` and `cti-agent-*` patterns, passes them after `--`, defaults
    to `cti-agent-*` and exits 2 on anything else (new man page). `cti-alert`
    had the same hole through `--unit=--host=...`: it now refuses (exit 2) any
    unit not matching `^cti-agent-[A-Za-z0-9@._-]+$` and calls
    `/usr/bin/systemctl show ... -- UNIT` and `/usr/bin/journalctl
    --unit=UNIT` by absolute path.

    **Upgrade:** pull and re-run `install-fedora.sh`. It installs
    `fleet-timers` and rebuilds `cti-alert` (the binary is built on the box,
    so the fix is not in place until the installer has run). `run-checkin
    --audit` should pass, and the next beat's allowed tools show
    `fleet-timers`.
  - **Beat commands cannot carry shell syntax, and four grants are
    narrower (internal review).**
    - A new PreToolUse hook on Bash, `$FLEET_CODE/bin/checkin-bash-guard`
      (`python3 -I`, named in `checkin-settings.json`, which now has
      `disableAllHooks: false` and this one hook), blocks (exit 2) any beat
      command containing `<` `>` `|` `;` `&`, a backtick, a newline or CR
      anywhere, and, outside single quotes, `$` (any expansion, plain `$NAME`
      included: the beat's environment carries `fleet.env`, so
      `$CLIENT_SECRET` could reach the board or a `cti-alert` mail), `*`, `?`,
      `[` and `~`. A leading `NAME=value` is blocked too. Single-quoted text
      is literal, so `'cti-agent-*'` still works; the beat types absolute
      paths, never `$FLEET_CODE`. It fails closed on unreadable input. A prefix
      grant can therefore never become a redirect-to-file write, run a
      substituted command or leak a secret.
    - On Linux `run-checkin` refuses to start if the guard is missing, if the
      settings do not parse to `disableAllHooks: false` with a Bash
      PreToolUse command hook at `$FLEET_CODE/bin/checkin-bash-guard`, or if
      piping a redirect payload through the guard does not exit 2. A hook
      whose command is missing, or a guard whose python is missing, would
      otherwise fail open.
    - The `fleet-board` grant is `say`, `read`, `tail`, `resolve` and
      `expire`. Not `post` (it names its own sender, so a beat could sign as
      `@operator` or `@systemd`) and not `prune` (a regex; `prune .` empties
      the board, ERROR lines included). The beat still tidies the board each
      beat: `resolve <id>` archives the `id=<id>` line and its `re:<id>` lines
      (whole words, so q17 does not take q170) and `expire <days>` (2-365)
      archives older lines, keeping ERROR lines 7 days whatever is passed and
      lines with no timestamp. `say <to> <kind> <body>` posts as `@you`.
      `read` now requires an `@name` handle. `fleet-board post` exits 2 on a
      handle that is not `@name` from `[A-Za-z0-9._-]` (32 at most) or a kind
      that is not upper-case letters and digits (16 at most); a newline in a
      handle used to forge a second board line. Control characters are
      stripped from post bodies.
    - The `cti-budget` grant is `status` only; `record` and `check` are
      `run-checkin`'s.
    - `cti-kev --enriched PATH` accepts only a regular file named
      `enriched-*.json`, symlinks resolved, and with `FLEET_HOME` set only one
      directly in `$FLEET_HOME/state`. It used to open any file the account
      could read.

    **Upgrade:** re-run `install-fedora.sh`, which installs the guard and
    rebuilds `cti-kev`. After the first beat, `journalctl -u
    cti-agent-checkin.service -n 40 --no-pager` should show no `REFUSING to
    start`. Free-pattern `fleet-board prune` is now the operator's alone. A `checkin-bash-guard:` line in a beat log means the guard blocked
    a command; that is expected, not a fault.
  - **cti-patchtuesday.** `--dry-run` (granted with any arguments) now
    refuses `--url-msrc` (except `none`), `--url-bleeping`, `--url-qualys`
    and `--drop-dir`, so a beat cannot make the box fetch an arbitrary URL or
    read an arbitrary folder, and refuses a `--dry-run` that a later
    `--dry-run=false` turns off (the flag package lets the last one win, so
    that matched the grant and was a real run: `--mark-sent`, `--json PATH`
    writes, any URL). The operator's by-hand runs without `--dry-run` are
    unchanged.
  - Claude Code's auto-memory is off for the beat
    (`CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`), and the installer's quarantine
    will not follow a symlinked `~/.claude` onto the root-owned files.

  **Upgrade:** pull and re-run `install-fedora.sh`. It installs the
  orchestrator directory and settings file, and moves the old
  `/var/lib/cti-agent/CLAUDE.md`, `.claude/skills` and any planted Claude Code
  files into `/etc/cti-agent/quarantine/<time>/` (nothing is deleted). If you
  had edited the old `CLAUDE.md`, compare it with the diff command the
  installer prints and apply your edits to
  `/opt/cti-agent/orchestrator/CLAUDE.md`. The Verification block must show
  `run-checkin --audit` passing; until the installer has run, the heartbeat
  refuses to start. After the next beat,
  `journalctl -u cti-agent-checkin.service -n 30 --no-pager` should show
  `using /usr/bin/claude in /opt/cti-agent/orchestrator` and `fleet-journal`
  in the allowed tools.

---

## 1.4 — 2026-10-25

### Changed

- **`cti-jira` also files CVSS 9.0+ findings:** a PRESENT CVE now earns a
  ticket when it is on CISA KEV, rated Sev5, **or has a CVSS base score of
  9.0 or more** (`CriticalCVSS`, CVSS's own Critical band). CVSS 9.0+ tickets
  file automatically like KEV ones (no `--approve`), unassigned for triage,
  with the extra label `cvss-critical` and ", CVSS 9.8"-style text in the
  summary. A non-KEV Sev5 below CVSS 9.0 still waits for `--approve`. Why:
  CVE-2025-27918 (CVSS 9.8, not on KEV, low EPSS) ranked Sev4 and got only a
  digest line for two weeks, with no ticket.

- **The AppSec weekly is named for the organisation:** "<FLEET_ORG> AppSec
  Weekly" in the heading, title and subject (was "CTI AppSec Weekly" /
  "CTI Fleet AppSec"), and the footer reads "Generated by the <FLEET_ORG>
  Agent Fleet AppSec lane." Mail rules matching the old subject need updating.

- **Weekly lanes spread across the week:** the domains weekly moved from
  Monday 08:00 to Tuesday 08:00 and the AppSec weekly from Monday 07:30 to
  Friday 07:30. The weekly digest stays Monday 07:00. Domains runs before
  AppSec because AppSec's NOT SCANNED check reads the website list
  run-domains writes; Friday because the weekly WAS scans finish by Thursday.

### Fixed

- **The AppSec lane called the Qualys WAS API twice per run.** `run-appscan`
  got its subject line from a second `cti-appscan --subject-only`, a full
  re-run that re-read the mailbox and repeated every scanner call - double the
  load against the rate limit, and log counts that disagreed. The subject now
  comes out of the one run (`cti-appscan --subject-out`).

- **AppSec read the Qualys notices as Graph's plain-text conversion**, which
  ran every field onto one line and dropped the report link, so no scan
  matched the WAS scan list and every application was left alone.
  `cti-appscan` now reads the HTML body the parser was written for (the
  digest and mailbox cleanup still read text), splits re-written layouts
  (table rows, `<br>` with attributes, spaced hidden preheaders) into fields,
  and claims a notice as read only when its scan reference is well-formed.

- **The domains email now names its Jira lock-down ticket.** `run-domains`
  filed the ticket after the email had gone, so the report never said which
  ticket IT was working from. The ticket is now filed or updated first
  (`cti-jira --domains-actions --ref-out`) and its key, status and link are
  stamped beside the DNS changes (`cti-domains --ticket-slot`,
  `--stamp-ticket`): "filed", "list changed, added as a comment", "already
  has this list", "nothing left - it can be closed", or "NOT updated this
  run - why". A dry run or `--to-dev` says what it would do. Jira trouble
  still never stops the email. Only an https Jira browse link for that key
  is put in the email.

### Added

- **How the scanner found it, on the ticket.** The AppSec open-findings search
  is now verbose (100 per page, response capped at 64 MB). Each application
  ticket shows one place in full - request, payload, access path and a response
  excerpt in a `{noformat}` block - and the attached file shows every place.
  Request headers are never read and `Cookie`/`Set-Cookie`/`Authorization`
  lines are redacted. Evidence does not change a ticket's fingerprint.

- **`INTERFACES.md`.** One page listing every Go interface the fleet is built on
  (`LookupProvider`, `appscan.Provider` and its capability interfaces,
  `Registrar`, `Resolver`), how complete each is, the places where a command
  still calls the Qualys client directly, and where new interfaces could go.
  The proposals are on the backlog. **The README is now the front page:** its
  design decisions, binaries table and project layout moved to
  `ARCHITECTURE.md`, its lookup-provider and AppSec boundary sections moved into
  `INTERFACES.md`, and its backlog became `BACKLOG.md`. Documentation only.

- **Recurring AppSec tickets link back to the last closed one:** a new
  application ticket now names the application's most recent closed ticket
  ("Recurring: ... previous ticket, KEY, is done"), says how many of its
  findings were on that ticket when it was last updated, and is linked to it
  ("Relates"). The preview shows the note and a "would link to" line. Best
  effort: a failed search or link is logged and the ticket is still filed.
  `cti-jira --check` now lists LINK_ISSUES. **Upgrade:** grant the Jira API
  account "Link issues" on the project; otherwise the link is skipped and
  logged.
- **Rehearse an AppSec ticket before Friday:** `cti-jira --appscan-tickets`
  previews now end each would-create and would-comment with the attachments
  ("would attach appscan-DATE.txt (N KB)", the scanner report or "no scanner
  report to attach"). `--appscan-test <web-app id>` files (with `--for-real`)
  ONE "[TEST]" ticket for that application, labelled `cti-agent-test` only,
  unassigned, no component or watchers, nothing in state, with the findings
  text and report attached; `JIRA_ALLOW_CREATE` applies. `run-appscan --to-dev`
  with `WAS_ATTACH_REPORT=1` now fetches the reports so the preview file names
  each attachment and size (`--dry-run` does not). **Upgrade:** reinstall;
  nothing to configure.

- **One Jira ticket per application, assigned to its owner, with the fix.**
  The AppSec weekly now keeps one live ticket per application
  (`cti-jira --appscan-tickets`, filed before the email goes): every active,
  confirmed finding of Qualys severity 5-3, grouped by QID with every URL and
  parameter, and for each the **risk, what the scanner found and how to fix
  it** from the Qualys KnowledgeBase entry for the QID (the WAS finding itself
  carries none of that). Assigned to the owner in
  `/etc/cti-agent/app-owners.txt` - looked up in Jira by email, never guessed;
  unlisted means unassigned, and the email says so. Commented only when the
  findings change, told once when nothing is left, left alone the week a scan
  was incomplete, failed to log in, or its detail could not be fetched. The
  weekly email gains a JIRA TICKETS section and a one-line fix under each new
  finding. Dry runs and `--to-dev` preview only.
- **`cti-appscan --list-apps`** prints a complete `app-owners.txt` from every
  web app defined in Qualys WAS, keyed on web-app id: owners already on file
  kept, new apps with an `OWNER@example.com` placeholder (refused by the
  parser until replaced), stale lines listed. The weekly email names any web
  app with no owner.
- **Coverage check: live websites with no web application scan.** The domains
  lane writes our live websites (`cti-domains --websites-out`,
  `state/domains-websites.json`; redirects, registrar landers, parked pages
  and the new `landing` inventory marker left out). The AppSec weekly lists any
  that no Qualys WAS web app points at under NOT SCANNED, and `--list-apps`
  adds them as `site:<domain>` lines in `app-owners.txt` for whoever should get
  the scan set up.
- **Staging copies that stand in for production.** `covers=<host>` on a web
  app's line in `app-owners.txt` says that web app - typically a staging copy
  such as a WP Engine `*.wpenginepowered.com` install - is scanned instead of
  the production site. The production site moves from NOT SCANNED to a new
  COVERED VIA STAGING section ("production not scanned directly"), the web
  app's ticket says the fix goes into the code and is then deployed, and
  `--list-apps` keeps `covers=` and flags staging-looking web apps that have
  none. RUNBOOK 11f covers what a stand-in does not test and recommends
  password-protecting the staging copy and adding a non-intrusive scan of
  production.
- **Watchers on application tickets.** An optional
  `watchers=a@example.com,b@example.com` field (max 10, any field order) on a
  line in `app-owners.txt` adds each as a Jira watcher on that application's
  ticket, on create and on every weekly comment (idempotent). Looked up by
  email like the owner; one not found, invalid or refused is logged and
  skipped, never blocking the ticket. The owner field stays one email.
  `--list-apps` keeps `watchers=` on lines with a real owner.
- **Scoped Jira API token support (`JIRA_CLOUD_ID`).** Optional. Set it and
  Jira API calls go through `https://api.atlassian.com/ex/jira/<cloud id>`,
  which an Atlassian scoped token on a service account requires (three scopes:
  `read:jira-work`, `write:jira-work`, `read:jira-user`); email links still use
  `JIRA_BASE_URL`. UUID only. Unset changes nothing. `cti-jira --check` now
  also prints each Jira permission the fleet uses as ok or MISSING, writing
  nothing. RUNBOOK 11c has the setup, switch and rollback.
- **`cti-appreport`: the scanner's own report on each AppSec ticket.** New
  command (`sudo cti-agent cti-appreport ...`) that fetches the DAST scanner's
  per-application report - Qualys WAS: create, poll, download as HTML_ZIPPED,
  delete - for `cti-jira --appscan-reports DIR` to attach when a ticket is
  filed or its findings change. The ticket text says it is attached and that
  it contains scan-account session cookies. `run-appscan` does this when
  `WAS_ATTACH_REPORT=1` (default **off**) on a real run: a `cti-jira` preview
  decides which applications need one, `cti-appreport --tickets --only-ref`
  fetches only those, `cti-jira --for-real --appscan-reports` attaches, and the
  reports directory is deleted. Never fatal. Files 0600, directory 0700. The
  scanner is chosen by `APPSCAN_REPORT_PROVIDER` (default `qualys-was`) behind
  the Go interface `appscan.ReportFetcher`, so Invicti or Wiz is a package and
  one case. Flags for testing against a live account: `--list-ids` (the
  application ids from the last weekly run's tickets file; no API calls), `--check`,
  `--dump-request`, `--request-file`, `--probe-findings` (output passes through
  `Redact()`, which strips Cookie, Set-Cookie and Authorization). The live
  Qualys Report API element names have **not** been verified yet; that is what
  the probe sequence in RUNBOOK 11f is for.
- **Qualys API rate limiter (`internal/qualysrl`).** The WAS client used by
  `cti-appscan` and `cti-appreport` now reads Qualys's `X-RateLimit-*` and
  `X-Concurrency-Limit-*` headers on every response, waits out a short
  refusal, and gives way when only `QUALYS_RL_RESERVE` calls (default 5) are
  left, so the optional report work never starves the VM lane or KnowledgeBase
  lookups. `QUALYS_RL_MAX_WAIT` (default 5m) is the longest it sleeps; longer is
  an error. It follows limit increases automatically: nothing to change when
  the Qualys contract raises limits. The VM-lane client is not wired to it.
- **AppSec tickets list potential Critical and Urgent findings.** The
  scanner's unconfirmed (POTENTIAL) findings of severity 4 and 5 now appear in
  their own "POTENTIAL - please verify" section under a callout saying they are
  deliberately listed, not confirmed, and that not confirmed does not mean not
  there. Each line reads "POTENTIAL <sev> - unconfirmed, please verify", and the
  summary and header count them separately ("To verify: ..."). Potential
  Serious and below are still left out. A finding that moves between potential
  and confirmed counts as changed, so its ticket is told.
- **`cti-jira --appscan-tickets` preview honours the write gate.** With
  `JIRA_ALLOW_CREATE` closed, a preview now reports `gate-closed` instead of
  `would-create`/`would-comment`, so no scanner report is fetched for a ticket
  the real run would not touch.

### Upgrade

Pull, reinstall (or, if you only copy the timers, `sudo systemctl
daemon-reload`) so the new timer days take effect: domains now Tuesday 08:00,
AppSec Friday 07:30. Check with `systemctl list-timers --all 'cti-agent-*'`.
Then:

1. Create `/etc/cti-agent/app-owners.txt` from the scanner's list:
   `sudo cti-agent cti-appscan --list-apps > /tmp/app-owners.txt`, replace
   every `OWNER@example.com`, then install it mode 0640 root:ctiagent
   (RUNBOOK 11f has the commands).
2. Give the Jira API account the **Browse users and groups** permission, or
   every ticket is filed unassigned. Using `watchers=` (optional, no action
   otherwise) also needs **Manage watcher list**.
3. `sudo cti-agent run-appscan --to-dev` to preview the tickets, then let
   Monday's run file them.
4. Optional: nothing to do unless you switch to a scoped Jira token (RUNBOOK
   11c, "Using a scoped service-account token").
5. Rebuild and install (`install-fedora.sh`): there is a new binary,
   `cti-appreport`. Nothing else to configure.
6. `WAS_ATTACH_REPORT` is **off by default**; the lane behaves as before until
   you set `WAS_ATTACH_REPORT=1`. Run the probe sequence first (RUNBOOK 11f,
   "Attaching the scanner's report": `cti-appreport --check`, `--dump-request`,
   one report with `--keep` then without, `--probe-findings`), because the
   Report API field names are not yet verified against a live account. The
   Qualys account needs permission to create WAS reports.
7. CVSS 9.0+ ticketing: nothing to configure. CVEs already past their first
   daily are not re-read by the daily, so a one-off backfill picks them up:
   `sudo cti-agent fleet-db rollup --days 30 | sudo -u ctiagent sh -c 'umask
   077; cat > /var/lib/cti-agent/state/rollup-backfill.json'`, then
   `sudo cti-agent cti-jira --from-enriched
   /var/lib/cti-agent/state/rollup-backfill.json` (preview), the same with
   `--for-real`, then `sudo rm -f /var/lib/cti-agent/state/rollup-backfill*.json`.
   The file goes in the state directory, owned by the service account,
   because `cti-agent` runs every command as that account - a 0600 file of
   yours in /tmp is unreadable to it. Only CVEs the
   scanner still finds today are filed, and a CVE that already has a ticket is
   updated, not filed again. Existing tickets keep their summary and labels.
8. **Existing AppSec tickets will get one comment** on the next run listing the
   newly included potential Critical and Urgent findings (the findings
   fingerprint now includes them). That is expected, not a fault.

## 1.3.2 — 2026-10-19

### Changed

- **Automatic replies always go to Deleted Items.** The mailbox cleanup only
  deleted an out-of-office when the digest had recorded reading it, checked
  only its headers, and skipped the whole run on a day with no CTI email - so
  replies arriving after the morning read, from systems that omit the
  auto-reply headers, or on a quiet day stayed in the inbox for good. Now an
  automatic reply is deleted read or not, recognised by its headers **or** a
  subject that starts `Automatic reply:`, `Out of Office:`, `Autoreply:` and similar
  variants, on every run. Anyone can title a message that way, so a
  subject-only match no lane has read yet waits `GRAPH_LOOKBACK_HOURS` for
  the digest, and one the digest took a CVE from is archived instead.
  Deleted Items is recoverable; nothing purges.
- **Mail is archived once the lane that owns it has seen it.** Qualys WAS scan
  notifications used to stay in the inbox forever: the digest reads them and
  finds no CVE, and the AppSec weekly that reports on them recorded nothing.
  `cti-appscan --seen-out` / `--commit-seen` now record the notices a weekly
  covered, only after a real send (`state/processed-appscan.json`), and the
  cleanup archives them after the usual grace. Only notices that parsed are
  claimed, and the Qualys sender check now matches the address's domain
  exactly - it was a substring test on "Name <address>", which a display
  name could satisfy. Mail no lane owns - reported phish, Defender alerts,
  colleagues - is still left alone.
- **The cleanup looks back 14 days, not 3** (`MAILBOX_LOOKBACK_HOURS` default
  336, was 72), so a weekly lane's mail is still in view when it is
  archived. `cti-mailbox --lookback 720h` sweeps further for a one-off.
- **Domains: Proofpoint on Demand, from DNS.** A new weekly section, on when
  any domain's MX is on PoD: domains NOT YET ON THE GATEWAY (acquisitions
  whose mail is still at Microsoft 365, Google or another system, named, with
  how many weeks), MX on another organisation's PoD tenant (High), senders
  whose SPF does not authorise PoD (send route unconfirmed), and leftovers
  after a move (another mailbox provider still in SPF, a Google DKIM key).
  The tenant is learned from the MX records only when one has a strict
  majority (otherwise the check is off and the log says to pin it with
  `PROOFPOINT_POD_TENANT`); nested SPF includes count.
  No credentials. The PoD Log API half stays on the backlog.

### Fixed

- **`install-fedora.sh` was not executable.** A commit on 2026-10-12 dropped
  its executable bit (and those of `run-digest`, `run-patchtuesday`,
  `run-mailbox-cleanup`, `dev-run`, `brief.py`, `mailer.py`), so
  `./fleet-kit/install-fedora.sh` answered "Permission denied". The box's
  installed runners were unaffected (the installer copies them 0755). Bits
  restored, and a lane test now fails on any script git does not record as
  executable.

### Upgrade

Pull, reinstall. Then, in `/etc/cti-agent/fleet.env`:

```bash
sudo sed -i 's/^MAILBOX_LOOKBACK_HOURS=72$/MAILBOX_LOOKBACK_HOURS=336/' /etc/cti-agent/fleet.env
```

The next cleanup will move mail it used to leave: auto-replies without the
headers or never read, and WAS notices after the next AppSec weekly. Look
at a dry run first - `sudo cti-agent run-mailbox-cleanup` - and, for the
backlog already sitting there, a one-off
`sudo cti-agent cti-mailbox --lookback 720h --timeout 10m`, then the same
with `--for-real`.

## 1.3.1 — 2026-10-18

### Fixed

- **Qualys host counts stopped at the first page.** The Host List Detection
  API returns 1,000 hosts per page and a WARNING with the next page's URL
  when there are more. The client read the first page only, so a QID on
  more than 1,000 hosts - a cumulative update across the Windows estate -
  was counted from whichever hosts happened to be on page one, and nothing
  in the daily, the Jira tickets or the Patch Tuesday exposure table said
  the number was partial. Every page is now read and merged (a host is
  counted once per QID across pages). The page size is set explicitly.
- **When not every page can be read, the count says "at least".** A later
  page failing, a next-page URL pointing anywhere but `QUALYS_BASE_URL`
  (it is never followed - the request would carry the account's
  credentials), or the 200-page safety limit marks every count from that
  call as a floor, through the same path the 5,000-host cap already used.
  A failure on the first page is still an error.
- **The KnowledgeBase download follows pages too**, and a rebuild or
  incremental refresh that could not read every page is refused rather
  than saved: the cached CVE→QID map is kept.

### Changed

- **`FLEET_ALLOW_TO` is now `VM_ALLOW_TO`.** It only ever gated the
  vulnerability digest, and beside `WAS_ALLOW_TO` and `DOM_ALLOW_TO` the
  "FLEET" name read as if it covered every lane. Lane lists already
  referenced it as `$VM_ALLOW_TO`. Both mailers still read the old name and
  log a note asking for the rename; `$FLEET_ALLOW_TO` and `$VM_ALLOW_TO`
  references in lane lists both resolve. Both names set to **different**
  lists refuses every send that uses an allowlist (escalations to the
  operator still go) and `cti-mailer --check` reports it - one control,
  one value.

- **`--to-dev` on every runner that mails, and on `cti-alert`.** It reached
  only `cti-mailer` in 1.3, so testing a lane meant a dry run and then a
  hand-built `cti-mailer --to-dev` against the right file. `run-digest`,
  `run-patchtuesday`, `run-appscan` and `run-domains` now take `--to-dev`:
  the real lane, mailed to `FLEET_DEV_EMAIL` only with a `[DEV TEST]`
  subject, and **otherwise a dry run** - no already-sent record (so the real
  send still goes), no Jira writes, no baseline advanced, no Patch Tuesday
  manifest or mark-sent, no board line. A lane's own `*_TO` / `*_ALLOW_TO`
  are not consulted, so a report can be seen before its audience is
  configured. `run-patchtuesday --month M --to-dev` replays a past release
  to you without `--for-real`. `run-appscan --to-dev` sends its
  authentication-failure alert to you as well, through the new
  `cti-alert --to-dev`, which mails `FLEET_DEV_EMAIL` and posts nothing to
  the board. With `--dry-run` too, nothing is mailed. Unset
  `FLEET_DEV_EMAIL` is refused before any work.
- **`run-patchtuesday` and `run-mailbox-cleanup` on macOS bash 3.2.** An
  empty argument array (no `--month`, no `--no-manifest`, no thresholds) is
  "unbound" there under `set -u`, so the runners died on the Mac while
  working on the box's bash 5. Guarded expansions now, and a test refuses
  the unguarded form in any runner.

### Upgrade

Pull, reinstall. Expect larger host counts on widespread QIDs in the next
daily and on open Jira tickets - those are the real numbers, not a
regression. Worth one spot check: pick a QID on most of the estate and
compare the daily's host count with the Qualys console.

Rename `FLEET_ALLOW_TO=` to `VM_ALLOW_TO=` in `/etc/cti-agent/fleet.env`
when convenient - nothing breaks until you do, the mailer just notes it:

```bash
sudo sed -i 's/^FLEET_ALLOW_TO=/VM_ALLOW_TO=/' /etc/cti-agent/fleet.env
sudo cti-agent cti-mailer --check | grep -i allow
```

## 1.3 — 2026-10-17

### Added

- **Man pages for every operator command** - the ten Go binaries, the six
  `run-*` runners, `fleet-db`, `fleet-board`, the `cti-agent` wrapper, the
  four Python lanes and `dev-run`: NAME, SYNOPSIS, DESCRIPTION, OPTIONS or
  COMMANDS with every flag, ENVIRONMENT, FILES, EXIT STATUS, EXAMPLES and
  SEE ALSO, in `man/man1/`. The installer copies them to
  `/usr/local/share/man/man1`. A lane test fails if a flag, runner argument,
  lane argument or subcommand is missing from its page; `task man:lint`
  checks rendering.
- **Patch Tuesday reads Microsoft's own release data.** The Security Update
  Guide's CVRF API (`api.msrc.microsoft.com`, public, no key) is now the
  primary source for the counts, severities, exploited and publicly disclosed
  CVEs, the by-impact table, product families and the CVE list correlated
  with Qualys. The release is the CVEs Microsoft assigned, first published on
  Patch Tuesday, that need customer action; cloud-only fixes are counted
  separately. New `--url-msrc URL|none`.
- **BleepingComputer is the cross-check.** A total that differs from
  Microsoft's is stated in the email with the likely reason.
- **The Qualys blog is optional.** It answers 403 to Azure addresses. It is
  still tried for its published QQL; when it fails it is listed as "optional,
  not read" and does not mark the report incomplete.
- **Domains lane follows the security team's decision chart.** New
  inventory markers `receive`, `saas`, `unknown`, `legacy` (with `send`)
  choose each domain's row; no marker is "no mail at all". Each row says what
  MX, SPF, DKIM and DMARC the domain should publish, and the difference is
  listed as DNS CHANGES FOR IT: exact records for the lock-down rows (`v=spf1
  -all`, DMARC `p=reject`, null MX `0 .`, DKIM keys deleted), a starting
  `p=none` DMARC for senders with none, review items otherwise. `unknown` is
  never tightened; broken SPF is fixed before DMARC enforcement.
  **`send` alone now means send-only** - mark mail domains `send receive`.
- **`cti-mailer --to-dev`** sends a report only to `FLEET_DEV_EMAIL`, never
  CC'd, subject prefixed `[DEV TEST]`: a preview in a real mail client
  without mailing the team.
- **Patch Tuesday reads saved copies of the articles.** Both publishers'
  bot checks refuse the Azure box. Save the Qualys review and the
  BleepingComputer article in a browser into
  `/var/lib/cti-agent/inbox/patchtuesday/YYYY-MM/` (names containing
  `qualys` / `bleeping`, `.html` or `.txt`) before running it and the lane
  reads them instead of fetching (`--drop-dir`). Run by hand for now, timer
  disabled: CHEATSHEET section 7a. Without them it sends
  from Microsoft's data and says where to save them. With Microsoft's data
  loaded, a missing article no longer marks the report incomplete.
- **Long-lapsed registrations are not reported as problems.** A domain
  cancelled, expired or transferred out more than 45 days ago is listed once
  under INVENTORY for removal from `domains.txt` and not probed; unlisted
  ones are ignored. They used to produce "no nameservers", "status CANCELLED"
  and "expired 2013" every week.
- **INVENTORY vs GODADDY at the top of the domains report.** Domains in the
  registrar account but missing from `domains.txt` (with status, expiry and
  auto-renew) and domains in `domains.txt` that the account does not hold,
  as one section and one sentence in the lead, instead of 40-odd separate
  review cards.
- **One Jira lock-down ticket per domains run.** `cti-domains --actions-out`
  writes the changes; `cti-jira --domains-actions` files them as one ticket
  (every change needs the same GoDaddy access), or comments on the open one
  only when the list changed, and says once when nothing is left.
- **CHEATSHEET.md** - the operator's one-page view of the box: health check,
  installed version, timers, dry runs, logs, troubleshooting. `task
  cheatsheet:pdf` renders it to a PDF (needs `pip3 install reportlab`).
- **FLEET TICKETS in the daily.** Every fleet ticket cti-jira re-checks is
  listed - key and link, CVE, Jira status, hosts the scanner sees today, and
  what the re-check did ("commented: no detections remain", "no change - no
  comment", "not re-checked: the scanner lookup failed") - with tickets closed
  in the last 30 days below. A ticket used to appear only on a day its CVE was
  back in the mail, so the daily follow-up reached Jira and not the reader.
  The domains lock-down ticket is listed there too, and the follow-up no
  longer reports it as a ticket "with no CVE label".
- **The domains report leads with WEBSITES.** Which domains have a live
  site - sitecheck.go's first use - was only in the inventory table at the
  bottom. The report now opens with it (after INVENTORY vs GODADDY, when the
  account and the inventory disagree), grouped as live (final host, status,
  page title), redirecting to another domain, registrar-hosted, parked, DNS
  but no working page, no website, and not checked, and the lead says it in
  one sentence.
- **The incomplete-sources banner says what the report was built from**
  ("Built from X only; could not read Y"), not just what failed.

### Fixed

- **Uninstall left three timers enabled.** It disabled a hand-kept list that
  stopped at patchtuesday; the mailbox, appscan and domains timers stayed
  enabled, pointing at removed units. It now disables every installed
  `cti-agent-*.timer`.
- **Anyone could get mail archived by setting `X-CTI-Agent-Sent`.** The header
  was the mailbox name and its mere presence marked a message as the fleet's
  own: the digest skipped it unread and cti-mailbox archived it. The value
  now carries an HMAC keyed from the app's client secret; an unsigned or
  forged header is ignored. cti-mailbox archives only signed mail (the sender
  address alone is no longer enough); the digest still also skips mail from
  its own mailbox.
- **A failed heartbeat was never recorded.** Under errexit a non-zero
  `claude` exit ended run-checkin before the budget record, so failures were
  not counted, rate-limit backoff never engaged, and out-of-credit could not
  reach the HOLD path.
- **A digest that sent but failed to record could be sent twice.** The
  post-send steps ran under errexit (the 1.2.1 weekly `KeyError`). Counts now
  fall back to zero; a failed `fleet-db sent` exits 3 with the exact command
  to record it by hand; a failed board post is a warning.
- **Patch Tuesday replays overwrote the release manifest.** With `--month`,
  the runner's `--json` path was `state/patchtuesday-YYYY-MM.json`, the
  manifest's own name. The dump now goes to `reports/`, and
  `cti-patchtuesday` refuses a `--json` path that is the manifest.
- **`run-patchtuesday --dry-run` reset a sent manifest to unsent**, putting
  the release's CVEs back into the next daily. New `--no-manifest` flag,
  passed on dry runs.
- **`cti-patchtuesday --dry-run --json` wrote the file.** A dry run now writes
  nothing.
- **`cti-alert --dry-run` posted a real line to the board.** It now prints
  the line it would post. ESCALATION is posted as INFO "escalated", not
  ERROR "failed".
- **cti-jira commented on tickets with the write gate closed.** An empty
  `JIRA_ALLOW_CREATE` stopped new tickets only; comments, CSV attachments and
  exposure properties went ahead. Every write is gated now; with the gate
  closed the follow-up runs read-only and the digest keeps its ticket links.
- **Hand runs did not load `fleet.env`** for cti-kev, cti-budget, fleet-db
  and the Python lanes. The `cti-agent` wrapper loads it as the service
  account (keeping its own layout variables), and cti-budget loads it too.
- **cti-budget panicked on an unreadable ledger.** It now reports the path
  and exits 1, and `record` never overwrites a ledger it could not read.
- **dev-run** read P1-P4 counts (a `KeyError` since the Sev rework), missed
  `MISSING  Mail.Read` (two spaces), and reported both roles granted when
  `mailer.py --check` stopped before the token.

### Upgrade

Reinstall. `man cti-domains` works afterwards.

Patch Tuesday is run by hand for now: leave `cti-agent-patchtuesday.timer`
disabled (`sudo systemctl disable --now cti-agent-patchtuesday.timer` if it is
on) and follow CHEATSHEET 7a each month. Microsoft's data loads from the box;
save the two articles into the release's inbox folder before the run to
include their commentary.

Update `/etc/cti-agent/domains.txt`: change `send` to `send receive` on every
domain that also receives mail, and add `receive`, `legacy`, `saas` or
`unknown` where they apply. Run `sudo cti-agent run-domains --dry-run` and
read DNS CHANGES FOR IT before the Monday run files the ticket - every
unmarked domain gets a null MX in it.

Mail the fleet sent before this upgrade carries the old unsigned header, so
cti-mailbox leaves it in the inbox instead of archiving it. It drops out of
the 72-hour window by itself; archive it by hand if the backlog alarm fires
in the meantime. Rotating the client secret has the same effect on mail
already in the inbox.

An old `state/patchtuesday-YYYY-MM.json` that a replay overwrote is not a
valid manifest. Check `jq .sent /var/lib/cti-agent/state/patchtuesday-*.json`;
a file that prints `null` was clobbered. Delete it; the daily then reports
that month's CVEs again, which is the safe direction to be wrong in.

## 1.2.1 — 2026-10-12

### Fixed

- **Jira ticket links appeared only for CVEs in that day's mail.** The
  cve -> ticket map the digest reads held only the tickets cti-jira filed or
  updated from that morning's findings, so a ticketed CVE lost its link on
  any day it was not back in the news. `--follow-up` already finds every
  fleet ticket; it now hands them all to the map (today's references win).
- **The Monday weekly overwrote the Monday daily's findings, and had no ticket
  links.** Both wrote `state/enriched-$DAY.json`, an hour apart. The weekly
  now writes `weekly-enriched-$DAY.json` - not prefixed `enriched-`, so
  `cti-kev`'s newest-file pick still finds the daily - and borrows the newest
  daily ticket map, since it never runs cti-jira itself.

- **The weekly failed after sending, and the send went unrecorded.** The
  rollup counted only the severity bands that had findings; a week with no
  Sev5 had no `Sev5` key, and the log step after the send died with
  `KeyError`. The unit showed failed, and because the send was never
  recorded, restarting it would have mailed the weekly a second time. The
  rollup now always lists all five bands, and the log step tolerates a
  missing one.

- **The domains check used the box's own DNS, which can be internal.** On the
  first real run the organisation's main sending domains showed "no SPF
  record" and "no DMARC record" - the internal zone for them has neither,
  the public zone has both. It now asks public resolvers by default
  (`DOMAINS_DNS_SERVERS`, `system` to opt out), and the web and SMTP probes
  connect to the addresses those return.
- **A failure on the domains lane's first run read as a change the next
  week.** A lookup that failed, or a site that did not answer, with nothing
  earlier to carry forward was saved as absent or down; six hours later the
  dry run reported "MX appeared", "DMARC appeared" and "started serving a
  working page" for domains that had not changed. Both are saved as unknown
  now, and unknown is never reported as a change.

### Upgrade

Reinstall, and delete `/var/lib/cti-agent/state/domains-state.json` once, so
next Monday's run starts a clean baseline from public DNS instead of diffing
against one taken through the internal resolver. Links return from the next daily; the weekly gets them from the
following Monday. If a weekly failed this way, it WAS sent: record it by hand
rather than restarting the unit, which would send it again -
`sudo cti-agent fleet-db sent <day> <S5> <S4> <S3> <S2> <S1> <request-id> weekly`
with the numbers from the journal's `[brief] wrote ...` and `sent` lines.

## 1.2 — 2026-10-10

### Added

- **A weekly domains check (`cti-domains`, `run-domains`,
  `cti-agent-domains.timer`, Mondays 08:00).** For every domain in an
  operator-kept inventory (`/etc/cti-agent/domains.txt`, never in the
  repository; `send` marks a domain that sends mail): is it in the GoDaddy
  account, and is the account holding domains the inventory does not list;
  status, expiry, auto-renew and transfer lock; registrar nameservers against
  DNS; live, parked or dark; dangling CNAMEs; certificates verified separately
  from reachability; and mail records by role - SPF, DKIM at known selectors
  and an enforcing DMARC with `rua=` for senders, `v=spf1 -all` and
  `p=reject` for everything else, with a non-sender that authorises senders
  asked as a question. Then what changed since last week. Mailed to the
  security team through `cti-mailer --lane dom` (`DOM_TO` / `DOM_ALLOW_TO`,
  fail-closed, no fallback). Forked from a standalone checker and reshaped:
  a failed lookup is reported as not checked rather than as a missing record,
  and the parking indicators no longer match real Website Builder sites.
- **Every check `sitecheck.go` made.** A/AAAA, CNAME, status, final URL and
  response time per host; one retry; live as 2xx/3xx; its GoDaddy markers kept
  as "registrar-hosted" beside the stricter parked test; `-mxstrict` (MX hosts
  must resolve); `-smtp` (banner from the first answering MX) with STARTTLS,
  each MX dialled once per run; and its full CSV, same columns first, attached
  to every send with formula-leading cells defused. Added beside them: 5xx and
  off-portfolio redirects, `http://` that does not upgrade, DKIM key size,
  certificate SANs and HSTS in the CSV.
- New settings: `DOMAINS_SMTP`, `DOMAINS_SMTP_PORT`.
- New settings: `DOM_TO`, `DOM_ALLOW_TO`, `DOMAINS_FILE`, `GODADDY_PAT`
  (read-only, `domains.domain:read`; the client never requests auth codes),
  `DOMAINS_DKIM_SELECTORS`, `DOMAINS_DMARC_RUA` (empty pending a decision on
  where aggregate reports go).

### Fixed

- **`example.com,send` in the inventory was skipped as "not a domain".** A
  list exported from a spreadsheet uses commas, and the parser split only on
  whitespace, so the four domains that had been marked as senders were the
  four that were dropped. Commas now separate like spaces.

### Upgrade

Reinstall, then configure the new lane before enabling its timer - nothing
existing changes:

1. Create `/etc/cti-agent/domains.txt` (`root:ctiagent`, `0640`), one domain
   per line, `send` after the ones that send mail.
2. In `fleet.env`: `DOM_TO`, `DOM_ALLOW_TO` (required to send), and
   `GODADDY_PAT` when you have it (without it the subject says
   `[REGISTRAR NOT CHECKED]`). Set `DOMAINS_DKIM_SELECTORS` to your mail
   service's selectors. Leave `DOMAINS_SMTP` empty if outbound 25 is open.
3. `sudo cti-agent run-domains --dry-run`, read the report and its CSV, then
   `sudo systemctl enable --now cti-agent-domains.timer`.

Separately, if your live `/etc/cti-agent/feeds.txt` still has
`msrc.microsoft.com/blog/feed`, replace it with
`https://api.msrc.microsoft.com/update-guide/rss` - the installer never
overwrites that file, so the template fix did not reach it.

---

## 1.1.1 — 2026-10-06

### Fixed

- **Tickets were only re-checked when their CVE was back in the news, and were
  never told they were finished.** Ticketing started from that morning's mail,
  so an open ticket whose CVE nobody mentioned again was never compared with
  the scanner. And the "no detections remain - this ticket can be closed"
  comment, though written, could never be sent: only PRESENT findings reached
  the ticketing step, and a remediated CVE is not present. `run-digest` now
  passes `cti-jira --follow-up`, which re-checks every fleet ticket that is
  open or touched in the last 30 days, under the same quiet rules. A lookup
  that failed or returned `UNKNOWN` leaves the ticket alone, so an outage can
  never be reported to IT as a fix.

  **At most one host-change comment a week per ticket, against what IT was
  last told.** The first dry run against real tickets showed three of four
  would be commented on every morning, each for one host swapped for another
  on a list of hundreds. Two causes, both fixed: the stored host list was
  overwritten every run, so a host that missed one scan was "newly affected"
  when it came back - it is now the list IT was last given, updated only when
  IT is told; and there was no rate limit - hosts that appear within a week of
  the last host-change comment are now held and named together in the next.
  "No detections remain", a new QID, a comeback after the all-clear, and
  closed-but-still-detected are never held.
  Tickets from before this change have no record of when IT was last told,
  so on the first morning their weekly clock starts instead of a comment
  going out; a host still affected a week later is reported then. Test tickets no longer carry the
  `cti-agent` label, and the setup test ticket (`CVE-1900-00000`) is skipped
  by name.

  A dry run now says what each ticket would get - `WOULD COMMENT: grew 300 ->
  340 host(s), 40 new host(s)`, `WOULD COMMENT: no detections remain`, or
  `no change - no comment` - from the same decision function the real run
  acts on, so the preview and the run cannot disagree.

- **The orchestrator's grant allowed what its prompt forbade.** `fleet-db:*`
  let a beat record a digest as sent (so `run-digest` would skip the real one)
  and rewrite stored findings; `cti-patchtuesday:*` let it mark a Patch Tuesday
  manifest sent, which makes the daily drop the release's CVEs. The grant is
  now per subcommand, and `cti-patchtuesday` refuses `--mark-sent` with
  `--dry-run` - previously the combination marked the manifest sent despite
  `--dry-run` promising to write nothing.
- **The orchestrator's prompt described a capability it did not have.** It
  said it could "run any lane", recover with `run-digest`, escalate through
  `mailer.py`, check timers with `systemctl`, and read replies from the
  mailbox. None was granted; on an unattended beat a denied command just does
  not happen. The prompt and the `/checkin` skill now say exactly what a beat
  can run, re-runs are escalated as `sudo cti-agent ...` commands for the
  operator, and answers come back on the board. `systemctl list-timers` is
  now granted - read-only, and the only way a beat can see a disabled timer.
- **The prompt told the agent to read `fleet.env`.** It holds the Graph secret,
  the Qualys password and a Claude token, and what the model reads is sent
  with its context. It now says never to.

### Upgrade

Reinstall. Nothing to configure. The first morning after, IT may see a "no
detections remain" comment on tickets that were fixed some time ago and never
told - that is the backlog clearing once, not a burst of new activity. The
three operator playbooks
(`/cti-digest`, `/patch-tuesday`, `/scout-sweep`) are unchanged in content and
now say they are for a session with you present.

---

## 1.1 — 2026-10-06

### Added

- **A weekly application-security lane.** `cti-appscan` +
  `cti-agent-appscan.timer`, Mondays 07:30. It reads the DAST scanner's own
  scan-completion emails out of the CTI mailbox, optionally pulls per-finding
  detail from the Qualys WAS Findings API, and mails the result to the people
  who own application code.

  `internal/appscan` is a provider boundary, the way `internal/vulnlookup` is
  for host VM. A new scanner needs `Name`, `Recognises(sender, subject)` and
  `Parse(body)` — **no credentials**, so Invicti or Wiz becomes useful the day
  its email arrives rather than the day somebody negotiates API access. An API
  is an optional second interface, `DetailFetcher`; losing it costs
  per-finding detail and not the report.

  The lane reports the Qualys **Active** counts, never the lifecycle totals.
  The two differ by an order of magnitude on a real application — one carries
  270 "Urgent" on record of which 247 are already fixed — and leading with the
  lifecycle number would be a false alarm twelve times too large.

- **Per-lane recipient allowlists, fail-closed.** `cti-mailer --lane was`
  resolves `WAS_TO` against `WAS_ALLOW_TO` and **refuses if either is unset**,
  naming the variable that is missing. There is no fallback to the digest
  audience, and `--approve` does not override an empty list. An allowlist may
  reference another by name — `PT_ALLOW_TO=$VM_ALLOW_TO,extra@example.com` —
  with cycles caught and a depth limit; a wildcard reference (`$*_ALLOW_TO`)
  is refused by name rather than resolved to something surprising.

### Fixed

- **An unauthenticated scan was being reported as a coverage gap.** It is not
  one. The first real send of this report put three applications under a
  heading reading `COVERAGE GAPS`; all three are public sites with **no login
  at all**, so there is no missing authentication record, nothing to configure
  and nothing for the audience of that mail to do. The lane was filing a
  defect against three applications for being public.

  Authentication is now two separate things. A **label** — every count in the
  report says whether an authenticated or an unauthenticated scan produced it,
  because a zero from a scan that never logged in is not the same number, and
  that caveat is the part of the old design worth keeping. And a **fault**,
  but only when a credential *was* configured and *failed*: then the scan
  covered the public surface while still looking configured in Qualys, and
  this week's counts are not comparable with last week's.

  `Auth.Blind()` is gone, replaced by `Configured()`, `Authenticated()`,
  `Failed()` and `Label()`. `ScanResult.Attention()` no longer fires merely
  because a scan did not authenticate — it used to sort three public sites to
  the top of the report every week with nothing actionable in them, and a
  permanent alarm is read as no alarm.

- **A failed login no longer alerts the wrong people — or nobody.** An
  authentication failure now emails the fleet operator through `cti-alert`
  (kind `HOLD`), because the App Dev audience cannot fix a scanner credential.
  `cti-appscan --auth-fail-out` writes the finding to a file and the runner
  decides what to do with it: this binary does not send mail and must not
  learn how, since `cti-mailer` holds the only recipient gate in the fleet.
  The file is written on **every** run — empty means "checked, none failed",
  absent means an older binary that never checked, and the runner says which.

- **A broken login stopped erasing the open backlog.** Found by rendering it:
  the report partitioned "faulted" and "counted" scans as mutually exclusive,
  so the week an application's login failed it dropped out of `OPEN NOW`
  entirely and the severity tiles went to zero with it. An application with 23
  Urgent findings open does not become clean because the scanner had a bad
  password. The two sets now overlap; only an *incomplete* scan has no numbers
  to print.

- **`run-appscan` did not source `fleet.env`.** Every other runner does, and
  this one did not, so `cti-appscan` ran with no credentials at all and
  reported `missing required environment variables: CLIENT_ID CLIENT_SECRET
  GRAPH_MAILBOX TENANT_ID` on a box where all four are set. The error was
  accurate and pointed at the wrong thing. A lane test now asserts that every
  runner reads the config file, because four of the five followed an unwritten
  convention and the fifth did not.

- **`cti-appscan` did not load `fleet.env` itself.** The runner fix above made
  the timer work and left the hand-run broken: `sudo cti-agent cti-appscan
  --since 336h` still reported the same missing variables, because the binary
  never opened the file - only its runner did. Every other command that reads
  credentials calls `fleetenv.Load()`; a lane test now fails one that does not.

- **The AppSec unit logged as the weekly digest.** It was generated from the
  weekly's unit and kept `SyslogIdentifier=cti-agent-weekly`, so its lines -
  including `AUTH FAILED` - read as the digest's, and `journalctl -t
  cti-agent-appscan` returned nothing. A lane test now checks every unit logs
  under its own name.

- **Per-finding detail was empty for nearly every application.** The finding
  search was keyed on `webApp.name`, and the name it was given came from the
  scan title ("Example Run #47" -> "Example"), which on the real estate matched
  the scanner's application name in almost no scan. The search returned zero
  findings without error and the report said "detail not available". It is
  now keyed on `webApp.id` from the scan list, asks for vulnerabilities only,
  marks unconfirmed ("potential") findings as such, and no longer lists
  findings someone set to ignored in Qualys as new work. The application name
  falls back to the notification's `Target` line, not the title.

- **Quiet applications had no report link.** The link was rendered only under
  CHANGED THIS WEEK, so an application with nothing new - on the first send,
  all three public sites - never showed one. It is now one line under every
  application in OPEN NOW, and under the fault entry for a scan that did not
  finish.

- **`run-appscan` accepted and ignored unknown arguments.** The unit file was
  first generated from the weekly one and arrived with a stray `weekly` on its
  `ExecStart`. The runner would have shrugged and run in the default mode while
  the service file looked correct to anyone reading it; it now refuses.

### Changed

- **The application-security email looks like the rest of the fleet's mail.**
  The daily brief's palette, navy header band and 640px card, severity tiles,
  and a subject in the family shape — `CTI Fleet AppSec Oct 05: ...`, with
  `[AUTH FAILED]` or `[INCOMPLETE]` in front when something is broken. It
  previously read `[AppSec] Week of Oct 4: ...`, which nowhere said where the
  mail had come from.

  The severity **colours** are shared with the daily; the severity **words**
  are not, and the footer says so on every send.

- **One clickable link, for links the lane builds.** Every URL that arrived in
  scanner mail stays plain text. Each application's "open in Qualys" link is
  built from the WAS scan list: the UI host derived from `QUALYS_BASE_URL`,
  a constant path, and the scan's integer id -
  `/was/#/reports/online-reports/email-report/scan/<id>`, the same page
  Qualys's own email links to, with the id checked against a real
  notification. It is rendered as an anchor only after an https and
  exact-host check against hosts registered for that scan's provider.

- **The mailbox is reconciled with the Qualys WAS scan list.** Joined on the
  scan reference. The API supplies the real application name and id, can mark
  a scan's authentication FAILED (never the reverse), and adds vulnerability
  scans whose completion email never arrived - listed under SCANNED, NO
  NOTIFICATION with no counts, never totalled. Discovery scans, scans still
  running, and on-demand runs that failed with no email are left out; a
  scheduled authentication failure is a fault whether or not an email came.
  With no Qualys credentials the lane reports from the notifications exactly
  as before. Qualys severity 5 is a claim
  about one HTTP response; the fleet's Sev5 means exploited in the wild and
  confirmed present in the estate.

- **The weekly digest is a roll-up of stored findings, not a second mailbox
  read.** It never was a week: `cti-agent-weekly.service` runs `run-digest`
  with no `--lookback`, so it read the same 24 hours as the daily. On
  2026-10-05 both briefs reported reading the same four emails an hour apart,
  and the operator reasonably read that as the daily having sent twice.

  Widening the mailbox query to 168h does not fix it — the cleanup lane
  archives advisories on a 48-hour grace once a completed run has read them, so
  a 7-day query sees only what happened not to be archived yet. That is a
  partial week presented as a whole one, which is worse than the honest 24
  hours it produced before. `fleet-db rollup --days N` reads the findings table
  instead: those are what the fleet concluded, they outlive the mail they came
  from, and they are immune to the archive grace.

- **The weekly subject is no longer byte-identical to the daily's.**
  `subject(data, kind)` accepted `kind` and used it in none of its six return
  paths, so the Monday weekly went out with the daily's subject line —
  including "in the last 24h" on a report covering seven days.

### Upgrade

Reinstall and set two variables. The lane's timer is **not** enabled by the
installer; see [RUNBOOK 11f](RUNBOOK.md#11f-the-weekly-application-security-lane).

```bash
# in fleet.env, both required - the mailer refuses without them
WAS_TO="appdev-leads@example.com"
WAS_ALLOW_TO="appdev-leads@example.com,security@example.com"
```

```bash
sudo cti-agent run-appscan --dry-run     # open the HTML it leaves in state/
sudo systemctl enable --now cti-agent-appscan.timer
```

Nothing else changes meaning. The Qualys WAS Findings API uses the same
credentials as the VM lane and the same `QUALYS_BASE_URL`, but needs the WAS
module enabled on the account's role — without it the lane reports counts from
the notification emails and logs a warning naming the role.

---

## 1.0.2 — 2026-10-04

### Fixed

- **The daily digest was reading its own output back in.** The digest is
  delivered to the same mailbox it reads, so yesterday's digest arrived as
  today's input, the extractor pulled the CVEs out of our own report, and they
  were presented as newly mentioned. Self-sustaining: a CVE reported once
  re-entered every subsequent run, so the daily could never go quiet and the
  "emails mentioning a CVE" count was fiction. Observed on 2026-10-04, where
  the single CVE-bearing email of the run was the previous day's own Sev5
  digest. Outgoing mail now carries `X-CTI-Agent-Sent`, and the ingest skips
  anything carrying it — with the sending address as a backstop for mail sent
  before the header existed. The count of skipped messages is logged, because a
  filter that silently removes input is how the next blind spot starts.
- **The cleanup lane would have left those reports in the inbox forever.** Its
  first rule is "no processing record → leave, absolute", and our own mail is
  now deliberately never processed. Left alone it would have filled the inbox
  and then escalated *"the agent has stopped reading the mailbox"* about a
  mailbox it was reading perfectly well. Self-sent mail is archived — not
  deleted; there is no case for a schedule quietly destroying our own audit
  trail in a shared mailbox.
- **A dead feed was reported as malformed XML for four days.**
  `msrc.microsoft.com/blog/feed` now 302s to an HTML page. Every run logged an
  identical `mismatched tag: line 124, column 158` — true about a stable HTML
  document, thoroughly misleading about the cause, and it sent the diagnosis
  looking for a bad byte in somebody's XML. Twenty-four consecutive beats
  recorded it as "known, persists". Microsoft advisory coverage was dark
  throughout. `scout` now distinguishes "this is not XML at all" from "this XML
  is malformed" and says which, and the feed is replaced by the MSRC Update
  Guide RSS — one item per CVE, which is what the lane keys on.

### Changed

- `task ship` ran `gofmt -w .` and then `git push`, so any reformatting it
  performed was left uncommitted and never pushed. That is how `v1.0` got
  stamped `-DIRTY`. It now fails instead: a gate may not modify the thing it is
  checking. Run `task fmt` yourself and commit the result.
- `task check` referenced a task named `fmt:check` that did not exist, so the
  CI entry point would have errored on first use. It exists now.

### Upgrade

Nothing required. Pull, reinstall.

On the first scout run after this, expect a large batch of first-seen CVE IDs:
the Update Guide feed carries every revision, including a lot of republished
Chromium entries, and none of them are in the seen-set yet. Worth watching that
run rather than letting it land unattended.

---

## 1.0.1 — 2026-10-02

### Fixed

- **The installer could stop halfway and look like it had finished.** Reading
  an optional `FLEET_*` key from `fleet.env` with a `grep` pipeline ends the
  script when the key is absent: grep exits 1 on no match, `set -o pipefail`
  carries that status to the end of the pipeline, the assignment inherits it
  and `set -e` exits — with no message at all. A box whose `fleet.env` predated
  the Patch Tuesday lane stopped four lines after printing `✓ daemon-reload`,
  with 400 lines left to run. The wrapper, `/etc/cti-agent/version` and the
  entire verification block never executed, and the visible output was
  indistinguishable from a clean install. Config reads now go through a `sed`
  helper that returns empty for an absent key.
- **`check_path` could never report a missing path.** It read config the same
  way, so a missing key killed the script one line before the `"$1 is unset"`
  branch that exists to report missing keys.
- **`scrub-history.sh` aborted its verification when the scrub had worked.**
  `git grep -l` exits 1 on zero matches, and zero matches is the success case,
  so a fully scrubbed history stopped the loop instead of printing "clean".
- **`run-checkin` could die while explaining why it was holding.** `grep -v`
  exits 1 when it filters everything out, which is reachable whenever
  `cti-budget` prints a flag and no explanation.

### Added

- `internal/shellgate`: a test that fails the build on this pattern. It ran
  clean against all 11 fleet scripts and is checked against the three real
  lines that caused the bugs above, so a failure can be trusted.
- The installer now has an EXIT trap. Any end other than reaching the
  "Installed" banner prints the line number and says the box is partially
  installed. Deliberate exits — `--help`, a dry run, a failed verification —
  stay quiet.
- `task test:syntax` derives its script list from the directories instead of a
  hand-written one. It was checking 9 of 11 scripts; `run-mailbox-cleanup` and
  `compare-mailers.sh` had never been checked.

### Upgrade

Nothing. Pull and reinstall.

If an install ever stopped early on this box, re-running the installer is
sufficient — it is idempotent. Confirm with:

```bash
sudo cat /etc/cti-agent/version      # must exist
sudo cti-agent cti-mailer --check | head -2
```

---

## 1.0 — 2026-10-02

First tagged release. Everything below was already running; this marks the
point from which changes are tracked and a rollback target exists.

### Lanes

- **Daily and weekly digest** — reads the CTI mailbox over Graph, enriches
  against NVD, EPSS and CISA KEV, confirms presence against Qualys Host
  Detection, scores Sev5–Sev1 and emails the result.
- **Patch Tuesday** — monthly synopsis correlated against the estate, reported
  per QID. Holds its CVEs out of the daily so the same release is not reported
  twice.
- **KEV deadlines** — CISA remediation dates for CVEs confirmed present.
- **Mailbox cleanup** — archives advisories the agent has taken a CVE from,
  deletes header-confirmed auto-replies, leaves everything else for a human.
- **Orchestrator heartbeat** — a `/checkin` beat every two hours, rationed
  against the subscription by `cti-budget`.
- **Jira ticketing** — one ticket per confirmed KEV or Sev5 CVE, carrying every
  QID and host, updated in place as exposure changes.
- **Failure alerting** — `cti-alert` on unit failure, and as the orchestrator's
  only route to a human.

### Added in the run-up to this tag

- `cti-jira`: files and updates one Jira ticket per CVE, identified by a label
  on the ticket rather than a local database, so closing or moving a ticket in
  the UI cannot cause a duplicate. Host lists attach as CSV; the attachment is
  never truncated at any scale.
- `cti-mailer`: the Go port of `mailer.py`, verified byte-identical across a
  19-case comparison harness. **The runners still call `mailer.py`** — see
  RUNBOOK 11b to switch.
- `internal/triage`: deterministic extraction of CVEs, MITRE techniques and
  defanged indicators from advisories that carry no CVE at all. Nothing invokes
  it yet.
- `fleet-db note`: records that a finding has been handed to someone, so a
  ticketed CVE stops being reported as un-actioned.
- Version stamping: binaries carry their tag and commit, and the installer
  records what it built.

### Fixed

Six defects, five of which reported success while doing nothing:

- **The duplicate-send guard had never once fired.** `fleet-db sent` read the
  kind from the message-id's argument index, so every digest was stored under a
  Graph request id and `was-sent` could never match.
- **`findings --stale-days`** compared an ISO-8601 timestamp against SQLite's
  own format as raw strings, silently missing everything from the boundary day.
- **The cleanup archived mail the digest had not finished reading**, so CVEs
  reported only by those advisories dropped out of the next digest. The grace
  period must now be at least as long as the ingest window, enforced at startup.
- **`run-mailbox-cleanup` was never installed** — the copy step used a
  hand-written list while the verification step asserted the file existed.
- **Errored heartbeats consumed model quota**, so a crash-looping orchestrator
  rationed itself into a hold and reported a budget problem instead of a code
  one.
- **An escalation was presented as a crash**, titled "CTI fleet failure" with
  "systemd result: success" underneath.

### Known gaps

- The Graph app is **not scoped to one mailbox**. With `Mail.ReadWrite` and
  `Mail.Send` consented tenant-wide and no access policy, the credential on the
  fleet host can read, move and send as any mailbox in the tenant. Verified
  2026-10-01, accepted for now, recorded in SECURITY.md with the probe to
  re-check it.
- `/etc/cti-agent/ORG-PROFILE.md` is created unfilled. The triage lane stays
  dormant until it is written.
- The orchestrator cannot send mail by design. Escalation is `cti-alert` only,
  which has no `--to`.

### Upgrade

**From an untagged install:**

1. `MAILBOX_LOOKBACK_HOURS` and `MAILBOX_MIN_AGE_HOURS` are new, and the
   installer will refuse to start if the grace is shorter than
   `GRAPH_LOOKBACK_HOURS`. The defaults (72 and 48 against an ingest window of
   24) are consistent; you only need to act if you set them yourself.
2. For Jira ticketing, set `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
   `JIRA_PROJECT_KEY` and `JIRA_ISSUE_TYPE`. Nothing is filed until
   `JIRA_ALLOW_CREATE` also names the project — it fails closed.
3. `Mail.ReadWrite` is required only for the mailbox cleanup lane. Without it
   that lane 403s; everything else is unaffected.
4. Existing files in the state directory keep their old permissions:
   `sudo find /var/lib/cti-agent/state -type f ! -perm 600 -exec chmod 600 {} +`

Nothing else requires action.
