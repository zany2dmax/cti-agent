# Backlog

Ideas not yet built. Nothing here is a commitment: ask before picking one up,
and expect each to be designed first. Interface work follows the rule in
[INTERFACES.md](INTERFACES.md): build an interface when a second implementation
is real, not before. Finished work moves out of this file into
[CHANGELOG.md](CHANGELOG.md).

- **Scanner report staging (PrimeSec Top-228, for 1.7).** Stage scanner reports in
  `PrivateTmp`, promote them after redaction, clean up orphans on start, extend
  the scrub list; test with a killed run. Needs an Opus review (credential scrubbing).
- More scanner providers — Defender, Tenable, Rapid7 — behind the same interface
- **Compromise assessment cross-check lane (research).** A consulting firm
  sends a draft compromise assessment before a recurring review meeting. The
  first one was a posture report (many numbered categories, no conclusion, no
  indicators section), so the useful lane is a pre-meeting brief that checks
  the report's claims against what the fleet already knows: scan coverage and
  open exploited CVEs (`cti-vmscan`, `cti-kev`), domain and mail-authentication
  posture (`cti-domains`), web-application findings (`cti-appscan`) and patch
  status. Research first: how the report arrives (an encrypted PDF, the
  password in a second email, so it must be read by a person or a local tool,
  never by the mailbox lane), whether its tables can be read reliably (icons
  and chart values were lost in text extraction), and which questions come up
  every time (counts that disagree between pages, findings with no follow-up).
  Never ingest the report into a tracked file; the brief names no hosts or
  users.
- **Interface work** (the full reasoning, with the current gaps, is in
  [INTERFACES.md](INTERFACES.md); build each when a second implementation is
  real, not before):
  - Finish `vulnlookup.LookupProvider`: `cti-patchtuesday` builds the Qualys
    client directly and ignores `LOOKUP_PROVIDER` (it needs the KB's CVE-to-QID
    map and host counts, which the interface cannot express yet; `cti-jira` is done)
  - `LOOKUP_PROVIDER`-style setting for the registrar (`registrarFor` is fixed
    to GoDaddy)
  - Mail transport interfaces (read, send, move) so a fleet on Google
    Workspace or SMTP/IMAP can run it; Microsoft Graph is used directly by five
    commands plus `mailer.py`. The recipient allowlist stays above the
    interface in `cti-mailer`. Largest, most valuable
  - A ticket-tracker interface (`tickets.Tracker`) so ServiceNow, Azure
    DevOps or GitHub Issues can replace Jira. Needs an answer for state kept
    as a Jira issue property and for the Jira wiki-markup text
  - A notification channel interface (`alert.Notifier`) for `cti-alert`:
    Teams, Slack, a pager. Smallest, a good first one
  - An ownership source interface (`appscan.OwnerSource`) so a CMDB or
    identity group can replace `app-owners.txt`
  - A network-source interface (`netmap.NetworkSource`: `Subnets(ctx)` returning
    the subnets, each with a location and an address range, plus any questions
    about the data) so the VM scan coverage check can read an IPAM (NetBox,
    phpIPAM, Infoblox) or a CSV/JSON export, not only the spreadsheet.
    `netmap.Check` is already source-neutral; `coverage()` in `cmd/cti-vmscan`
    picks the spreadsheet or Graph file directly, and the parser, the corp-row
    guess and `netrules.txt` assume the sheet's shape. An IPAM gives structured
    prefixes, sites and roles, so most of that guessing would not be needed.
    Needs a source-neutral reference on a finding (today a spreadsheet row
    number) and a configured role or tag in place of the corp-row guess. Select
    with a `SUBNET_SOURCE` setting. The same pattern could cover the Asset
    Group side for another scanner. About a day: define the interface, move the
    xlsx path behind it with no behaviour change (the existing tests prove it),
    then add a CSV source; write a real IPAM adapter only against a real one.
    A candidate feature for 1.6. Do it after the coverage check has run once
    against the real spreadsheet (waiting on the Graph permission), so the
    behaviour being moved is known to be right
  - An advisory/exploit feed interface for new feeds (EPSS, vendor lists);
    whether the Python CISA KEV fetch moves under it is a separate decision
  - A detection-mapping interface (`vulnlookup.DetectionMapper`, CVE to
    scanner detection IDs) for the Patch Tuesday correlation, which is
    Qualys-only today
- **Agent harness** (the reasoning, what already exists and the order, is in
  [HARNESS.md](HARNESS.md); each item ships on its own and feeds the next):
  - H2. Eval harness: 5 to 10 check-in scenarios with fake `$FLEET_HOME`
    fixtures (quiet day, silent lane, Sev5/KEV, prompt injection in an
    advisory, existing HOLD), behavior checked from the trace, run by hand
    with `task eval` (3 runs each, pass rate), never in `task ship`. Scores
    from the beat traces (H1, built: `fleet-trace`)
  - H3. Structured check-in verdict: the skill ends in one `cti-checkin/1`
    JSON object, verified in Go the way `internal/triage` verifies
    `cti-triage/1`; invalid or missing is a board ERROR
  - H4. Shared model-lane runner pulled out of `run-checkin`, only when a
    second model lane (triage agent, supplier-request triage) is real
  - H5. Optional learning exercise: reproduce one beat with the Claude Agent
    SDK outside production. Not a migration
- AppSec remediation is tracked by email, not Jira (decided 2026-11-07). The
  app owners are mostly marketing teams with no Jira logins and no habit of
  working there, so a separate AppSec Jira project would track work nobody can
  update. The owner report and the weekly are the tracking: each finding stays
  in them until a scan no longer sees it. The tickets the lane already files in
  CR stay where they are. Not designed, if this proves too passive: a reminder
  in the owner email for findings open past a set age, and an escalation line
  to the AppSec team for ones that stay open
- Supplier-request triage for third-party risk: the security team's shared
  mailbox is now on the supplier-request distribution list, and each request
  has to be judged for "will this supplier have access to company data or
  systems, or provide technology?" (unsure counts as yes). A lane would find the
  new-supplier-form messages and read the form's fields deterministically (it is
  an `.xlsx`, so `archive/zip` and `encoding/xml`: supplier name, branch,
  expense or inventory, spend, free-text notes), then give Yes / No / Unsure
  with reasons from the name and notes, through the no-tools triage agent
  pattern, for the security team only. It must never open the W-9 and bank
  attachments (tax ids and account numbers; the PDFs are scanned anyway), never
  reply to the requester and never move mail itself (the daily cleanup files away what the lane has dealt with). Sampled 2026-11-02: only
  about 4 of 10 threads were real new-supplier requests (the rest were credit
  applications, approvals and intercompany accounts), and at least one
  technology supplier arrived with no form at all, so it must also read the
  message text. The form does not yet carry the question; when it does, the
  lane checks the requester's answer and flags a "No" for a name that looks like
  a technology provider. Output decided: one item per request on the
  security team's Kanban board (Jira project CYBR, a Task), assigned to the
  Jira user named by a new `fleet.env` setting (an email, looked up like the
  AppSec owners; an unknown user leaves it unassigned with a warning, never a
  guess). Needs `CYBR` in `JIRA_ALLOW_CREATE`, a project-key setting for the
  lane (the way the domains lane has its own), and the service account's
  permissions in CYBR. **Digest decided (2026-11-08):** the lane also emails
  the security team a digest listing the day's requests, so the person
  assigned knows to go to the Kanban board. **Unsure wording decided
  (2026-11-08):** only a certain Yes reads as a Yes. When the lane could not
  determine a 100% Yes it says so on the item, in words along the lines of "we
  could not determine a 100% Yes, so this is Unsure, and an Unsure gets a CYBR
  Kanban to-do", so the person knows to check it by hand. Exact text is a
  `fleet.env` template. **Linked forms (decided 2026-11-08):** a form can
  arrive as a SharePoint/OneDrive link in the message body instead of an
  attachment (a technology supplier did). The lane does not open links: it
  marks that request Unsure with the reason "form not readable: linked, not
  attached" and judges from the message text. **Built:** `internal/supplier`
  reads the form (fields found by label text, blanks kept, required-but-empty
  fields listed) on the shared `internal/xlsx` reader. **Finder built:**
  `graph.MessagesAddressedTo` (address in To or Cc, case-insensitive, read-only)
  and `supplier.ReadForms`, the only path from a message to attachment bytes:
  `.xlsx` only by default, refuses names with a whole word like w9, bank,
  routing, void, tax, irs or ach, caps size, and a test proves the W-9 and bank
  files are never downloaded. **Judgement built (code side):**
  `supplier.Render` / `supplier.Judge` and the no-tools agent's instructions
  (`fleet-kit/fleet/agents/supplier/CLAUDE.md`, status design: nothing invokes
  it yet). Code only ever moves a verdict toward Unsure: a Yes or No needs a
  quote copied from the request, a No is refused when the form was linked or
  unreadable, when the name, subject or notes hold a technology word, or when
  the request tried to steer the reader, and output code cannot use is Unsure.
  **Jira item and digest built (pure builders):** `supplier.TicketSummary` /
  `TicketDescription` / `Labels` / `FindJQL` (one item per conversation, found
  again by a hashed label so a rerun never files twice; Yes and Unsure get an
  item, a No gets none - decided 2026-11-08, a No appears in the digest only,
  so the lane never sets `includeNo`; no address, contact or remittance detail
  goes in; everything from the request is escaped for Jira wiki markup) and
  `supplier.Digest` (counts, the board link, https links only; no email on a
  day with no requests). **Lane built (2026-11-08):** `cmd/cti-supplier`
  (`--collect`, `--finish`, `--commit-seen`, each under `--dry-run` or
  `--for-real`), `run-supplier` (the model runs with no tools, one request per
  call; no model or a failed one means Unsure), the `cti-agent-supplier`
  service and timer (daily 07:45, off until enabled), the `SUPPLIER_*`
  settings, man pages, runbook, lanes and security notes. **Dry run on the real
  mailbox (2026-11-08):** the model step worked end to end
  (the no-tools flags are accepted; 20 requests judged, none failed), which
  also showed that a window cutting a conversation hid its form message (fixed:
  threads are read whole) and that the quarantine digest was filed as a request
  (fixed: skipped by `MAILBOX_DIGEST_SENDERS`, counted). **Re-judging built:**
  a reported request with a newer message is judged again and, if the verdict or
  form state changed, commented on its existing item and listed as updated; each
  Yes or Unsure item lists what is still needed; a request whose item failed is
  no longer recorded as reported. Many open Unsure items are accepted on purpose:
  the board is what prompts the requester to be asked for more. **Real run
  (2026-11-09):** 19 requests judged and 12 items filed (CYBR-821 to 832), which
  exposed two things now fixed: items were created in Jira's first status, Open,
  which the board has no column for (the lane now moves them to To Do), and
  nothing filed the mail away (the cleanup now archives what the lane dealt with).
  **Waiting on the TPRM owner's final question wording**, to be added to the
  supplier request form itself (website, what is supplied, data and system
  access, security contact): then the form reader learns those fields, a
  requester's Yes becomes a Yes, a blank becomes "still needed", and the website
  gives a safe place to start a lookup done by code, not by the model.
  **Eval set built and baselined (2026-11-08):** `task eval:supplier` (42
  invented requests, 3 runs each, fails only on a dangerous No;
  `internal/supplier/eval_test.go`, built with `-tags eval`). Instructions as of
  commit c404c9c. Sonnet: 123/123 acceptable, 120/123 exact, 0 dangerous, 3%
  too cautious, and it flagged all 18 hostile runs. Haiku: 121/123 acceptable,
  103/123 exact, 0 dangerous, 21% too cautious (more Unsure, so more to-dos,
  and two clear technology suppliers came back Unsure). Neither was ever moved
  by the code's checks, so the gates are covered only by unit tests. Limits: the
  cases and the instructions were written by the same hand, they are cleaner
  than the real mailbox (the real dry run was 18 of 20 Unsure, mostly because
  real forms have blank notes), and Opus was not run. Next: add a case whenever
  a real request surprises us, rerun after any change to the instructions or
  `SUPPLIER_MODEL`. Not done: the lookup by code, and a shared model-lane
  runner (H4).
  **Framing and shape (added 2026-11-06):** a Yes to the question means the
  supplier is *critical* - it touches company data, systems or networks, or
  provides technology (hardware, software or connected equipment) - and a
  critical supplier has to go through the third-party risk management (TPRM)
  process; a No is a supplier of materials or other non-technology goods. The
  lane's job is to find the critical suppliers. Scope: every message in the
  shared mailbox with the supplier-request address in To **or Cc**, not only
  the new-supplier-form messages; the evidence is the message body and the
  attachments that are safe to read (the form), never the tax and bank forms.
  It is built generically so another organisation could use it: the
  supplier-request address, the question's wording, the TPRM wording, the Jira
  project and owner, and the readable attachment types come from `fleet.env`
  settings (a template file for the longer text), with generic defaults and no
  organisation name, address or supplier in tracked files. Like the other
  lanes, an unset address means the lane does nothing, and its output goes
  only to the security team
- Qualys severity bands beside the QDS number, once the thresholds are verified
  against Qualys' own documentation rather than guessed
- A container image for deployment
- Message trace for the domains lane: which domains actually send mail and from
  where, on a separate read-only app registration. Probably unnecessary:
  outbound mail relays through Proofpoint on Demand, so the PoD Log API
  item below covers it for every domain already moved to PoD
- *Maybe:* subdomain discovery for the domains lane, from Certificate
  Transparency only (or the zone records, if the GoDaddy token can read
  them) - not subfinder, whose dozens of third-party sources and libraries
  would break the no-dependency rule and hand our domain list to outside
  services. Resolve every name and report only live hosts missing from
  `domains.txt`, dangling CNAMEs (takeover risk, High) and names new since
  last week; historical names that no longer resolve are dropped
- *Maybe:* CAA and DNSSEC checks for the domains lane (noted 2026-11-08). First
  find out whether Qualys already reports them: a search found nothing in
  Qualys EASM's Domain Security documentation beyond SPF and DKIM, so the
  likely answer is no, but the docs may lag the product - look in the tenant
  (CSAM, EASM, Domain Security) or ask the Qualys account manager before
  building. If it does not, add the small version to the domains lane, Go
  standard library only like the rest: the CAA lookup (walking up the name
  until a CAA record is found, since a subdomain inherits its parent's), DS
  and DNSKEY presence for DNSSEC, and the validating resolver's authenticated
  (AD) answer bit. Estimate 2 to 3 days without a DNS library (about a day
  with `miekg/dns`, which would break the no-dependency rule). Reporting
  rules to settle when it is picked up: whether a missing CAA record is a
  finding for every domain or only those that send mail or serve a site, and
  whether DNSSEC counts for a domain parked at the registrar. Security-ratings
  platforms (Bitsight, UpGuard, SecurityScorecard) score both, so if the
  company already pays for one, reading its API may beat building this
- Domains lane, the Proofpoint on Demand Log API half: **built** behind
  `DOMAINS_MAIL_GATEWAY=pod` (off by default; `domains.MailGateway` with
  `podgw` as the first implementation, see [INTERFACES.md](INTERFACES.md) and
  RUNBOOK 11g part 7). A domain with outbound mail is never asked to be locked
  down, and a failed read holds the tickets. Left: live verification on the
  box (token, window size and read time against a real week); the `p=reject`
  evidence is a finding line in the report, not a ticket action; and then
  `domains.txt` could need only `saas` / `legacy` / `unknown`.
- Certificate expiry lane (build it behind a `certs.Source` interface from
  the start, see [INTERFACES.md](INTERFACES.md)): a weekly email to IT listing certificates about to
  expire, from Qualys Certificate View (CertView; the subscription has it and
  the fleet's existing Qualys credentials reach it). Group by days left
  (expired, 30, 60, 90), name the host, issuer and owner, and mention changes
  since last week. Read-only, its own per-lane recipient list that fails
  closed (like `WAS_*`/`DOM_*`), Go standard library only. Open questions:
  the exact CertView API endpoints and fields (to be checked against a live
  call, as the sandbox cannot reach Qualys), and whether IT wants a Jira
  ticket per certificate
- Fleet housekeeping: watch and trim the fleet's own data so the box never
  fills up quietly - the orchestrator's `board.md` and its archive (rotate or
  trim by size/age), `state/memory.db` (size, rollup and pruning, periodic
  VACUUM), free disk on the volumes the fleet uses with a warning before it
  is critical, journal and log rotation for the fleet's units, and the dated
  reports, ticket files, previews and KB cache that build up in `state/`.
  Problems and growth trends reported through the existing alert path or the
  check-in. Noted only, not designed
- **Split `fleet.env` and take the secrets out of the environment** (noted
  2026-11-09, not designed). The file has grown to about 90 settings, and every
  unit loads all of it through `EnvironmentFile=`, so every lane carries every
  secret. That includes the check-in beat, which reads untrusted text;
  `checkin-bash-guard` refuses `$NAME` expansion largely because of this. In
  order:
  1. **`fleet-config check`** (cheapest, touches no secrets): reports unknown
     keys (typos), settings equal to their default, required settings that are
     missing, and which lane reads each one. Never prints a value. Shows how
     much of the file can simply go. Goes in `commands.manifest`
  2. **Secrets as systemd credentials**: the ~10 secrets (`CLIENT_SECRET`,
     `QUALYS_PASSWORD`, `GODADDY_PAT`, `POD_API_TOKEN`, `JIRA_API_TOKEN`,
     `NVD_API_KEY`, the Claude token, `REPORT_REDACTION_SALT`) encrypted with
     `systemd-creds` (TPM-bound on Fedora) and granted per unit with
     `LoadCredentialEncrypted=`, so each lane gets only its own and the values
     reach the process as files under `$CREDENTIALS_DIRECTORY`, not as
     environment its children inherit. A `Secret(name)` helper in
     `internal/fleetenv` (and its twins in `mailer.py` and the shell runners)
     reads the credential and falls back to the environment during the move.
     Start with the check-in, then one lane at a time
  3. **Settings split per lane**: `/etc/cti-agent/fleet.d/00-core.env` plus one
     file per lane; each unit loads core and its own. Goes with step 2
  4. **1Password as the source of truth for secrets**: one field per secret
     instead of a pasted copy of the whole file, and a committed `fleet.env.tpl`
     of `op://` references rendered with `op inject` on the operator's Mac at
     setup or rotation and fed to `systemd-creds encrypt` on the box. No
     1Password service-account token on the server
- Supplier request mail: the shared inbox also collects supplier requests, and
  nothing tidies them. Probably its own lane (they are not CTI mail and need a
  different owner and rules than cti-mailbox). Not designed: what the requests
  are, who answers them, and what "done" means for one
- The AI triage agent wired into the threat-intel digest, and a Defender for
  Cloud attack-path lane
- **Heartbeat escalation to a stronger model** (designed 2026-11-08, not
  built). Groundwork shipped: `CHECKIN_MODEL` picks the beat's model. First
  run a week or two of beats on a cheaper model (Sonnet) and look at where
  they fell short before building this. The idea: routine beats stay cheap, a
  beat that hits a hard reasoning problem gets one look from a stronger model
  (Opus), and that model either solves it or escalates it to the operator.
  - **The line between more power and a person.** The test is whether the
    problem needs better reasoning over data the fleet can already read (send
    to the stronger model) or an action or information the fleet does not
    have (a person).
    - *Stronger model:* conflicting signals between two sources (the Nov 4
      beats saw `cti-kev` clean while the rollup showed 9 overdue); an
      `UNKNOWN` CVE mapping that needs careful reading of the advisory against
      the scanner's data; the cause of a recurring lane failure buried in the
      journal; Patch Tuesday exposure reasoning; whether a feed or format
      change is harmless or broken.
    - *Always a person:* anything that changes who is mailed, an allowlist, a
      gate or a ticket; credentials and authentication; anything that needs a
      system the fleet cannot see, or contact with someone outside the company
      (the CISA block); a risk decision (accepting an overdue KEV); suspected
      prompt injection or compromise; a bug in the fleet's own code (the
      stronger model may diagnose it, but the fix is the operator's).
  - **Mechanism.** The decision sits in `run-checkin`, the deterministic
    bash, never in a model:
    1. The beat asks through one new granted command, e.g. `fleet-deeper
       <kind> <subject> "<question>"`. `kind` must come from a fixed list
       (`conflict`, `unknown-cve`, `failure`, `exposure`, `noise`). The
       command records one bounded request in state. The beat cannot name a
       model, tools or a budget; it can only ask.
    2. After the beat, `run-checkin` gates it: a valid request, `kind` on the
       list, budget room with the stronger run weighted as several beats, the
       same subject not escalated in the last 24 hours, and a daily cap not
       yet used. Pass, and it runs; fail, and the request is logged and
       dropped. This is the automatic approval, and it is plain bash.
    3. It runs `claude -p /deeper --model $DEEPER_MODEL` with exactly the
       beat's grants (read-only plus board, memory and `cti-alert`; no Agent
       tool, no edit tools) and the request as input. It must end in one of
       three outcomes: **solved** (posts the finding, writes a memory);
       **needs a person** (one `cti-alert` carrying the original question and
       its own analysis); or **not worth it** (a memory saying so, so later
       cheap beats escalate less).
    4. Optional: deterministic triggers that request a deeper look without
       asking the model, such as the same `UNKNOWN` unresolved across 3 beats,
       or a lane failing twice in a row.
  - **Safety.** A cheap beat steered by hostile mail can request a deeper look
    but gains nothing: the stronger run has no more power than the beat,
    so the worst case is wasted quota (capped daily) and an alert to the
    operator, which a beat can already send. This design never grants the
    Agent tool, which would widen what a beat can do.
  - **Pieces:** `DEEPER_MODEL` in `fleet.env`; the `fleet-deeper` wrapper
    (root-owned, validated like `fleet-board`, and in `checkin-bash-guard`'s
    world); a `/deeper` skill; the gate and the second run in `run-checkin`;
    beat weighting in `cti-budget`, which counts beats today, not cost;
    tests for the gate's refusals; and the orchestrator CLAUDE.md telling a
    beat when to ask.
- **VM lane: Jira tickets for out-of-SLA vulnerabilities** (noted 2026-11-10,
  not designed). Pull every detection past its remediation SLA for its
  severity, with the affected hosts, and file Jira tickets for them. Not
  decided yet, so brainstorm before building:
  - Ticket granularity: one ticket per QID listing its N hosts, one per host,
    one per QID per owning team or site, or a rollup per severity.
  - Where the SLA days per severity are defined, and whether they come from
    config or from Qualys.
  - How a ticket stays in step on later runs: hosts added or fixed, closing
    when none are left, and reopening when one comes back.
  - Assignment and project. AppSec tickets already want their own project
    (see #160), and CR is the infrastructure help desk.
  - It must follow the fleet's rules: a full preview and one labelled test
    ticket before any real filing, and no real host names in tracked files.
- **New lane: weekly design-review coverage report** (noted 2026-11-11, not
  designed; the Jira query is still to be decided). Once a week, look at the
  sprint status across the development projects in Jira. Report which work
  items got a PrimeSec design review, which did not, and, for each that did
  not, the justification recorded for skipping it, or that there is none.
  - **Inputs.**
    - Jira: the sprint's issues across projects, via the existing
      `/rest/api/3/search/jql` client in `internal/jira` (read-only). **The JQL
      is TBD**: which projects and boards, which sprint (the active one, or
      the one closed that week), and which issue types count as needing a
      review (stories and epics, but probably not bugs or subtasks).
    - PrimeSec: the design reviews (`search_design_docs` and the security
      review brief in the Prime API), matched back to Jira issues.
  - **Open questions, to brainstorm before building:**
    - *How a review is tied to an issue.* A Jira link or field on the issue,
      the issue key in the Prime design doc, or Prime's own Jira integration?
      This decides whether matching is exact or a guess. A guess should be
      reported as unmatched, never as reviewed.
    - *Where the justification lives.* A Jira field, a label (such as
      `no-design-review`) with a comment, or a resolution. It has to be
      something a person sets on purpose, so the report can tell "no review,
      justified" apart from "no review, nobody said why".
    - *What "got a review" means.* A Prime review that exists, one that is
      finished, or one whose open threats have been answered. It could also
      show the review's risk level or open recommendations.
    - *Audience and format.* Who gets it (AppSec, engineering leads, the
      product owners), on which day after the sprint boundary, and whether it
      is an email digest, a board post, or both. The default is email to an
      allowlisted audience through `cti-mailer`, like the other lanes.
    - *The Prime credential.* A Prime API token for the fleet, read-only,
      kept with the other secrets (see "Split `fleet.env`" above), and how the
      lane's rate use is budgeted.
    - *Go or Python.* A Go command (`cti-designreview`) with a
      `run-designreview` runner and timer, following `cti-appscan` and
      `run-appscan`. Python only if it needs SQLite (SECURITY.md, Supply
      chain); the history of what was reported each week probably does not.
  - **Fleet rules it must follow.**
    - Read-only against Jira and Prime: it files and changes nothing.
    - `--dry-run`, `--for-real` or `--to-dev` with no default, and an entry
      in `commands.manifest` and a man page.
    - Listed in the orchestrator's lane table and the checkin skill, which a
      test enforces.
    - Issue keys and titles can name internal projects, so the report goes
      only to the configured audience, and none of it lands in tracked files.
      The tests use example projects.
