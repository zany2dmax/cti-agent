# Backlog

Ideas not yet built. Nothing here is a commitment: ask before picking one up,
and expect each to be designed first. Interface work follows the rule in
[INTERFACES.md](INTERFACES.md): build an interface when a second implementation
is real, not before. Finished work moves out of this file into
[CHANGELOG.md](CHANGELOG.md).

- More scanner providers — Defender, Tenable, Rapid7 — behind the same interface
- **Interface work** (the full reasoning, with the current gaps, is in
  [INTERFACES.md](INTERFACES.md); build each when a second implementation is
  real, not before):
  - Finish `vulnlookup.LookupProvider`: `cti-jira` (`scannerFor`) and
    `cti-patchtuesday` build the Qualys client directly and ignore
    `LOOKUP_PROVIDER`. Small for `cti-jira` (share `buildLookupProvider`)
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
  - An advisory/exploit feed interface for new feeds (EPSS, vendor lists);
    whether the Python CISA KEV fetch moves under it is a separate decision
  - A detection-mapping interface (`vulnlookup.DetectionMapper`, CVE to
    scanner detection IDs) for the Patch Tuesday correlation, which is
    Qualys-only today
- AppSec tickets in their own Jira project: CR is the infrastructure help desk,
  and the AppSec teams track their work in other projects, so the AppSec lane
  should file there (project TBD) instead of CR. Points to settle when it is
  designed: a separate project key for the lane (CVE and domains tickets stay in
  CR), its own issue type and `JIRA_ALLOW_CREATE` / `JIRA_ALLOW_CLOSE` entries,
  the service account's permissions in the new project (`--check` per project),
  the searches that assume one project (open ticket, prior-ticket link, retired
  app close), and moving the six existing AppSec tickets
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
  reply to the requester and never move their mail. Sampled 2026-11-02: only
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
  permissions in CYBR. Still open: whether a digest line also lists the day's
  requests, and Unsure-means-Yes wording on the item
- `cti-jira --list`: a read-only list of the fleet's open tickets (key, status,
  age, assignee, kind - CVE, AppSec, lock-down, test - and summary), with `--all`
  to include closed ones and `--json`. No write gate needed; it would also give
  `--appscan-close-test` a way to find the test ticket's key
- Qualys severity bands beside the QDS number, once the thresholds are verified
  against Qualys' own documentation rather than guessed
- A container image for deployment
- AppSec lane fully provider-neutral: `cmd/cti-appscan` fetching detail through
  `appscan.DetailFetcher` (and scan-list reconciliation as an optional provider
  capability) instead of calling the Qualys API type directly
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
- Weekly Qualys scan summary: check the two weekly scans Qualys runs on
  Thursday and summarize both in one email on Friday. Noted only, not
  designed; which two scans (and which audience) to be settled when it is
  picked up
- Fleet housekeeping: watch and trim the fleet's own data so the box never
  fills up quietly - the orchestrator's `board.md` and its archive (rotate or
  trim by size/age), `state/memory.db` (size, rollup and pruning, periodic
  VACUUM), free disk on the volumes the fleet uses with a warning before it
  is critical, journal and log rotation for the fleet's units, and the dated
  reports, ticket files, previews and KB cache that build up in `state/`.
  Problems and growth trends reported through the existing alert path or the
  check-in. Noted only, not designed
- Supplier request mail: the shared inbox also collects supplier requests, and
  nothing tidies them. Probably its own lane (they are not CTI mail and need a
  different owner and rules than cti-mailbox). Not designed: what the requests
  are, who answers them, and what "done" means for one
- The AI triage agent wired into the threat-intel digest, and a Defender for
  Cloud attack-path lane
