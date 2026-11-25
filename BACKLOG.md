# Backlog

Ideas not yet built. Nothing here is a commitment: ask before picking one up,
and expect each to be designed first. Interface work follows the rule in
[INTERFACES.md](INTERFACES.md): build an interface when a second implementation
is real, not before. Finished work moves out of this file into
[CHANGELOG.md](CHANGELOG.md).

## Before 2.0 final

The reuse work for 2.0 is built. What is left is checking it.

- **A clean-box install.** Follow [INSTALL.md](INSTALL.md) on a scratch Fedora
  VM until `cti-agent-doctor` shows no FAIL. It has only been run as an
  upgrade of an existing box. Fix whatever the guide gets wrong.
- **A fork's install.** On the same VM, install a throwaway fork with an
  `org/` pack, a `layout.env` and a `FLEET_LANES` subset. The doctor should
  check the fork's pack, the paths should be relocated, and the lanes left
  out should stay off.
- **A new check-in eval baseline** (`task eval:checkin`). The one in
  HARNESS.md (2026-11-18) is from before the beat stopped running the
  credential checks, so its turns and cost no longer compare.
- **The GitHub tag ruleset** on the repository, by its owner (the command is
  in [development.md §11i](docs/guides/development.md#a-pushed-tag-never-moves)),
  and a leak check of the whole tree for organization names.

## Hardening

- **Redaction of encoded sessions in the scanner's report** (from the review
  of the report staging change, 2026-11-25). Still passed through: a folded
  header continuation inside `<pre>`, a base64-encoded `Cookie` outside the
  verbose XML's own tags (in a `<pre>` or `<td>`), and a percent-encoded
  `Cookie%3A%20...` in plain text. What it covers today is in
  `internal/appscan/redact.go`. Also: a `TMPDIR` set in `fleet.env` moves the
  runners' staging out of PrivateTmp, so the runners could ignore one from
  there.

## Interfaces

The reasoning and the current gaps are in [INTERFACES.md](INTERFACES.md).
Build each when a second implementation is real.

- More scanner providers (Defender, Tenable, Rapid7) behind
  `vulnlookup.LookupProvider`.
- Finish `vulnlookup.LookupProvider`: `cti-patchtuesday` builds the Qualys
  client directly and ignores `LOOKUP_PROVIDER`. It needs the KB's
  CVE-to-QID map and host counts, which the interface cannot express yet. With
  it, a detection-mapping interface (`vulnlookup.DetectionMapper`, CVE to
  scanner detection IDs) for the Patch Tuesday correlation.
- A second registrar: `DOMAINS_REGISTRAR` knows `godaddy` and `none`.
- **Mail transport** (read, send, move), so a fleet on Google Workspace or
  SMTP/IMAP can run it. Microsoft Graph is used directly by five commands; the
  recipient allowlist stays above the interface in `cti-mailer`. The largest,
  and the most valuable for reuse.
- **A ticket tracker** (`tickets.Tracker`) so ServiceNow, Azure DevOps or
  GitHub Issues can replace Jira. Needs an answer for the state kept as a Jira
  issue property, and for the Jira wiki markup.
- **A notification channel** (`alert.Notifier`) for `cti-alert`: Teams,
  Slack, a pager. The smallest, a good first one.
- **An ownership source** (`appscan.OwnerSource`) so a CMDB or identity group
  can replace the owners list.
- **A network source** (`netmap.NetworkSource`, `Subnets(ctx)`) so the VM scan
  coverage check can read an IPAM (NetBox, phpIPAM, Infoblox) or a CSV/JSON
  export, not only the spreadsheet. `netmap.Check` is already source-neutral;
  `coverage()` in `cmd/cti-vmscan` picks the sheet directly, and the parser,
  the corp-row guess and `netrules.txt` assume its shape. Needs a
  source-neutral reference on a finding (today a row number) and a configured
  role in place of the corp-row guess, selected by a `SUBNET_SOURCE` setting.
  About a day: move the xlsx path behind the interface with no change in
  behaviour (the tests prove it), then add a CSV source. Write an IPAM adapter
  only against a real one.
- An advisory/exploit feed interface for new feeds (EPSS, vendor lists).

## The agent harness

The order and reasoning are in [HARNESS.md](HARNESS.md).

- **H2, evals.** Built, with a Sonnet baseline. Left: a Haiku comparison
  before any move to a cheaper model, and a scenario for each PrimeSec vector
  that touched the orchestrator.
- **H3, use the saved verdicts.** A lane-health line in the digest, and a
  trend of attention and degraded beats.
- **H4.** Decide whether the supplier lane's model calls count against
  `cti-budget`, like the heartbeat's.
- **H5 (optional).** Reproduce one beat with the Claude Agent SDK outside
  production, as a learning exercise, not a migration.
- **Heartbeat escalation to a stronger model.** Designed 2026-11-08 and not
  built, on purpose. The idea: a beat asks through one granted command
  (`fleet-deeper <kind> <subject> "<question>"`, `kind` from a fixed list);
  `run-checkin` gates the request in bash (budget, one per subject per day, a
  daily cap) and runs one stronger beat with exactly the beat's grants, which
  ends solved, needing a person, or not worth it. A beat steered by hostile
  mail gains nothing but wasted quota. A week of Sonnet beats (2026-11-08 to
  11-15: 82 beats, $13.35, all `ok`) found one case that would have used it,
  and it turned out to be a definition problem, fixed without a stronger
  model. Rerun that review on another week of traces; build it only if real
  cases keep appearing.

## Lanes

- **Supplier requests: the TPRM wording.** Waiting on the final question
  wording for the supplier request form (website, what is supplied, data and
  system access, security contact). Then the form reader learns those fields,
  a requester's Yes becomes a Yes, a blank becomes "still needed", and the
  website gives a safe starting point for a lookup done by code, not by the
  model. Add an eval case whenever a real request surprises us.
- **`cti-kev` over every stored finding, not one day's mail.** It reads the
  newest daily enriched file, so a present KEV CVE drops out the first day no
  email names it. Likely shape: `run-digest daily` writes a JSON snapshot of
  the stored PRESENT KEV findings (`fleet-db rollup`, a wider window), and
  `cti-kev` reads that. Decide the window (a stored row is re-confirmed only
  when mail names it again) and whether the daily's KEV banner moves to it.
- **VM lane: Jira tickets for out-of-SLA vulnerabilities.** Every detection
  past its remediation SLA, with its hosts. To brainstorm first: one ticket
  per QID, per host, per team or site, or a rollup per severity; where the SLA
  days come from; how a ticket follows later runs (hosts added or fixed,
  closed when none are left, reopened when one comes back); its project and
  assignee. A full preview and one labelled test ticket before any real
  filing, and no real host names in tracked files.
- **A certificate expiry lane**, behind a `certs.Source` interface from the
  start: a weekly email to IT of certificates about to expire, from Qualys
  Certificate View (the existing Qualys credentials reach it), grouped by days
  left, with host, issuer and owner, and changes since last week. Read-only,
  with its own recipient list that fails closed. Open: the CertView endpoints
  and fields (check against a live call), and whether IT wants a ticket per
  certificate.
- **A weekly design-review coverage report.** For the sprint's work items
  across the development projects in Jira, which got a PrimeSec design review,
  which did not, and the recorded reason for each that did not. Read-only
  against Jira and Prime. To decide first: the JQL (projects, which sprint,
  which issue types), how a review is tied to an issue (exactly, never by a
  guess), where the justification lives (something a person sets on
  purpose), what counts as reviewed, the audience, and a read-only Prime token
  stored with the other secrets. Issue keys and titles can name internal
  projects, so the report goes only to its configured audience.
- **A compromise-assessment cross-check (research).** A consulting firm sends
  a draft assessment before a recurring review meeting. The useful lane is a
  pre-meeting brief that checks the report's claims against what the fleet
  already knows: scan coverage and open exploited CVEs, domain and
  mail-authentication posture, web-application findings and patch status.
  Research first how it arrives (an encrypted PDF with the password in a
  second email, so a person or a local tool reads it, never the mailbox
  lane), whether its tables can be read reliably, and which questions come up
  every time. Never put the report in a tracked file; the brief names no hosts
  or users.
- **A Defender for Cloud attack-path lane.**
- **Domains: what the mail gateway can't see.** A null MX on a domain whose MX
  is not on Proofpoint (Microsoft 365, GoDaddy, others) is still not checked,
  since its mail never passes the gateway: a Graph or Exchange message trace,
  or moving those domains' MX to PoD first, would close it. The `p=reject`
  evidence is a finding line, not a ticket action. Then `domains.txt` could
  need only `saas`, `legacy` and `unknown`.
- *Maybe:* **subdomain discovery** for the domains lane, from Certificate
  Transparency only (or the zone records, if the registrar token can read
  them). Report live hosts missing from `domains.txt`, dangling CNAMEs
  (takeover risk) and names new since last week. Not subfinder: its third-party
  sources and libraries would break the no-dependency rule and hand the domain
  list to outside services.
- *Maybe:* **CAA and DNSSEC checks** for the domains lane. First find out
  whether Qualys already reports them (look in the tenant, or ask the account
  manager). If not: the CAA lookup walking up the name, DS and DNSKEY presence,
  and the validating resolver's AD bit, in the standard library (2 to 3 days).
  Settle first whether a missing CAA record is a finding for every domain, and
  whether DNSSEC counts for a parked one. A security-ratings platform's API
  may beat building it, if one is already paid for.
- Qualys severity bands beside the QDS number, once the thresholds are checked
  against Qualys' own documentation rather than guessed.

## The platform

- **Narrow each unit's secrets from "could read" to "does read."** The grants
  are generated from which programs a unit could run, so most lanes get more
  than they use (the check-in was narrowed by hand in 2.0). Do it one lane at
  a time, testing each with only its grants. The same per-function reads
  would shrink `00-core.env`, which holds anything a shared program names.
- **1Password as the source of truth for secrets**: one field per secret, a
  committed `fleet.env.tpl` of `op://` references rendered with `op inject` on
  the operator's Mac at setup or rotation, then stored on the box with
  `cti-agent-secrets set`. No 1Password token on the server.
- **Fleet housekeeping**: watch and trim the fleet's own data so the box never
  fills up quietly. That covers the board and its archive, `memory.db` (size,
  pruning, VACUUM), free disk with a warning before it is critical, journal
  and log rotation, and the dated reports, previews and KB cache in `state/`,
  reported through the alert path or the check-in. Not designed.
- **A container image** for deployment, after 2.0: the install layout is now
  set by `layout.env`, which is most of what an image needs.
