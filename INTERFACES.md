# Interfaces: where the fleet is vendor-neutral, and where it is not yet

The fleet is built so that the tool behind a lane can be changed without
rewriting the lane. This page lists every Go interface that does that, says
how complete each one is, and lists the places that are still tied to one
vendor, so a developer can see what exists and what is worth building.

Read [ARCHITECTURE.md](ARCHITECTURE.md) first for what the lanes do. This page
is about the seams between a lane and the product it talks to.

**Be honest about the state of it.** Most of these interfaces are used end to
end. Two groups, `LookupProvider` and the AppSec detail interfaces, are
declared but only partly used: some commands still call the Qualys client
directly. [The gaps](#2-where-the-abstraction-is-incomplete-today) say exactly
where.

---

## 0. Contents

1. [The interfaces that exist](#1-the-interfaces-that-exist)
2. [Where the abstraction is incomplete today](#2-where-the-abstraction-is-incomplete-today)
3. [Where new interfaces could go](#3-where-new-interfaces-could-go)
4. [What we deliberately do not abstract](#4-what-we-deliberately-do-not-abstract)
5. [How to put a new tool behind an interface](#5-how-to-put-a-new-tool-behind-an-interface)
6. [The conventions every interface here follows](#6-the-conventions-every-interface-here-follows)

---

## 1. The interfaces that exist

| Interface | Package | Abstracts | Implementations | Chosen by | How complete |
|---|---|---|---|---|---|
| `LookupProvider` | `internal/vulnlookup` | "Is this CVE present in our estate?" (VM / EDR) | Qualys, CrowdStrike (**placeholder**), no-op | `LOOKUP_PROVIDER` in `cmd/cti-agent` | **Partial**: the digest uses it; ticketing and Patch Tuesday do not ([2.1](#21-vulnlookuplookupprovider-is-bypassed-by-two-commands)) |
| `Provider` | `internal/appscan` | Recognising and parsing a DAST scan-completion email | Qualys WAS | the `providers` slice in `cmd/cti-appscan` | **Full** for the email path |
| `DetailFetcher`, `RemedyFetcher` | `internal/appscan` | Per-finding detail and the fix text, from a scanner API | Qualys WAS | type assertion in `cmd/cti-appscan` | **Partial**: only `RemedyFetcher` is used as an interface ([2.2](#22-the-appsec-lane-calls-the-qualys-api-type-directly)) |
| `ReportFetcher`, `RateReporter` | `internal/appscan` | The scanner's own per-application report; API budget status | Qualys WAS | `APPSCAN_REPORT_PROVIDER` in `cmd/cti-appreport` | **Full** |
| `Registrar` | `internal/domains` | "Which domains does this account hold?" | GoDaddy | `registrarFor` in `cmd/cti-domains` (fixed to GoDaddy, no setting) | **Full** in use; **no switch** yet |
| `Resolver` | `internal/domains` | DNS lookups | `net.DefaultResolver`, test maps | `cmd/cti-domains` | Full, but a **test seam**, not a product seam |

Function-typed seams, which do the same job in a lighter way and exist mainly
so tests can replace the network: `domains.WebProber`, `domains.SMTPProber`,
`cti-jira`'s `hostFiller` and `scannerFor`, and `cti-domains`'s `registrarFor`.

### 1.1 `vulnlookup.LookupProvider`: query-shaped

```go
type LookupProvider interface {
    Name() string
    LookupCVE(ctx context.Context, cve string) (Result, error)
}
```

You hand it a CVE and ask whether the estate has it. It returns a normalised
`Result` with a status of `PRESENT`, `NOT_PRESENT` or `UNKNOWN`, the affected
hosts, and a reason.

- **`UNKNOWN` is not `NOT_PRESENT`.** A provider that could not check says
  `UNKNOWN` with a reason. Reporting "not present" for a failed lookup is the
  failure this codebase is built to avoid. The no-op provider and the
  CrowdStrike placeholder both return `UNKNOWN`.
- **Hosts may be shorter than `HostCount`.** Providers that truncate set
  `HostCountIsFloor`; callers take the count from `HostCount` and the names
  from `Hosts`.
- **Where to look:** selection is `buildLookupProvider` in
  `cmd/cti-agent/main.go`. Qualys is `internal/vulnlookup/qualys`. The
  CrowdStrike package is a stub that returns an error: it shows where an
  implementation goes, nothing more.

### 1.2 `appscan.Provider`: push-shaped

```go
type Provider interface {
    Name() string
    Recognises(sender, subject string) bool
    Parse(body string) (ScanResult, []string)
}
```

DAST products mail a completion summary; they do not wait to be asked. So this
interface recognises a vendor's email and parses it, and needs **no
credentials**. A new scanner is useful the day its email arrives, before
anybody negotiates API access.

- `cmd/cti-appscan` keeps `var providers = []appscan.Provider{...}` and asks
  each in turn whether a message is theirs. Adding Invicti or Wiz is one entry
  plus a parser.
- A provider that can click through to a portal registers its hosts with
  `appscan.AllowPortalHosts(name, hosts...)`. Without that, report links stay
  plain text. That is the safe failure.
- Scanner severity (1 to 5) is **not** the fleet's Sev1 to Sev5. Do not map
  one onto the other. A scanner's "Severity 5" describes one HTTP response; a
  fleet Sev1 means confirmed present *and* known exploited.

### 1.3 `appscan.DetailFetcher`, `RemedyFetcher`, `ReportFetcher`

Optional capabilities, each its own small interface, so a provider implements
only what its API offers. A lane that cannot fetch a capability degrades
instead of failing.

| Interface | Gives | Used as an interface today? |
|---|---|---|
| `DetailFetcher` | Findings for an application, since a date | No: `cmd/cti-appscan` holds the concrete `*qualys.API` |
| `RemedyFetcher` | Fix text for finding IDs (Qualys KnowledgeBase) | **Yes**: `attachRemedies` takes the interface |
| `ReportFetcher` | The scanner's own zipped report for one application; deletes what it created | **Yes**: `cmd/cti-appreport` only ever sees the interface |
| `RateReporter` | A one-line API-budget status for the log | **Yes** |

`ReportFetcher` is the model to copy. `cmd/cti-appreport` has one function,
`reportProvider`, that picks an implementation from `APPSCAN_REPORT_PROVIDER`,
and nothing else in the command, in `cti-jira` or in the runner names a
vendor. The reports reach Jira through `reports.json` and a zip file, which
are vendor-neutral by construction.

`cti-appreport` also has three private interfaces (`checker`, `prober`,
`requestDumper`) for `--check`, `--probe-findings` and `--dump-request`. A
provider that does not implement them still attaches reports; the command says
the flag is not available for it.

### 1.4 `domains.Registrar`

```go
type Registrar interface {
    Name() string
    Domains(ctx context.Context) ([]Registration, error)
}
```

Lists the domains an account holds, so the weekly check can compare the
registrar's list against `domains.txt` in both directions. Moving registrar,
or holding domains at two, is an implementation.

- `cmd/cti-domains` builds it through `var registrarFor = func(token string)
  domains.Registrar`. It is hard-wired to GoDaddy and has **no environment
  switch** yet. To add one, mirror `buildLookupProvider`.
- The GoDaddy token is read-only (`domains.domain:read`). A new registrar
  implementation must be read-only too. The lane never needs an auth code or a
  write scope.

### 1.5 `domains.Resolver`

A five-method slice of `*net.Resolver`. `net.DefaultResolver` satisfies it;
tests supply a map. It is here so the DNS checks can be tested without a
network. It is also where you would point the lane at a specific resolver, but
it is not meant for swapping a vendor.

---

## 2. Where the abstraction is incomplete today

These are accurate as of this writing and are the first things to fix before
claiming a second provider "just plugs in".

### 2.1 `vulnlookup.LookupProvider` is bypassed by two commands

| Command | What it does | Why it matters |
|---|---|---|
| `cmd/cti-agent` (the daily digest) | Uses `buildLookupProvider` and the interface | Correct |
| `cmd/cti-jira` | `scannerFor` builds `qualys.New(...)` and calls `LoadOrBuildKBCache` directly | Ticketing and the follow-up ignore `LOOKUP_PROVIDER`. A deployment on another provider would still be asked for Qualys credentials |
| `cmd/cti-patchtuesday` | Builds `qualys.New(...)` and uses the KnowledgeBase's CVE to QID map | The correlation is a Qualys feature (see [3.4](#34-cve-to-detection-mapping-for-patch-tuesday)) |

`cti-jira` is the easy one. It already works through a function type
(`hostFiller`) that matches `LookupCVE`, so the fix is to share
`buildLookupProvider` instead of constructing Qualys by hand.

### 2.2 The AppSec lane calls the Qualys API type directly

`cmd/cti-appscan`'s `wasAPI` returns `*qualys.API`, and the lane also calls
`Scans`, `WebApps`, `OpenFindings` and `Reconcile`. None of those is on any
interface. The email-parsing half is vendor-neutral; the API half is Qualys.
This is already on the README backlog.

### 2.3 Domains has two single-vendor pieces with no interface

- `internal/domains/proofpoint.go` recognises Proofpoint on Demand by MX and
  SPF host names. It is logic, not an interface.
- The registrar has no selection setting (see [1.4](#14-domainsregistrar)).

### 2.4 Microsoft 365 Graph and Jira are used as concrete types

See [3.1](#31-mail-transport-microsoft-graph) and
[3.2](#32-ticketing-jira). They are the two biggest vendor dependencies in the
fleet, and neither has an interface.

---

## 3. Where new interfaces could go

Ranked by value for someone adopting this repo on a different stack. Effort is
relative. **Do not build these speculatively**: see the rule in
[section 5](#5-how-to-put-a-new-tool-behind-an-interface).

| # | Seam | Today | Proposed interface | Value | Effort |
|---|---|---|---|---|---|
| 3.1 | Mail transport | Microsoft Graph, five commands | `mail.Reader`, `mail.Sender`, `mail.Mover` | Highest | High |
| 3.2 | Ticketing | Jira, one command | `tickets.Tracker` | High | Medium-high |
| 3.3 | AppSec scanner API | Qualys API type | finish the `appscan` capability interfaces | High | Medium |
| 3.4 | CVE to detection mapping | Qualys KnowledgeBase | `vulnlookup.DetectionMapper` | Medium | Medium |
| 3.5 | Notification channel | board plus Graph mail | `alert.Notifier` | Medium | Low |
| 3.6 | Ownership source | `app-owners.txt` | `appscan.OwnerSource` | Medium | Low |
| 3.7 | Advisory and exploit feeds | CISA KEV in Python; Patch Tuesday sources in Go | `AdvisorySource` | Medium | Medium |
| 3.8 | Mail-gateway evidence | Proofpoint on Demand, hard-coded | `domains.MailGateway` | Low until the PoD item ships | Medium |
| 3.9 | Exposure / attack-path source | Defender for Cloud emails | `exposure.Provider` | Low until built | Medium |
| 3.10 | Certificate inventory | not built | `certs.Source` | Decide at build time | Low |

### 3.1 Mail transport (Microsoft Graph)

Five commands construct a `graph.Client` directly: `cti-agent` and `cti-appscan`
read the mailbox, `cti-mailer` and `cti-alert` send, and `cti-mailbox` moves
messages. The Python `mailer.py` is a second, separate sender.

A fleet on Google Workspace, or on plain SMTP and IMAP, cannot use any of it.
Three small interfaces would split it cleanly: read recent messages (the
digest and AppSec lanes), send with attachments, and move to a folder
(cleanup).

**Security constraint.** The recipient allowlist (`FLEET_ALLOW_TO`, `WAS_*`,
`DOM_*`) lives in `cti-mailer` and **must stay above the interface**. A
transport must never decide who may be mailed. It sends what the gate already
approved. Likewise "nothing purges mail" is a property of the mover's
contract: it moves to Archive or Deleted Items and has no delete.

### 3.2 Ticketing (Jira)

`internal/jira.Client` is used only by `cmd/cti-jira`, which makes it a good
candidate: one consumer to change. The surface the lanes use is small:
create, search, comment, attach, link, watch, look up an assignee by email,
and read or write a per-issue property.

Two things make this harder than it looks, and a design must answer both:

- **State is kept on the ticket.** The AppSec lane stores what a ticket was
  last told as a Jira issue property, and finds the ticket by a label. Another
  tracker needs an equivalent (a custom field, a hidden comment or a
  sidecar store).
- **Ticket text is Jira wiki markup**, produced by `wikiText` and
  `wikiEscape`. A tracker interface needs the renderer on the implementation
  side, not in the lane.

The write gate (`--for-real`, `JIRA_ALLOW_CREATE`) is in `cti-jira` and must
stay there, above the interface.

### 3.3 AppSec scanner API: finish the job

Add the missing capability interfaces so `cmd/cti-appscan` never names
`*qualys.API`: a scan lister, a web-app lister and an open-findings fetcher,
each optional, plus `Reconcile` as an optional capability. This is the README's
"AppSec lane fully provider-neutral" item. It is the cheapest way to make
Invicti or Wiz a real second provider rather than a parser alone.

### 3.4 CVE to detection mapping for Patch Tuesday

Patch Tuesday asks "which scanner signatures detect this month's CVEs, and how
many of our hosts have them". That is a Qualys QID lookup through the
KnowledgeBase cache, and `LookupProvider` cannot express it, because it takes
a CVE and returns a verdict, not a list of detection IDs. A `DetectionMapper`
(`CVE -> []detection ID`, plus hosts per detection) would let another scanner
do the same correlation. Lower priority than 3.1 to 3.3: the correlation is
itself a Qualys feature, and a second scanner may not have an equivalent.

### 3.5 Notification channel

`cti-alert` writes to the message board and sends one email. A `Notifier`
(Teams, Slack, a pager) would be a small, low-risk first interface to add. Any
outbound channel needs the same discipline as mail: an allowlist, no default
destination, and a fail-closed default.

### 3.6 Ownership source

`app-owners.txt` maps applications to owners, components and watchers.
An `OwnerSource` would let a CMDB or an identity group be that source instead
of a file. The file stays the default and the fallback.

### 3.7 Advisory and exploit feeds

CISA KEV is fetched in the Python `enrich.py` lane (`KEV_FEED`), the Go
`internal/kev` package only handles deadlines, and Patch Tuesday reads the
Qualys blog, BleepingComputer and MSRC through `patchtuesday.Source`, which is
a data struct and not an interface. New features are Go, so any new feed
(EPSS, a vendor advisory list) should be built behind an `AdvisorySource`
from the start. Whether to move the Python KEV fetch under it is a separate
decision.

### 3.8 Mail-gateway evidence

The domains lane's Proofpoint handling is hard-coded. The README backlog item
for the Proofpoint on Demand Log API would be the first real implementation
of a `MailGateway` ("does this domain send mail, and from where"). Define the
interface when that item is built, with PoD as implementation one, so the
shape follows a real API rather than a guess.

### 3.9 Exposure / attack-path source

The `internal/defender` package parses Defender for Cloud attack-path emails.
The backlog's attack-path lane is where an `exposure.Provider` would first be
needed, as the second source after Defender.

### 3.10 Certificate inventory

The backlog's certificate-expiry lane (Qualys Certificate View) is unbuilt.
Because it is unbuilt, it can be written behind a `certs.Source` from line one
at almost no extra cost. Decide that when it is picked up.

---

## 4. What we deliberately do not abstract

- **The agent runtime.** The orchestrator runs on the `claude` CLI and
  `internal/budget` rations a Claude subscription. This is the product, not a
  swappable tool. Abstracting it would add a layer with nothing behind it.
- **The state store** (`state/memory.db`, the dated report and ticket files).
  Plain files and SQLite are the point: they are inspectable from an SSH
  session at 06:30.
- **The one-shot parsers** (`internal/triage`, `internal/mailbox` plans). They
  are pure functions of text; an interface would be ceremony.

---

## 5. How to put a new tool behind an interface

**The rule: extract an interface when the second implementation is real or
imminent.** An interface written for a vendor nobody uses yet is a guess about
that vendor's API, and guesses are wrong in ways that are expensive to fix
later. The exceptions are lanes not yet built (3.8 to 3.10): write them behind
an interface from the start.

Adding an implementation to an existing interface:

1. **Package.** Put it beside the others, for example
   `internal/appscan/invicti/`, importing only the interface's package and the
   standard library. The module has **no dependencies**; push back on any
   change that needs one.
2. **Implement the whole contract**, including the tri-state results
   ([section 6](#6-the-conventions-every-interface-here-follows)).
3. **One selection point.** Add a case to the single function that chooses
   the implementation (`buildLookupProvider`, `reportProvider`, the
   `providers` slice, `registrarFor`). Do not add vendor checks anywhere else.
4. **Configuration.** Add the environment variables to
   `fleet-kit/fleet/fleet.env.example`, with `none` or empty meaning "off",
   and make config validation require the credentials only when that provider
   is selected.
5. **Tests with a fake server.** Use invented data only: `example.com`,
   `host-a`, `192.0.2.x`. No real tenant, host or application data in any
   tracked file.
6. **Docs.** The man pages must document every new flag (a test fails on
   drift); update README, RUNBOOK, CHEATSHEET and SECURITY where the vendor is
   mentioned; add a CHANGELOG entry that ends with **Upgrade**.
7. **Verify against the live service before trusting it.** Element and field
   names from a vendor's documentation are a hypothesis. Add a probe flag
   (see `cti-appreport --probe-findings` and `--request-file`) so the first
   live run is a diagnosis, not a guess.

---

## 6. The conventions every interface here follows

These are visible in the code and are why the existing interfaces hold up.

- **The interface lives with its consumer's domain**, not with a vendor, and
  vendor code lives in a subpackage (`vulnlookup/qualys`, `appscan/qualys`,
  `domains/godaddy`).
- **`Name()` is a stable key** stored on results and printed in reports, so a
  report always says which provider produced a line.
- **Optional capabilities are separate small interfaces**, discovered by type
  assertion. An email-only path needs no credentials and cannot be broken by an
  API outage.
- **Three outcomes, never two.** Present, absent, and *could not tell*. Every
  normalised result type carries the third state and a reason. A lookup error
  is reported as unknown, never as clean.
- **Vendor scales and ids do not leak.** A scanner's severity stays its own
  scale and is labelled; a provider's identifiers are carried as opaque
  strings.
- **Read-only unless the lane's job is to write**, and every write path sits
  behind a gate that lives above the interface: the mail allowlist in
  `cti-mailer`, the Jira gate in `cti-jira`.
- **A stub is honest.** The CrowdStrike placeholder returns an error and an
  `UNKNOWN` result that says it is not implemented. It never pretends.
- **The vendor's budget is respected in the client**, not in each caller.
  The Qualys rate limiter reads the vendor's own headers
  (`internal/qualysrl`), so a raised limit needs no change here.
