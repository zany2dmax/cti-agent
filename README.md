# CTI CVE Agent

A modular Go agent that reads daily CTI emails from a shared Microsoft 365 mailbox, extracts CVEs, sends those CVEs to a swappable vulnerability lookup provider, and writes a markdown report.

The first implemented lookup provider is Qualys VMDR. The lookup layer is intentionally isolated so it can later be replaced or supplemented with CrowdStrike Exposure Management / Spotlight, Defender, Tenable, Rapid7, or another VM platform.

## What it does

1. Reads recent emails from `cybersecurity@crhomeusa.com` or another configured mailbox.
2. Extracts CVE IDs with regex.
3. Sends each CVE to the configured lookup provider.
4. Normalizes provider-specific evidence into a common result model.
5. Generates a markdown summary showing `PRESENT`, `NOT_PRESENT`, or `UNKNOWN`.

Presence should be determined only by the lookup provider. CTI email text provides urgency/context, not proof that a vulnerability exists in the environment.

## Project layout

```text
cmd/cti-qualys-agent/          CLI entrypoint
internal/config/               environment/config loading
internal/cti/                  CTI parsing and CVE extraction
internal/graph/                Microsoft Graph mailbox reader
internal/vulnlookup/           provider-neutral lookup interface and result types
internal/vulnlookup/qualys/    Qualys implementation
internal/vulnlookup/crowdstrike/ placeholder for future CrowdStrike implementation
internal/vulnlookup/noop	For testing the CVE extraction and not calling a VM provider API
internal/report/               markdown report writer
fleet-kit/                     the always-on fleet (see fleet-kit/README.md)
fleet-kit/bin/dev-run          local pipeline runner: doctor/ingest/enrich/brief/send
fleet-kit/fleet/lanes/         enrich, scout, brief, mailer
fleet-kit/fleet/bin/           run-digest, run-checkin, fleet-board, fleet-db
fleet-kit/fleet/systemd/       service + timer pairs for the server
fleet-kit/tests/               lane tests (stdlib unittest, no network)
scripts/                       history scrub + exposure remediation notes
```

## Lookup provider boundary

The important abstraction is `internal/vulnlookup.LookupProvider`:

```go
type LookupProvider interface {
    Name() string
    LookupCVE(ctx context.Context, cve string) (Result, error)
}
```

The rest of the app does not know whether a CVE was checked in Qualys, CrowdStrike, or another backend. Provider-specific IDs like Qualys QIDs are returned as normalized `ExternalIDs`.

## Current providers

### Qualys

The Qualys provider does a two-step lookup:

1. Build/load a local Qualys KnowledgeBase cache mapping `CVE -> QID[]`.
2. Query Host Detection List for active detections of those QIDs.

### CrowdStrike

A placeholder provider exists at `internal/vulnlookup/crowdstrike`. It currently returns `UNKNOWN` until a real CrowdStrike API lookup is added.

### noop/none

Allows testing the full CVE parsing of the emails in outlook without calling a VM provider

## Required permissions

### Microsoft Graph

For daemon/service operation, use Microsoft Graph application permissions and grant admin consent:

- `Mail.Read` — required by the agent, to read the CTI mailbox.
- `Mail.Send` — required only by the fleet, to send digests and escalations.

The app must be allowed to read the shared mailbox. In production, restrict it
with an Exchange Application Access Policy: `Mail.Send` as an *application*
permission is tenant-wide by default, meaning the app could otherwise send as
any mailbox in the tenant.

```powershell
New-ApplicationAccessPolicy -AppId <CLIENT_ID> `
  -PolicyScopeGroupId cti-fleet-mailboxes@example.com `
  -AccessRight RestrictAccess -Description "CTI: security mailbox only"
Test-ApplicationAccessPolicy -Identity <MAILBOX> -AppId <CLIENT_ID>
```

`fleet-kit/fleet/lanes/mailer.py --check` decodes the token and reports which
roles were actually granted — consent is the step people skip.

### Qualys

The Qualys account needs API access to:

- KnowledgeBase vulnerability list
- Host Detection List

## Two ways to run this

**The agent alone** — build it, point it at a mailbox, get a markdown report.
That is the Quick start below.

**The agent inside the fleet** (`fleet-kit/`) — an always-on orchestrator plus
three executor lanes that add exploitability context (NVD CVSS, EPSS, CISA
KEV), prioritize P1–P4, render an HTML digest and mail it on a schedule. See
[fleet-kit/README.md](fleet-kit/README.md) for the full runbook and a complete
command reference.

For local development and debugging, `fleet-kit/bin/dev-run` executes the whole
pipeline from a checkout with no root, no service account and no systemd. It
sends nothing unless you explicitly ask:

```bash
cp .env.example .env && vi .env

./fleet-kit/bin/dev-run doctor                  # config + Graph token + roles
./fleet-kit/bin/dev-run ingest --provider none  # mailbox + CVE extraction only
./fleet-kit/bin/dev-run all                     # full pipeline, opens the digest
```

`task --list` shows every target. Start with `--provider none`: it needs only
the Entra credentials, so it separates "can we read the mailbox" from "does the
scanner answer" — two failures that look identical together.

## Quick start

```bash
cp .env.example .env
# edit .env with real values

set -a
source .env
set +a

go run ./cmd/cti-qualys-agent
```

Or with Task:

```bash
task build
task run
```

## Environment variables

| Variable | Purpose |
|---|---|
| `TENANT_ID` | Entra tenant ID |
| `CLIENT_ID` | App registration client ID |
| `CLIENT_SECRET` | App registration client secret |
| `GRAPH_MAILBOX` | Mailbox to read, e.g. `cybersecurity@crhomeusa.com` |
| `GRAPH_FOLDER` | Folder to read, default `inbox` |
| `GRAPH_LOOKBACK_HOURS` | How far back to read messages |
| `LOOKUP_PROVIDER` | `qualys`, `crowdstrike`, or `none`/`noop` (skip the scanner) |
| `QUALYS_BASE_URL` | Qualys API base URL, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_USERNAME` | Qualys username, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_PASSWORD` | Qualys password, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_KB_CACHE` | Local JSON cache path for CVE -> QID map |
| `REPORT_PATH` | Markdown output file |
| `QUALYS_KB_MAX_AGE_HOURS` | Hours before the CVE→QID cache refreshes (default 168) |
| `NVD_API_KEY` | **Free** NVD key — without it enrichment is 10x slower. See below |
| `FLEET_USER_AGENT` | User-Agent sent to NVD, EPSS, CISA and advisory feeds |
| `DIGEST_TO` | Digest recipients, comma-separated. No default |
| `FLEET_ALLOW_TO` | Recipient allowlist; anything else needs `--approve` |
| `FLEET_OPERATOR_EMAIL` | Where the orchestrator escalates. Pre-approved |
| `CTI_REPLY_MAILBOX` | Mailbox you reply into; defaults to `GRAPH_MAILBOX` |
| `FLEET_HOME` | Fleet state directory |
| `REPORT_HOSTNAMES` | Hostname disclosure: `full` (default), `redact`, or `count` |
| `REPORT_REDACTION_SALT` | Private, stable salt for hostname pseudonyms |

## Report sensitivity

A CTI report pairs "this CVE is exploitable" with "these are the machines that
have it." That is a targeting list if it leaks.

The default is nonetheless `full`, because the alternative is worse in practice:
a pseudonym cannot be looked up in the scanner, so a redacted report tells you a
P1 exists without telling you where, and you have to rerun the pipeline to act
on it. An unactionable security report is not a safe security report.

What keeps that defensible is everything around it — reports are written `0600`,
excluded by `.gitignore`, and mailed only to an allowlisted internal DL. Switch
to `redact` or `count` for any copy leaving that path.

| `REPORT_HOSTNAMES` | Output |
|---|---|
| `redact` | Stable pseudonyms — `host-3797a22b`. The same machine keeps the same label across reports, so you can track remediation without naming it. **Not reversible** — there is no lookup table, so you cannot resolve one back to a host. |
| `count` | Host count only, names withheld entirely. |
| `full` *(default)* | Real hostnames. The report carries a "do not commit" banner. |

Set `REPORT_REDACTION_SALT` to a private, stable value. Pseudonyms are
deterministic, so without a salt anyone holding a list of candidate hostnames
can confirm matches by hashing them. With a salt they cannot.

Generated reports are written mode `0600` and are excluded by `.gitignore`.
Do not commit them, attach them to tickets, or paste them into chat tools.
`scripts/scrub-history.sh` exists because this rule was learned the hard way.

## The NVD API key

The fleet's enrich lane calls NVD once per CVE. Get a key before running this
on a schedule — it is free and takes about a minute:
**https://nvd.nist.gov/developers/request-an-api-key**

| | Rate limit | 20 CVEs | 50 CVEs |
|---|---|---|---|
| No key | 5 req / 30s | ~2 min | ~5 min |
| With `NVD_API_KEY` | 50 req / 30s | ~15 s | ~35 s |

Responses are cached for 7 days, so the cost is worst on a first run. EPSS and
the CISA KEV catalog need no key.

## Scanner KB cache freshness

The Qualys provider maps CVE→QID from a local cache of the KnowledgeBase. That
cache expires after `QUALYS_KB_MAX_AGE_HOURS` (default 168 = 7 days), after
which the agent tops it up incrementally and falls back to a full rebuild.

This matters more than it sounds. A cache older than a CVE has no mapping for
it, so the CVE reports `UNKNOWN` — which reads as "not affected" when it
actually means "never checked". If a refresh fails, the run continues but every
`UNKNOWN` then says **"coverage UNVERIFIED, not confirmed absent"** rather than
"no mapping found". Those are different facts and the report distinguishes them.

To force a rebuild, delete the cache file and rerun. The first build is a large
download and takes a few minutes.

### Microsoft Graph permissions needed
## Microsoft Graph API Permissions

The CTI Agent uses Microsoft Graph application authentication (Client Credentials Flow) to read emails from the Cyber Security shared mailbox.

### Required Application Permissions

| Permission | Type | Needed by |
|------------|------|-----------|
| Mail.Read | Application | the agent — reading the CTI mailbox |
| Mail.Send | Application | the fleet — sending digests and escalations |

### Grant Admin Consent

After adding the permission in Microsoft Entra:

1. Navigate to Entra ID → App Registrations
2. Select the CTI Agent application
3. API Permissions
4. Add Permission → Microsoft Graph → Application Permissions
5. Add `Mail.Read`, and `Mail.Send` if you are running the fleet
6. Click **Grant Admin Consent** — this step is easy to miss, and nothing works without it

### Required Configuration

```env
TENANT_ID=<tenant-id>
CLIENT_ID=<app-registration-client-id>
CLIENT_SECRET=<client-secret>
MAILBOX=cybersecurity@crhomeusa.com
```

### Authentication Flow

1. Obtain access token from Microsoft Entra ID
2. Call Microsoft Graph API
3. Read messages from the Cyber Security shared mailbox
4. Parse CTI emails and extract CVEs


## Adding another lookup provider

1. Create a package under `internal/vulnlookup/<provider>`.
2. Implement `Name()` and `LookupCVE(ctx, cve)`.
3. Return normalized `vulnlookup.Result` values.
4. Add the provider to `buildLookupProvider()` in `cmd/cti-qualys-agent/main.go`.
5. Add provider-specific config to `internal/config` only if needed.

## Notes

- The initial Qualys KnowledgeBase download can be large. The agent caches the CVE/QID mapping locally.
- For very large Qualys environments, add pagination/truncation handling and batching by QID.
- This is an MVP scaffold meant to be checked into GitHub and iterated.

## Feature Requests

- Add other VM providers as needed
- Email the final report back to a distruction list
- Package this up as a docker container for easy deployment and maintainability
