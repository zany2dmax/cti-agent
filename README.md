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

- `Mail.Read`

The app must be allowed to read the shared mailbox. In production, consider an Exchange Application Access Policy to restrict the app to only the cybersecurity mailbox.

### Qualys

The Qualys account needs API access to:

- KnowledgeBase vulnerability list
- Host Detection List

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
| `LOOKUP_PROVIDER` | Provider to use: `qualys` or `crowdstrike` |
| `QUALYS_BASE_URL` | Qualys API base URL, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_USERNAME` | Qualys username, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_PASSWORD` | Qualys password, required when `LOOKUP_PROVIDER=qualys` |
| `QUALYS_KB_CACHE` | Local JSON cache path for CVE -> QID map |
| `REPORT_PATH` | Markdown output file |

### Microsoft Graph permissions needed
## Microsoft Graph API Permissions

The CTI Agent uses Microsoft Graph application authentication (Client Credentials Flow) to read emails from the Cyber Security shared mailbox.

### Required Application Permissions

| Permission | Type |
|------------|------|
| Mail.Read | Application |

### Grant Admin Consent

After adding the permission in Microsoft Entra:

1. Navigate to Entra ID → App Registrations
2. Select the CTI Agent application
3. API Permissions
4. Add Permission → Microsoft Graph → Application Permissions
5. Add `Mail.Read`
6. Click **Grant Admin Consent**

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
