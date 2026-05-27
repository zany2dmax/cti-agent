# CTI Qualys Agent

A small Go agent that reads daily CTI emails from a shared Microsoft 365 mailbox, extracts CVEs, maps CVEs to Qualys QIDs, checks whether those QIDs are currently detected in Qualys VMDR, and writes a markdown report.

## What it does

1. Reads recent emails from email shared mailbox in M365 or another configured mailbox.
2. Extracts CVE IDs with regex.
3. Builds or loads a local Qualys KnowledgeBase cache mapping CVE -> QIDs.
4. Queries Qualys Host Detection List for active detections.
5. Generates a markdown summary showing `PRESENT`, `NOT_PRESENT`, or `UNKNOWN`.

Presence is determined only by Qualys detections. CTI email text provides context, not proof that a vulnerability exists in the environment.

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

go mod tidy
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
| `GRAPH_MAILBOX` | Mailbox to read in mailbox@domain.com format |
| `GRAPH_FOLDER` | Folder to read, default `inbox` |
| `GRAPH_LOOKBACK_HOURS` | How far back to read messages |
| `QUALYS_BASE_URL` | Qualys API base URL |
| `QUALYS_USERNAME` | Qualys username |
| `QUALYS_PASSWORD` | Qualys password |
| `QUALYS_KB_CACHE` | Local JSON cache path for CVE -> QID map |
| `REPORT_PATH` | Markdown output file |

## Notes

- The initial KnowledgeBase download can be large. The agent caches the CVE/QID mapping locally.
- For very large Qualys environments, you may need pagination/truncation handling and batching by QID.
- This is an MVP scaffold meant to be checked into GitHub and iterated.
