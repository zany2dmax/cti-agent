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
