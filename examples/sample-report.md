# CTI / CVE Daily Report

<!--
Illustrative output only. Every value here is invented: the mailbox, the
hostnames and the CVE IDs. A real report contains the hostnames of vulnerable
machines in your estate and is written 0600 and gitignored for that reason -
do not replace this file with one.

The Sample Hosts column reflects REPORT_HOSTNAMES:
  full    real hostnames, as below
  redact  salted pseudonyms, host-xxxxxxxx
  count   the Host Count column only
-->

- Mailbox: `threatintel@example.com`
- Lookback since: `2026-05-21T00:00:00-04:00`
- Emails inspected: `12`
- Lookup provider: `qualys`
- Generated: `2026-05-21T09:00:00-04:00`

| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts | Reason |
|---|---|---|---|---:|---:|---|---|---|
| CVE-2026-9082 | PRESENT | qualys | 123456 | 3 | 95 | 2026-05-21T03:15:00Z | web01.example.com, web02.example.com, web03.example.com | Detected by QID 123456 |
| CVE-2026-9083 | NOT_PRESENT | qualys | 234567 | 0 | 0 | | | Scanned, no detections |
| CVE-2026-9999 | UNKNOWN | qualys | | 0 | 0 | | | No Qualys KnowledgeBase CVE-to-QID mapping found |
| CVE-2026-9998 | UNKNOWN | qualys | | 0 | 0 | | | KB cache is stale: coverage UNVERIFIED, not confirmed absent |

The two `UNKNOWN` rows say different things, which is the distinction the
report exists to preserve. The first was looked up and no mapping exists. The
second was not reliably looked up at all, because the KnowledgeBase cache had
aged past `QUALYS_KB_MAX_AGE_HOURS` and could not be refreshed. Neither means
"not affected", and a report that rendered them identically would invite
exactly that reading.
