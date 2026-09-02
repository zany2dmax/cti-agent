---
name: cti-digest
description: Run the full CTI pipeline and send the digest to the security DL. Use for the daily 06:00 brief, the Monday weekly, or an on-demand run.
---

# /cti-digest [--daily|--weekly|--dry-run]

Full pipeline: ingest → enrich → brief → send. Default is `--daily`.

## Steps

1. **Ingest.** Run the Go agent. It reads cybersecurity@crhomeusa.com, extracts
   CVEs, looks them up in Qualys, writes markdown.
   ```
   cd "$CTI_AGENT_DIR" && set -a && . ~/fleet/fleet.env && set +a && \
     REPORT_PATH=~/fleet/reports/raw-$(date +%F).md ./cti-qualys-agent
   ```
   If Graph auth fails, stop and post to the board — do not send a digest built
   on stale data without labeling it stale.

2. **Enrich.** Layer on NVD CVSS, EPSS, KEV; compute priority.
   ```
   python3 ~/fleet/lanes/enrich.py \
     --report ~/fleet/reports/raw-$(date +%F).md \
     --out ~/fleet/state/enriched-$(date +%F).json
   ```

3. **Brief.** Render HTML.
   ```
   python3 ~/fleet/lanes/brief.py --daily \
     --enriched ~/fleet/state/enriched-$(date +%F).json \
     --out ~/fleet/reports/digest-$(date +%F).html
   ```

4. **Read it before you send it.** Open the HTML. Sanity-check: does the P1
   count match what enrich found? Are host counts plausible? Is any CVE listed
   as exploitable that Qualys actually returned UNKNOWN for? If the digest
   claims something the data does not support, fix the lane, do not fix the
   wording.

5. **Send.** Only for `--daily` and `--weekly`, which are pre-approved.
   ```
   python3 ~/fleet/lanes/mailer.py \
     --html ~/fleet/reports/digest-$(date +%F).html \
     --subject "$(python3 ~/fleet/lanes/brief.py --subject-only \
                    --enriched ~/fleet/state/enriched-$(date +%F).json)"
   ```
   With `--dry-run`, stop here and post the path to the board instead.

6. **Log.** Write a `digest_sent` memory row with the date, P1/P2/P3/P4 counts,
   the Graph message id, and anything you chose to omit.

## Guardrails

- Never send twice for the same window. Check memory for an existing
  `digest_sent` row first.
- If enrich returns zero findings, still send the daily — a one-line "no new
  CVEs in the last 24h" is useful signal. Do not skip silently.
- If a lane errors, send the digest with an explicit `DEGRADED` banner naming
  which enrichment source was unavailable. A digest that hides its own gaps is
  worse than no digest.
