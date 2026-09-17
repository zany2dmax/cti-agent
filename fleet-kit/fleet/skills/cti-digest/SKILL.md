---
name: cti-digest
description: Run the full CTI pipeline and send the digest to the security DL. Use for the daily 06:00 brief, the Monday weekly, or an on-demand run.
---

# /cti-digest [--daily|--weekly|--dry-run]

Full pipeline: ingest → enrich → brief → send. Default is `--daily`.

## Prefer run-digest over these steps

**A systemd timer already does this.** `cti-agent-digest.timer` runs
`$FLEET_CODE/bin/run-digest daily` every morning without involving a model at
all, and that is deliberate: delivery must not depend on the orchestrator
having a good day or having quota left.

So reach for the one command, not the four:

```
$FLEET_CODE/bin/run-digest daily --dry-run    # renders, sends nothing
$FLEET_CODE/bin/run-digest daily              # sends to $DIGEST_TO
$FLEET_CODE/bin/run-digest weekly
```

It holds the **already-sent guard** — per `(kind, day)` in the database — which
is the thing that makes a recovery run safe. The step-by-step version below
does not, so running it after the timer already fired sends a second digest.

Use it when: the operator asks for an on-demand run, or a timer genuinely
failed and you are recovering. Not on a schedule of your own.

The individual steps are documented below because you may need to run *one* of
them — re-enriching after a KB cache refresh, say — or to understand what
broke. Read them as reference, not as a recipe.

## Steps

1. **Ingest.** Run the Go agent. It reads the CTI mailbox, extracts
   CVEs, looks them up in the configured scanner, writes markdown.
   ```
   cd "$CTI_AGENT_DIR" && set -a && . $FLEET_ENV && set +a && \
     REPORT_PATH=$FLEET_HOME/reports/raw-$(date +%F).md ./cti-agent
   ```
   If Graph auth fails, stop and post to the board — do not send a digest built
   on stale data without labeling it stale.

2. **Enrich.** Layer on NVD CVSS, EPSS, KEV; compute priority.
   ```
   python3 $FLEET_CODE/lanes/enrich.py \
     --report $FLEET_HOME/reports/raw-$(date +%F).md \
     --out $FLEET_HOME/state/enriched-$(date +%F).json
   ```

3. **Brief.** Render HTML.
   ```
   python3 $FLEET_CODE/lanes/brief.py --daily \
     --enriched $FLEET_HOME/state/enriched-$(date +%F).json \
     --out $FLEET_HOME/reports/digest-$(date +%F).html
   ```

4. **Read it before you send it.** Open the HTML. Sanity-check: does the Sev5
   count match what enrich found? Are host counts plausible? Is any CVE listed
   as exploitable that the scanner actually returned UNKNOWN for? If the digest
   claims something the data does not support, fix the lane, do not fix the
   wording.

5. **Send.** Only for `--daily` and `--weekly`, which are pre-approved.
   ```
   python3 $FLEET_CODE/lanes/mailer.py \
     --html $FLEET_HOME/reports/digest-$(date +%F).html \
     --subject "$(python3 $FLEET_CODE/lanes/brief.py --subject-only \
                    --enriched $FLEET_HOME/state/enriched-$(date +%F).json)"
   ```
   With `--dry-run`, stop here and post the path to the board instead.

6. **Log.** Write a `digest_sent` memory row with the date, Sev5/Sev4/Sev2/Sev1 counts,
   the Graph message id, and anything you chose to omit.

## Guardrails

- Never send twice for the same window. Check memory for an existing
  `digest_sent` row first.
- If enrich returns zero findings, still send the daily — a one-line "no new
  CVEs in the last 24h" is useful signal. Do not skip silently.
- If a lane errors, send the digest with an explicit `DEGRADED` banner naming
  which enrichment source was unavailable. A digest that hides its own gaps is
  worse than no digest. `brief.py` renders that banner from the `degraded` list
  in the enriched JSON, so you do not have to write it yourself.
- The digest carries CISA KEV deadlines automatically: a red banner and a
  subject suffix when something present in the estate is past its published
  due date. You do not add that either. If you want the detail behind it, run
  `$FLEET_CODE/bin/cti-kev`.
