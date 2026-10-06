---
name: scout-sweep
description: Poll vendor advisories and CTI feeds for CVEs the mailbox did not carry, then correlate through the vulnerability scanner.
---

# /scout-sweep

> **Operator-attended playbook.** Not runnable on the unattended heartbeat:
> `scout.py` and `enrich.py` are not on the orchestrator's grant (see
> `CLAUDE.md`, *What a beat can run*), and they do not need to be -
> `cti-agent-scout.timer` runs the sweep itself every four hours. On a beat,
> read what it found with `fleet-db recent` and the journal. In a session with
> the operator present, Claude Code asks before each command below.

Runs every 4 hours. The mailbox is reactive — this lane is how you find things
before a vendor newsletter gets around to telling you.

1. `python3 $FLEET_CODE/lanes/scout.py --out $FLEET_HOME/state/scout-$(date +%F).json`
   Polls the feeds in `$FLEET_FEEDS`, extracts CVEs, dedupes against
   `scout_items` in memory so you only surface genuinely new IDs.

2. Take the new CVE IDs and run them through the same lookup path the mailbox
   CVEs take, so presence is still decided by the scanner and nothing else:
   ```
   python3 $FLEET_CODE/lanes/enrich.py --cves CVE-2026-1234,CVE-2026-5678 \
     --out $FLEET_HOME/state/scout-enriched-$(date +%F).json
   ```

3. Anything that lands Sev5 or Sev4 goes on the board immediately so it makes the
   next digest. Everything else just accumulates in memory for the weekly.

4. Log a `scout_sweep` row: feeds polled, feeds that errored, new CVEs found.

If a feed has been failing for more than a day, post it to the board — a
silently dead feed is a blind spot that looks like good news.
