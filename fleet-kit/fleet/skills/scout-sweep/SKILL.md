---
name: scout-sweep
description: Poll vendor advisories and CTI feeds for CVEs the mailbox did not carry, then correlate through Qualys.
---

# /scout-sweep

Runs every 4 hours. The mailbox is reactive — this lane is how you find things
before a vendor newsletter gets around to telling you.

1. `python3 ~/fleet/lanes/scout.py --out ~/fleet/state/scout-$(date +%F).json`
   Polls the feeds in `~/fleet/lanes/feeds.txt`, extracts CVEs, dedupes against
   `scout_items` in memory so you only surface genuinely new IDs.

2. Take the new CVE IDs and run them through the same lookup path the mailbox
   CVEs take, so presence is still decided by Qualys and nothing else:
   ```
   python3 ~/fleet/lanes/enrich.py --cves CVE-2026-1234,CVE-2026-5678 \
     --out ~/fleet/state/scout-enriched-$(date +%F).json
   ```

3. Anything that lands P1 or P2 goes on the board immediately so it makes the
   next digest. Everything else just accumulates in memory for the weekly.

4. Log a `scout_sweep` row: feeds polled, feeds that errored, new CVEs found.

If a feed has been failing for more than a day, post it to the board — a
silently dead feed is a blind spot that looks like good news.
