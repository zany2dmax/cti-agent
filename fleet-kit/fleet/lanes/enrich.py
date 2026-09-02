#!/usr/bin/env python3
"""enrich.py - the @enrich lane.

Takes the CVEs the Go agent found (or an explicit list) and layers on the
context that decides whether anyone should care:

  * NVD 2.0    - CVSS v3.1 base score, severity, description, KEV flag
  * FIRST EPSS - probability of exploitation in the next 30 days
  * CISA KEV   - known-exploited flag, due date, ransomware association

Then it assigns a P1-P4 priority that combines *exploitability in the wild*
with *presence in our environment*. Presence comes only from the vulnerability
lookup provider - this lane never decides that on its own.

Usage:
  enrich.py --report ~/fleet/reports/raw-2026-08-18.md --out enriched.json
  enrich.py --cves CVE-2026-1234,CVE-2026-5678 --out enriched.json
  enrich.py --report raw.md --out enriched.json --no-db     # skip the upsert

Stdlib only. No pip install on the fleet box.
"""
import argparse
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

FLEET_HOME = os.environ.get("FLEET_HOME", os.path.expanduser("~/fleet"))
STATE = os.path.join(FLEET_HOME, "state")
NVD_CACHE = os.path.join(STATE, "nvd-cache.json")
KEV_CACHE = os.path.join(STATE, "kev-cache.json")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
UA = "cti-fleet-enrich/1.0 (+cybersecurity@crhomeusa.com)"

# NVD allows 5 req/30s anonymous, 50 req/30s with a key. Stay under both.
NVD_DELAY = 0.7 if os.environ.get("NVD_API_KEY") else 6.5
NVD_TTL_DAYS = 7          # CVSS scores rarely move once assigned
KEV_TTL_HOURS = 12


def log(msg):
    print(f"[enrich] {msg}", file=sys.stderr)


def http_json(url, headers=None, timeout=45, retries=3):
    """GET JSON with backoff. Returns None rather than raising - a missing
    enrichment source degrades the report, it does not kill the run."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503) and attempt < retries - 1:
                wait = (attempt + 1) * 15
                log(f"HTTP {e.code} on {url[:70]} - backing off {wait}s")
                time.sleep(wait)
                continue
            log(f"HTTP {e.code} giving up on {url[:70]}")
            return None
        except Exception as e:                                  # noqa: BLE001
            if attempt < retries - 1:
                time.sleep((attempt + 1) * 5)
                continue
            log(f"error on {url[:70]}: {e}")
            return None
    return None


def load_cache(path, ttl):
    try:
        with open(path) as f:
            blob = json.load(f)
        fetched = datetime.fromisoformat(blob.get("fetched", "1970-01-01T00:00:00+00:00"))
        if datetime.now(timezone.utc) - fetched < ttl:
            return blob.get("data", {})
    except Exception:                                           # noqa: BLE001
        pass
    return None


def save_cache(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"fetched": datetime.now(timezone.utc).isoformat(), "data": data}, f)
    os.replace(tmp, path)


# ---------------------------------------------------------------- input parsing

def parse_report(path):
    """Parse the Go agent's markdown table.

    Columns: CVE | Status | Provider | External IDs | Host Count | Max Score |
             Last Seen | Sample Hosts / Reason
    """
    findings = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|") or line.startswith("|---") or "| CVE |" in line:
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) < 8 or not CVE_RE.fullmatch(cells[0]):
                continue
            cve = cells[0].upper()

            def as_int(v):
                try:
                    return int(v or 0)
                except ValueError:
                    return 0

            findings[cve] = {
                "cve": cve,
                "status": cells[1] or "UNKNOWN",
                "provider": cells[2] or "unknown",
                "qids": cells[3],
                "host_count": as_int(cells[4]),
                "qualys_score": as_int(cells[5]),
                "last_seen": cells[6],
                "sample_hosts": cells[7],
            }
    return findings


def parse_meta(path):
    """Pull the header facts so the digest can state its own provenance."""
    meta = {}
    pats = {
        "mailbox": r"Mailbox:\s*`([^`]+)`",
        "since": r"Lookback since:\s*`([^`]+)`",
        "emails": r"Emails inspected:\s*`([^`]+)`",
        "provider": r"Lookup provider:\s*`([^`]+)`",
        "generated": r"Generated:\s*`([^`]+)`",
    }
    try:
        head = open(path, encoding="utf-8").read(4000)
    except OSError:
        return meta
    for k, p in pats.items():
        m = re.search(p, head)
        if m:
            meta[k] = m.group(1)
    return meta


# ------------------------------------------------------------------ enrichment

def fetch_nvd(cves):
    """One request per CVE (NVD has no bulk-by-id endpoint), cached 7 days."""
    cache = load_cache(NVD_CACHE, timedelta(days=NVD_TTL_DAYS)) or {}
    stale = [c for c in cves if c not in cache]
    if stale:
        log(f"NVD: {len(cache)} cached, fetching {len(stale)} "
            f"(~{int(len(stale) * NVD_DELAY)}s"
            f"{' - set NVD_API_KEY to go 10x faster' if NVD_DELAY > 1 else ''})")
    headers = {}
    if os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]

    for i, cve in enumerate(stale):
        if i:
            time.sleep(NVD_DELAY)
        data = http_json(f"{NVD_API}?cveId={urllib.parse.quote(cve)}", headers=headers)
        entry = {"cvss": None, "cvss_severity": None, "description": None,
                 "kev_nvd": False, "vuln_status": None, "published": None}
        if data and data.get("vulnerabilities"):
            v = data["vulnerabilities"][0].get("cve", {})
            entry["vuln_status"] = v.get("vulnStatus")
            entry["published"] = v.get("published")
            entry["kev_nvd"] = bool(v.get("cisaExploitAdd"))
            for d in v.get("descriptions", []):
                if d.get("lang") == "en":
                    entry["description"] = d.get("value", "")[:400]
                    break
            metrics = v.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    # Prefer the NVD-authored score over a CNA self-assessment.
                    chosen = next((m for m in metrics[key]
                                   if m.get("source", "").endswith("nist.gov")),
                                  metrics[key][0])
                    cd = chosen.get("cvssData", {})
                    entry["cvss"] = cd.get("baseScore")
                    entry["cvss_severity"] = (cd.get("baseSeverity")
                                              or chosen.get("baseSeverity"))
                    break
        cache[cve] = entry
    if stale:
        save_cache(NVD_CACHE, cache)
    return cache


def fetch_epss(cves):
    """EPSS takes a comma-separated list. Chunk at 100 to stay polite."""
    out = {}
    cves = list(cves)
    for i in range(0, len(cves), 100):
        chunk = cves[i:i + 100]
        data = http_json(f"{EPSS_API}?cve={','.join(chunk)}")
        if not data:
            continue
        for row in data.get("data", []):
            try:
                out[row["cve"].upper()] = {
                    "epss": float(row.get("epss") or 0),
                    "epss_pct": float(row.get("percentile") or 0),
                    "epss_date": row.get("date"),
                }
            except (TypeError, ValueError):
                continue
        time.sleep(1)
    log(f"EPSS: scored {len(out)}/{len(cves)}")
    return out


def fetch_kev():
    """Bulk KEV catalog. NVD already flags KEV membership, but the catalog is
    the only place with the remediation due date and ransomware association."""
    cache = load_cache(KEV_CACHE, timedelta(hours=KEV_TTL_HOURS))
    if cache is not None:
        log(f"KEV: {len(cache)} entries (cached)")
        return cache
    data = http_json(KEV_FEED, timeout=90)
    if not data:
        log("KEV: feed unavailable - falling back to the NVD cisaExploitAdd flag")
        return {}
    kev = {}
    for v in data.get("vulnerabilities", []):
        cid = (v.get("cveID") or "").upper()
        if cid:
            kev[cid] = {
                "kev_added": v.get("dateAdded"),
                "kev_due": v.get("dueDate"),
                "ransomware": v.get("knownRansomwareCampaignUse"),
                "kev_name": v.get("vulnerabilityName"),
                "kev_action": v.get("requiredAction"),
            }
    log(f"KEV: {len(kev)} entries (catalog {data.get('catalogVersion')})")
    save_cache(KEV_CACHE, kev)
    return kev


# -------------------------------------------------------------------- scoring

def prioritize(f):
    """Combine exploitability with presence.

    The whole point: a 10.0 CVSS on software we do not run is noise, and a 6.5
    that is being actively exploited on 300 of our hosts is an emergency. CVSS
    alone gets that backwards, which is why it is the tiebreaker and not the
    driver.

    P1 - present AND actively exploited (KEV or EPSS >= 10%)   -> today
    P2 - present in the environment at all                     -> this patch cycle
         (also: UNKNOWN coverage on something being exploited)
    P3 - exploited but not detected here, or UNKNOWN + CVSS>=9  -> verify coverage
    P4 - everything else                                       -> awareness

    Note that presence alone earns P2 regardless of CVSS. A 5.5 on 186 hosts is
    a real patching obligation; ranking it below a 9.3 we do not run inverts the
    thing this scoring exists to fix.
    """
    present = f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0
    unknown = f.get("status") == "UNKNOWN"
    kev = bool(f.get("kev"))
    epss = f.get("epss") or 0
    cvss = f.get("cvss") or 0
    hot = kev or epss >= 0.10
    very_hot = kev or epss >= 0.50

    why = []
    if kev:
        why.append("on CISA KEV")
    if epss >= 0.50:
        why.append(f"EPSS {epss:.0%} - exploitation likely")
    elif epss >= 0.10:
        why.append(f"EPSS {epss:.0%} - elevated")
    if cvss:
        why.append(f"CVSS {cvss}")
    if present:
        why.append(f"PRESENT on {f['host_count']} host(s)")
    elif f.get("status") == "NOT_PRESENT":
        why.append("not detected in Qualys")
    elif unknown:
        why.append("no Qualys QID mapping - coverage unverified")
    if str(f.get("ransomware", "")).lower() == "known":
        why.append("used in ransomware campaigns")

    if present and hot:
        p = "P1"
    elif present:
        p = "P2"
    elif unknown and very_hot:
        # Cannot confirm we are clean and it is being exploited. Do not let this
        # sit in the noise bucket just because Qualys had no mapping.
        p = "P2"
    elif hot or (unknown and cvss >= 9.0):
        # UNKNOWN means we did not look, not that we are clean. A critical with
        # no QID mapping is a coverage gap, so it does not get to be P4.
        p = "P3"
    else:
        p = "P4"
    return p, "; ".join(why) or "no enrichment data available"


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Enrich CTI CVEs with NVD, EPSS and KEV.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--report", help="markdown report from cti-qualys-agent")
    src.add_argument("--cves", help="comma-separated CVE list (scout lane)")
    ap.add_argument("--out", required=True, help="output JSON path")
    ap.add_argument("--no-db", action="store_true", help="skip the SQLite upsert")
    ap.add_argument("--skip-nvd", action="store_true", help="EPSS + KEV only (fast)")
    args = ap.parse_args()

    meta = {}
    if args.report:
        findings = parse_report(args.report)
        meta = parse_meta(args.report)
        log(f"parsed {len(findings)} CVEs from {os.path.basename(args.report)}")
    else:
        findings = {c.strip().upper(): {"cve": c.strip().upper(), "status": "UNKNOWN",
                                        "provider": "scout", "qids": "", "host_count": 0,
                                        "qualys_score": 0, "last_seen": "",
                                        "sample_hosts": ""}
                    for c in args.cves.split(",") if CVE_RE.fullmatch(c.strip())}
        log(f"scoring {len(findings)} CVEs from --cves")

    if not findings:
        log("no CVEs to enrich - writing an empty result so the digest still runs")

    cves = sorted(findings)
    degraded = []
    nvd = {} if args.skip_nvd else fetch_nvd(cves)
    if not args.skip_nvd and not any(v.get("cvss") for v in nvd.values()) and cves:
        degraded.append("NVD")
    epss = fetch_epss(cves) if cves else {}
    if cves and not epss:
        degraded.append("EPSS")
    kev = fetch_kev()
    if not kev:
        degraded.append("KEV catalog")

    for cve, f in findings.items():
        f.update({k: v for k, v in (nvd.get(cve) or {}).items() if k != "kev_nvd"})
        f.update(epss.get(cve) or {})
        if cve in kev:
            f["kev"] = 1
            f.update(kev[cve])
        else:
            # NVD's flag is the fallback when the catalog fetch failed.
            f["kev"] = 1 if (nvd.get(cve) or {}).get("kev_nvd") else 0
        f["priority"], f["rationale"] = prioritize(f)

    order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    rows = sorted(findings.values(),
                  key=lambda f: (order[f["priority"]], -(f.get("host_count") or 0),
                                 -(f.get("epss") or 0), f["cve"]))

    counts = {p: sum(1 for f in rows if f["priority"] == p) for p in ("P1", "P2", "P3", "P4")}
    result = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_meta": meta,
        "counts": counts,
        "total": len(rows),
        "degraded": degraded,
        "findings": rows,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    log(f"wrote {args.out}  P1={counts['P1']} P2={counts['P2']} "
        f"P3={counts['P3']} P4={counts['P4']}"
        + (f"  DEGRADED: {', '.join(degraded)}" if degraded else ""))

    if not args.no_db and rows:
        db = os.path.join(FLEET_HOME, "bin", "fleet-db")
        if os.path.exists(db):
            try:
                subprocess.run([sys.executable, db, "finding", "upsert"],
                               input=json.dumps(rows), text=True, check=True,
                               stdout=subprocess.DEVNULL)
                log(f"upserted {len(rows)} findings to memory.db")
            except subprocess.CalledProcessError as e:
                log(f"db upsert failed ({e}) - JSON is still on disk")
    return 0


if __name__ == "__main__":
    sys.exit(main())
