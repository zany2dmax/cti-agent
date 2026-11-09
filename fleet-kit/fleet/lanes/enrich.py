#!/usr/bin/env python3
"""enrich.py - the @enrich lane.

Takes the CVEs the Go agent found (or an explicit list) and layers on the
context that decides whether anyone should care:

  * NVD 2.0    - CVSS v3.1 base score, severity, description, KEV flag
  * FIRST EPSS - probability of exploitation in the next 30 days
  * CISA KEV   - known-exploited flag, due date, ransomware association

Then it assigns a Sev5-Sev1 severity that combines *exploitability in the wild*
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
# Beside the enriched file it describes, where brief.py looks for it.
PRODUCTS_NAME = "products.json"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = ("https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json")

# Severity bands, most urgent first. Defined once here; brief.py mirrors it
# for rendering, and fleet-db migrates stored values to match.
SEV_ORDER = ("Sev5", "Sev4", "Sev3", "Sev2", "Sev1")

# \d{4,}: the CVE ID sequence number has a four-digit minimum and no maximum.
# Used with fullmatch below, so the old upper bound of 7 rejected a longer ID
# outright and the row was skipped without comment.
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
# The agent carries the fleet's mailbox as a contact, read from fleet.env at
# run time so the public repo never holds the address: a publisher who sees
# our polling can write to us instead of blocking us. Never a browser's agent.
# Mirrors internal/useragent; test_lanes checks the lanes agree.
_MAILBOX_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def user_agent(product, env=os.environ):
    ua = (env.get("FLEET_USER_AGENT") or "").strip()
    if not ua or "\r" in ua or "\n" in ua:
        ua = product
    contact = (env.get("GRAPH_MAILBOX") or "").strip()
    if "(" in ua or not _MAILBOX_RE.fullmatch(contact):
        return ua
    return f"{ua} (+mailto:{contact})"


UA = user_agent("cti-agent-enrich/1.0")

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
            # Every URL is an https constant (NVD, EPSS, KEV, ...).
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:  # nosec B310
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
    except Exception:                                           # noqa: BLE001  # nosec B110
        pass                                  # no usable cache: fetch fresh
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
             Last Seen | Sample Hosts | Reason | Detection Titles

    Detection Titles (the scanner's own names for the detections, joined
    with " ; ") was added last, so a report without it still parses.
    Cells are split on unescaped pipes: the agent writes a pipe inside a
    cell as \\|, and a plain split would shift every column after it.

    Older reports combined the last two into "Sample Hosts / Reason", so a
    diagnostic sentence could end up in the hosts field. Both layouts are
    accepted; the 8-column form routes that cell by whether the lookup
    actually found hosts.
    """
    findings = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|") or line.startswith("|---") or "| CVE |" in line:
                continue
            body = line[1:-1] if line.endswith("|") and not line.endswith("\\|") else line[1:]
            cells = [c.strip().replace("\\|", "|")
                     for c in re.split(r"(?<!\\)\|", body)]
            if len(cells) < 8 or not CVE_RE.fullmatch(cells[0]):
                continue
            cve = cells[0].upper()

            def as_int(v):
                try:
                    return int(v or 0)
                except ValueError:
                    return 0

            host_count = as_int(cells[4])
            if len(cells) >= 9:
                hosts, reason = cells[7], cells[8]
            else:
                # Legacy single column: it holds hosts only when the provider
                # actually returned some, otherwise it is the reason text.
                hosts = cells[7] if host_count > 0 else ""
                reason = "" if host_count > 0 else cells[7]

            findings[cve] = {
                "cve": cve,
                "status": cells[1] or "UNKNOWN",
                "provider": cells[2] or "unknown",
                "qids": cells[3],
                "host_count": host_count,
                "qualys_score": as_int(cells[5]),
                "last_seen": cells[6],
                "sample_hosts": hosts,
                "provider_reason": reason,
                "detection_titles": [t.strip() for t in
                                     (cells[9] if len(cells) >= 10 else "").split(" ; ")
                                     if t.strip()],
            }
    return findings


def parse_subjects(path):
    """Read the 'Emails read this run' table the agent appends.

    Columns: CVE? | Received | Subject. Absent in reports from before this
    existed, in which case the digest simply omits the section.
    """
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return out
    if "## Emails read this run" not in text:
        return out
    block = text.split("## Emails read this run", 1)[1]
    for line in block.split("\n"):
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0] == "CVE?":
            continue
        out.append({
            "has_cve": cells[0].lower() == "yes",
            "received": cells[1],
            # The writer escapes pipes; undo that for display.
            "subject": cells[2].replace("\\|", "|"),
        })
    return out


def parse_meta(path):
    """Pull the header facts so the digest can state its own provenance."""
    meta = {}
    pats = {
        "mailbox": r"Mailbox:\s*`([^`]+)`",
        "since": r"Lookback since:\s*`([^`]+)`",
        # Both spellings: "Emails inspected" was the old single, misleading
        # count; the agent now writes three separately-labelled numbers.
        "emails": r"Emails (?:in window|inspected):\s*`([^`]+)`",
        "with_cves": r"Emails mentioning a CVE:\s*`([^`]+)`",
        "cves_found": r"Distinct CVEs extracted:\s*`([^`]+)`",
        "provider": r"Lookup provider:\s*`([^`]+)`",
        "generated": r"Generated:\s*`([^`]+)`",
    }
    try:
        with open(path, encoding="utf-8") as f:
            head = f.read(4000)
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
    # An entry cached before "cpe_products" existed is stale: without it the
    # product line would read "not identified" for up to a week when NVD
    # actually knows the answer.
    stale = [c for c in cves if c not in cache or "cpe_products" not in cache[c]]
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
                 "kev_nvd": False, "vuln_status": None, "published": None,
                 "cpe_products": []}
        if data and data.get("vulnerabilities"):
            v = data["vulnerabilities"][0].get("cve", {})
            entry["cpe_products"] = cpe_products(v)
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


# --------------------------------------------------------------- product name
#
# "Which product is this about?" - Chrome, Safari, PHP - on every finding and
# fleet ticket. Three sources the fleet already has, in order of trust:
#
#   1. The CISA KEV catalog's vendorProject and product: one clean name,
#      written by a person, e.g. "Google" / "Chromium V8".
#   2. NVD's CPE configuration: the vulnerable products as vendor:product
#      pairs, e.g. cpe:2.3:a:google:chrome. Missing for a CVE NVD has not
#      analysed yet, which is common in its first weeks.
#   3. The scanner's own detection titles, from the report's last column:
#      "Google Chrome Prior to 131.0 Multiple Vulnerabilities". The scanner's
#      name for what is installed here, cut down to the product.
#
# When neither has an answer the product is "" and the email says "product
# not identified". Nothing guesses one from the description text.

# CPE names are lower case. These words read as acronyms; the rest are
# capitalised. A wrong case here is cosmetic, never a wrong product.
_CPE_UPPER = {"php", "http", "https", "ssh", "ssl", "tls", "sql", "iis", "dns",
              "vpn", "api", "os", "xml", "pdf", "smb", "rdp", "ldap", "nas",
              "jdk", "jre", "ftp", "cms", "ip", "wan", "lan", "ui", "bios",
              "uefi", "vm", "esxi", "nfs", "snmp", "ntp", "ssl_vpn"}
_CPE_NAMES = {"macos": "macOS", "mac_os_x": "macOS", "iphone_os": "iOS",
              "ipados": "iPadOS", "watchos": "watchOS", "tvos": "tvOS",
              "visionos": "visionOS", "node.js": "Node.js"}
PRODUCT_MAX = 3   # name this many, then "+N more"


def _cpe_unescape(s):
    """CPE 2.3 escapes punctuation with a backslash: node\\.js -> node.js."""
    return re.sub(r"\\(.)", r"\1", s or "")


def _cpe_words(s):
    if s in _CPE_NAMES:
        return _CPE_NAMES[s]
    words = [w for w in re.split(r"[_\s]+", s) if w]
    return " ".join(w.upper() if w.lower() in _CPE_UPPER
                    else (w[:1].upper() + w[1:]) for w in words)


def product_name(vendor, product):
    """One readable name from a vendor and a product.

    The vendor is dropped when the product already starts with it, so
    php:php reads "PHP" and Microsoft / "Microsoft Exchange Server" does not
    say Microsoft twice.
    """
    v = " ".join((vendor or "").split())
    p = " ".join((product or "").split())
    if not p:
        return v
    if not v or p.lower().startswith(v.lower()):
        return p
    return f"{v} {p}"


def cpe_products(nvd_cve):
    """Vulnerable (vendor, product) pairs from an NVD CVE record, in order.

    Only cpeMatch entries marked vulnerable count. The others say what the
    product runs on ("Chrome on Windows"), and naming Windows for a Chrome
    bug would send the reader to the wrong machines.
    """
    seen, out = set(), []
    for conf in nvd_cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                # cpe:2.3:<part>:<vendor>:<product>:... An escaped colon
                # (\:) inside a field is rare enough that a split is fine:
                # the worst case is an odd-looking name, not a wrong one.
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 5 or parts[0] != "cpe":
                    continue
                pair = (_cpe_unescape(parts[3]), _cpe_unescape(parts[4]))
                if pair in seen or "*" in pair or "-" in pair or "" in pair:
                    continue
                seen.add(pair)
                out.append(list(pair))
    return out


# A scanner title names the product, then says what is wrong with it:
#   "Google Chrome Prior to 131.0 Multiple Vulnerabilities"
#   "PHP Multiple Vulnerabilities (8.3.14)"
#   "Red Hat Update for kernel (RHSA-2026:1234)"
#   "Microsoft Windows Security Update for November 2026"
# The product is the part before the first of these words. A title that does
# not split cleanly gives no name rather than a long or odd one.
_TITLE_FOR = re.compile(
    r"^(?P<who>.+?)\s+(?:Security\s+)?(?:Updates?|Notification|Advisory|Patch)"
    r"\s+for\s+(?P<what>.+)$", re.I)
_TITLE_CUT = re.compile(
    r"\s+(?:Prior\s+to\b|Before\b|Versions?\b|Multiple\b|Remote\b|Security\b|"
    r"Cumulative\b|Critical\b|Denial\b|Information\b|Privilege\b|Elevation\b|"
    r"Arbitrary\b|Cross[- ]Site\b|SQL\s+Injection\b|Buffer\b|Heap\b|Stack\b|"
    r"Use[- ]After[- ]Free\b|Out[- ]of[- ]Bounds\b|Type\s+Confusion\b|Integer\b|"
    r"Command\s+Injection\b|Path\s+Traversal\b|Authentication\b|Unspecified\b|"
    r"Vulnerabilit|Update\b|Patch\b|\(|-\s|:)", re.I)
_DATEISH = re.compile(r"^(?:January|February|March|April|May|June|July|August|"
                      r"September|October|November|December|\d)", re.I)
TITLE_PRODUCT_MAX = 60


def product_from_title(title):
    """The product named in a scanner detection title, or ""."""
    t = " ".join(str(title or "").split())
    if not t:
        return ""
    m = _TITLE_FOR.match(t)
    if m:
        who, what = m.group("who").strip(), _TITLE_CUT.split(m.group("what"), 1)[0].strip()
        # "Red Hat Update for kernel" is about the kernel, as Red Hat ships
        # it; "Microsoft Windows Security Update for November 2026" is about
        # Windows.
        name = who if (not what or _DATEISH.match(what)) else f"{what} ({who})"
    else:
        name = _TITLE_CUT.split(t, 1)[0].strip()
    name = name.strip(" -,:")
    if len(name) < 2 or len(name) > TITLE_PRODUCT_MAX or _DATEISH.match(name):
        return ""
    return name


def product_for(f):
    """(product, source) for an enriched finding; ("", "") when unknown.

    CISA KEV, then NVD, then the scanner's detection titles.
    """
    name = product_name(f.get("kev_vendor"), f.get("kev_product"))
    if name:
        return name, "CISA KEV"
    names = []
    for pair in f.get("cpe_products") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        n = product_name(_cpe_words(pair[0]), _cpe_words(pair[1]))
        if n and n not in names:
            names.append(n)
    source = "NVD"
    if not names:
        for t in f.get("detection_titles") or []:
            n = product_from_title(t)
            if n and n not in names:
                names.append(n)
        prov = str(f.get("provider") or "").strip()
        source = "Qualys" if prov.lower() == "qualys" else (prov or "scanner")
    if not names:
        return "", ""
    shown = ", ".join(names[:PRODUCT_MAX])
    if len(names) > PRODUCT_MAX:
        shown += f" +{len(names) - PRODUCT_MAX} more"
    return shown, source


def save_products(findings, kev, path):
    """Remember each CVE's product name, for tickets whose CVE is not in
    today's mail.

    The FLEET TICKETS section lists every open ticket, most of them for CVEs
    that are not in today's findings, and the NVD cache is thrown away weekly.
    This map is what lets brief.py name the product for those: every KEV
    entry (most fleet tickets are KEV), plus each finding's own answer.
    Merged, never pruned: one short line per CVE.
    """
    known = load_cache(path, timedelta(days=36500)) or {}
    before = dict(known)
    for cve, v in (kev or {}).items():
        name = product_name(v.get("kev_vendor"), v.get("kev_product"))
        if name:
            known[cve] = name
    for f in findings:
        if f.get("product"):
            known[f["cve"]] = f["product"]
    if known != before:
        save_cache(path, known)


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


def kev_days_left(f, today=None):
    """Days until the CISA KEV remediation deadline; negative means overdue.

    CISA publishes a dueDate with every KEV entry under BOD 22-01. Federal
    agencies are bound by it; everyone else gets a published, defensible date
    that someone else set - which is far more useful in a patching argument
    than an internal opinion about severity.

    Returns None when there is no date to compare, rather than guessing zero:
    "no deadline" and "due today" are opposite facts.
    """
    raw = (f.get("kev_due") or "").strip()
    if not raw:
        return None
    try:
        due = datetime.strptime(raw[:10], "%Y-%m-%d").date()
    except ValueError:
        # CISA has been consistent about ISO dates, but a malformed one must
        # not take down enrichment for every other finding.
        return None
    return (due - (today or datetime.now(timezone.utc).date())).days


def fleet_db_candidates():
    """Where fleet-db might be, most specific first.

    FLEET_CODE is the answer on both layouts when it is set; the FLEET_HOME
    fallback only works on the single-directory layout, which is why relying
    on it alone silently disabled the upsert under FHS.
    """
    out = []
    code = os.environ.get("FLEET_CODE")
    if code:
        out.append(os.path.join(code, "bin", "fleet-db"))
    out.append(os.path.join(FLEET_HOME, "bin", "fleet-db"))
    # Alongside this lane: lanes/ and bin/ are siblings in both layouts.
    out.append(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "bin", "fleet-db"))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def find_fleet_db():
    for p in fleet_db_candidates():
        if os.path.exists(p):
            return p
    return None


def mark_novelty(findings):
    """Flag each finding as new or previously seen, before the upsert.

    Answers the question a daily digest should lead with: what changed since
    yesterday? The lookback is a time window, so a CVE still being discussed
    reappears every run - without this, a reader cannot tell three weeks of
    the same finding from three weeks of fresh ones.

    Read directly rather than through fleet-db: sqlite3 is stdlib, the query
    is one statement, and it has to happen BEFORE the upsert or every CVE
    looks old. Failure is non-fatal - an unknown novelty flag is better than
    no digest.
    """
    import sqlite3
    path = os.path.join(STATE, "memory.db")
    for f in findings.values():
        f["is_new"] = None          # None = could not determine
        f["first_seen"] = None
    if not os.path.exists(path):
        return 0, 0, len(findings)
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            rows = dict(con.execute(
                "SELECT cve, first_seen FROM findings").fetchall())
        finally:
            con.close()
    except Exception as e:                                      # noqa: BLE001
        log(f"novelty check skipped ({e})")
        return 0, 0, len(findings)

    new = seen = 0
    for cve, f in findings.items():
        if cve in rows:
            f["is_new"] = False
            f["first_seen"] = rows[cve]
            seen += 1
        else:
            f["is_new"] = True
            new += 1
    return new, seen, 0


def kev_summary(rows):
    """Deadline rollup over findings that are actually in the estate.

    Every count here is restricted to PRESENT, because a deadline on a CVE we
    do not run is not an obligation. Reporting those inflates the number and
    the first time someone checks one and finds it irrelevant, the whole
    section stops being read.
    """
    present = [f for f in rows
               if f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0
               and f.get("kev_days_left") is not None]
    overdue = [f for f in present if f["kev_days_left"] < 0]
    soon = [f for f in present if 0 <= f["kev_days_left"] <= 14]
    return {
        "overdue": len(overdue),
        "due_within_14d": len(soon),
        "worst_overdue_days": max((-f["kev_days_left"] for f in overdue), default=0),
        "ransomware_present": sum(
            1 for f in present if str(f.get("ransomware", "")).lower() == "known"),
        "overdue_cves": [f["cve"] for f in overdue],
    }


def fetch_kev():
    """Bulk KEV catalog. NVD already flags KEV membership, but the catalog is
    the only place with the remediation due date and ransomware association."""
    cache = load_cache(KEV_CACHE, timedelta(hours=KEV_TTL_HOURS))
    # A cache written before kev_vendor existed is refetched once, or the
    # product names would be missing until it expired.
    if cache and any("kev_vendor" in v for v in cache.values()):
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
                "kev_vendor": v.get("vendorProject"),
                "kev_product": v.get("product"),
            }
    log(f"KEV: {len(kev)} entries (catalog {data.get('catalogVersion')})")
    save_cache(KEV_CACHE, kev)
    return kev


# -------------------------------------------------------------------- scoring

def prioritize(f, today=None):
    """Combine exploitability with presence, on a Sev5-Sev1 scale.

    The whole point: a 10.0 CVSS on software we do not run is noise, and a 6.5
    that is being actively exploited on 300 of our hosts is an emergency. CVSS
    alone gets that backwards, which is why it is the tiebreaker and not the
    driver.

    Sev5 - PRESENT and actively exploited (KEV or EPSS >= 10%)  -> today
    Sev4 - PRESENT, not known to be exploited                   -> this patch cycle
    Sev3 - exploited AND coverage UNVERIFIED                    -> resolve coverage now
    Sev2 - exploited but NOT_PRESENT, or unverified CVSS >= 9   -> verify coverage
    Sev1 - everything else                                     -> awareness

    WHY SEV AND NOT P1-P4
    This deliberately does not use P1-P4: that is the incident-reporting scale
    here, and a CTI digest arriving labelled "P1" reads as a live incident to
    anyone on the rota. Different scale, different meaning, no collision. Note
    the direction is inverted too - Sev5 is the most urgent, where P1 was.

    WHY FIVE BANDS
    Sev5/Sev4 and Sev3/Sev2 used to be two bands, and each conflated a
    confirmed finding with an unverified one. The digest then printed "present
    in the environment" as a heading above rows whose own status read UNKNOWN.
    Separating them means the band itself carries an honest claim, so no
    caveat is needed to undo the heading.

    Sev4 above Sev3 is the deliberate part, and it is a judgement call.
    "We definitely have it, nobody is exploiting it" ranks above "it is being
    exploited and we cannot tell whether we have it", because certainty of
    presence is bounded, assignable work while an unverified finding may turn
    out not to affect us at all. Ranking every coverage gap above every
    confirmed exposure would fill the top of the digest with questions instead
    of tasks.

    What Sev3 must never be is the noise floor. An exploited CVE the scanner
    could not check is not a clean result - it means nobody looked - so it sits
    in the middle of the scale where it gets read, not at the bottom with
    awareness items. That was the whole reason the old P2 band was split.

    Presence alone still earns Sev4 regardless of CVSS. A 5.5 on 186 hosts is a
    real patching obligation; ranking it below a 9.3 we do not run inverts the
    thing this scoring exists to fix.
    """
    present = f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0
    unknown = f.get("status") == "UNKNOWN"
    kev = bool(f.get("kev"))
    epss = f.get("epss") or 0
    cvss = f.get("cvss") or 0
    hot = kev or epss >= 0.10
    very_hot = kev or epss >= 0.50

    days = kev_days_left(f, today)
    f["kev_days_left"] = days

    why = []
    if kev:
        # The deadline only means anything for something we actually have.
        # "Overdue" on a CVE that is not in the estate is noise, and the kind
        # of noise that makes people stop reading deadline language entirely.
        if days is not None and present:
            if days < 0:
                why.append(f"CISA KEV deadline PASSED {-days}d ago ({f['kev_due']})")
            elif days == 0:
                why.append(f"CISA KEV deadline is TODAY ({f['kev_due']})")
            elif days <= 14:
                why.append(f"CISA KEV due in {days}d ({f['kev_due']})")
            else:
                why.append(f"on CISA KEV, due {f['kev_due']}")
        elif days is not None:
            why.append(f"on CISA KEV (due {f['kev_due']}, not detected here)")
        else:
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
        p = "Sev5"
    elif present:
        p = "Sev4"
    elif unknown and very_hot:
        # Being exploited, and the scanner could not tell us whether we are
        # exposed. Mid-scale on purpose: below confirmed presence, because a
        # gap may turn out to be nothing, but nowhere near the awareness floor,
        # because "we did not look" is not "we are clean".
        p = "Sev3"
    elif hot or (unknown and cvss >= 9.0):
        # UNKNOWN means we did not look, not that we are clean. A critical with
        # no QID mapping is a coverage gap, so it does not sink to Sev1.
        p = "Sev2"
    else:
        p = "Sev1"
    return p, "; ".join(why) or "no enrichment data available"


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Enrich CTI CVEs with NVD, EPSS and KEV.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--report", help="markdown report from cti-agent")
    src.add_argument("--cves", help="comma-separated CVE list (scout lane)")
    ap.add_argument("--out", required=True, help="output JSON path")
    ap.add_argument("--no-db", action="store_true", help="skip the SQLite upsert")
    ap.add_argument("--skip-nvd", action="store_true", help="EPSS + KEV only (fast)")
    args = ap.parse_args()

    # Initialised for both branches: the scout lane passes --cves and has no
    # mailbox pass, so there are no subjects to list.
    meta, subjects = {}, []
    if args.report:
        findings = parse_report(args.report)
        meta = parse_meta(args.report)
        subjects = parse_subjects(args.report)
        log(f"parsed {len(findings)} CVEs from {os.path.basename(args.report)}")
    else:
        findings = {c.strip().upper(): {"cve": c.strip().upper(), "status": "UNKNOWN",
                                        "provider": "scout", "qids": "", "host_count": 0,
                                        "qualys_score": 0, "last_seen": "",
                                        "sample_hosts": "", "provider_reason": ""}
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
        f["product"], f["product_source"] = product_for(f)

    # Before the upsert, or everything looks previously-seen.
    n_new, n_seen, n_unknown = mark_novelty(findings)
    if n_unknown:
        log(f"novelty: unknown for {n_unknown} finding(s) - no findings "
            f"database yet, so the first run cannot distinguish new from old")
    else:
        log(f"novelty: {n_new} new, {n_seen} seen before")

    # Urgency order for sorting, highest first.
    order = {p: i for i, p in enumerate(SEV_ORDER)}

    def rank(f):
        """Sort within a priority band.

        Host count stays the primary tiebreaker. An earlier cut of this put
        overdue-ness first, which pushed a 40-host P1 below a 4-host P1 - the
        same inversion as the CVSS-gated P2 bug this scoring exists to fix.
        Blast radius is the risk; a deadline is an obligation about that risk,
        and an obligation does not make a small exposure into a big one.

        Lateness breaks ties *after* host count, so two equally widespread
        findings are separated by which one someone external can ask about.
        The deadline still leads the digest subject and its own banner, and
        cti-kev orders by lateness - the compliance view lives where
        compliance questions get answered.
        """
        present = f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0
        days = f.get("kev_days_left")
        overdue = 0 if (days is None or not present or days >= 0) else -days
        return (order[f["priority"]], -(f.get("host_count") or 0), -overdue,
                -(f.get("epss") or 0), f["cve"])

    rows = sorted(findings.values(), key=rank)
    products_path = os.path.join(os.path.dirname(os.path.abspath(args.out)), PRODUCTS_NAME)
    try:
        save_products(rows, kev, products_path)
    except OSError as e:
        # A missing product map costs a name in FLEET TICKETS, nothing else.
        log(f"WARNING: could not update {products_path} ({e})")

    counts = {p: sum(1 for f in rows if f["priority"] == p) for p in SEV_ORDER}
    result = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_meta": meta,
        "counts": counts,
        "total": len(rows),
        "degraded": degraded,
        # Deadline summary, computed once here so the digest, the weekly and
        # cti-kev all report the same numbers rather than each deriving them.
        "kev_deadlines": kev_summary(rows),
        # What the ingest pass actually read. Listed in the digest so the
        # email count can be checked rather than taken on trust.
        "email_subjects": subjects,
        # What changed since the last run. None for new/seen means there was
        # no history to compare against - the digest must say "unknown", not
        # imply everything is new.
        "novelty": {
            "new": n_new, "seen_before": n_seen, "undetermined": n_unknown,
            "new_cves": [f["cve"] for f in rows if f.get("is_new")],
        },
        "findings": rows,
    }

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    log(f"wrote {args.out}  "
        + " ".join(f"{p}={counts[p]}" for p in SEV_ORDER)
        + (f"  DEGRADED: {', '.join(degraded)}" if degraded else ""))

    if not args.no_db and rows:
        # bin/ lives under FLEET_CODE, not FLEET_HOME. On the FHS layout those
        # are /opt/cti-agent and /var/lib/cti-agent, so the old
        # FLEET_HOME/bin/fleet-db never existed - and because the check was a
        # silent os.path.exists, every run skipped the upsert without saying
        # so. The findings database stayed empty while the digest looked fine.
        db = find_fleet_db()
        if db:
            try:
                # argv is this interpreter and fleet-db's own path.
                subprocess.run([sys.executable, db, "finding", "upsert"],  # nosec B603
                               input=json.dumps(rows), text=True, check=True,
                               stdout=subprocess.DEVNULL)
                log(f"upserted {len(rows)} findings to memory.db")
            except subprocess.CalledProcessError as e:
                log(f"db upsert failed ({e}) - JSON is still on disk")
        else:
            # Loud, not silent. Without the upsert there is no history, so
            # nothing can tell a new CVE from one reported every day this week.
            log("WARNING: fleet-db not found - findings were NOT written to "
                "memory.db, so 'new since last run' cannot be computed. "
                f"Looked in: {', '.join(fleet_db_candidates())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
