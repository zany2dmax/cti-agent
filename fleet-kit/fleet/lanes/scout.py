#!/usr/bin/env python3
"""scout.py - the @scout lane.

Polls vendor advisories and industry feeds for CVE IDs, dedupes against what we
have already seen, and hands the genuinely new ones back so they can be run
through the same Qualys lookup path as mailbox CVEs.

This lane finds candidates. It never decides exposure - only the vulnerability
lookup provider does that.

Usage:
  scout.py --out ~/fleet/state/scout-2026-08-18.json
  scout.py --out scout.json --feeds ~/fleet/lanes/feeds.txt --days 3
  scout.py --out scout.json --print-new    # bare CVE list for piping to enrich

Stdlib only - xml.etree instead of feedparser so there is nothing to pip install.
"""
import argparse
import json
import os
import re
import sqlite3
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from html import unescape

FLEET_HOME = os.environ.get("FLEET_HOME", os.path.expanduser("~/fleet"))
DB = os.path.join(FLEET_HOME, "state", "memory.db")
DEFAULT_FEEDS = os.path.join(FLEET_HOME, "lanes", "feeds.txt")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TAG_RE = re.compile(r"<[^>]+>")
UA = os.environ.get("FLEET_USER_AGENT", "cti-fleet-scout/1.0")


def log(m):
    print(f"[scout] {m}", file=sys.stderr)


def fetch(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
        })
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ssl.create_default_context()) as r:
            return r.read()
    except Exception as e:                                      # noqa: BLE001
        log(f"FEED FAIL {url} :: {e}")
        return None


def strip_ns(tag):
    return tag.split("}", 1)[-1] if "}" in tag else tag


def text_of(el):
    return unescape(TAG_RE.sub(" ", "".join(el.itertext()))) if el is not None else ""


def parse_date(raw):
    if not raw:
        return None
    raw = raw.strip()
    try:
        return parsedate_to_datetime(raw)                        # RFC 822 (RSS)
    except Exception:                                           # noqa: BLE001
        pass
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))  # ISO (Atom)
    except Exception:                                           # noqa: BLE001
        return None


def parse_feed(raw, url):
    """Handle RSS 2.0 and Atom without a dependency."""
    items = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        log(f"PARSE FAIL {url} :: {e}")
        return items

    entries = [e for e in root.iter() if strip_ns(e.tag) in ("item", "entry")]
    for e in entries:
        fields = {}
        for child in e:
            fields.setdefault(strip_ns(child.tag), child)
        title = text_of(fields.get("title")).strip()
        link = ""
        le = fields.get("link")
        if le is not None:
            link = (le.get("href") or le.text or "").strip()
        published = parse_date(
            text_of(fields.get("pubDate")) or text_of(fields.get("published"))
            or text_of(fields.get("updated")) or text_of(fields.get("date")))
        body = " ".join(text_of(fields.get(k)) for k in
                        ("description", "summary", "content", "encoded"))
        items.append({"title": title[:300], "link": link,
                      "published": published.isoformat() if published else None,
                      "text": f"{title} {body}"})
    return items


def known_cves(conn):
    seen = set()
    for table, col in (("findings", "cve"), ("scout_items", "cve")):
        try:
            for (c,) in conn.execute(f"SELECT {col} FROM {table} WHERE {col} IS NOT NULL"):
                seen.add(c.upper())
        except sqlite3.Error:
            pass
    return seen


def main():
    ap = argparse.ArgumentParser(description="Poll CTI feeds for new CVE IDs.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--feeds", default=DEFAULT_FEEDS)
    ap.add_argument("--days", type=int, default=3,
                    help="ignore entries older than this (default 3)")
    ap.add_argument("--print-new", action="store_true",
                    help="print new CVEs comma-separated on stdout")
    ap.add_argument("--no-db", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.feeds):
        log(f"no feed list at {args.feeds}")
        return 1
    with open(args.feeds) as f:
        feeds = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    log(f"polling {len(feeds)} feeds, window {args.days}d")

    conn = None
    seen = set()
    if not args.no_db and os.path.exists(DB):
        conn = sqlite3.connect(DB)
        conn.execute("PRAGMA busy_timeout=5000")
        seen = known_cves(conn)
        log(f"{len(seen)} CVEs already known")

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    hits, failed, ok = {}, [], 0

    for url in feeds:
        raw = fetch(url)
        if raw is None:
            failed.append(url)
            continue
        items = parse_feed(raw, url)
        if not items:
            failed.append(url)
            continue
        ok += 1
        for it in items:
            pub = parse_date(it["published"])
            if pub and pub.astimezone(timezone.utc) < cutoff:
                continue
            for cve in {c.upper() for c in CVE_RE.findall(it["text"])}:
                rec = hits.setdefault(cve, {"cve": cve, "sources": []})
                rec["sources"].append({"feed": url, "title": it["title"],
                                       "link": it["link"], "published": it["published"]})

    new = sorted(c for c in hits if c not in seen)
    log(f"{ok}/{len(feeds)} feeds ok, {len(failed)} failed, "
        f"{len(hits)} CVEs mentioned, {len(new)} new")
    if failed:
        log("failed feeds (a silently dead feed is a blind spot): "
            + ", ".join(urllib.parse.urlparse(f).netloc or f for f in failed))

    if conn:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for cve in hits:
            for s in hits[cve]["sources"][:3]:
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO scout_items"
                        "(cve,feed,title,link,published,correlated,ts) "
                        "VALUES(?,?,?,?,?,0,?)",
                        (cve, s["feed"], s["title"], s["link"], s["published"], ts))
                except sqlite3.Error as e:
                    log(f"db insert failed for {cve}: {e}")
        conn.commit()
        conn.close()

    result = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feeds_polled": len(feeds), "feeds_ok": ok, "feeds_failed": failed,
        "window_days": args.days,
        "new_cves": new,
        "all_mentioned": sorted(hits),
        "detail": [hits[c] for c in new],
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    log(f"wrote {args.out}")

    if args.print_new:
        print(",".join(new))
    return 0


if __name__ == "__main__":
    sys.exit(main())
