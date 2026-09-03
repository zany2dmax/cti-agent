#!/usr/bin/env python3
"""brief.py - the @brief lane. Renders the enriched findings as an email digest.

Built for a phone screen at 6am: P1 first, host counts visible, action stated.
Inline CSS and a table layout because Outlook ignores most of everything else.

Usage:
  brief.py --daily  --enriched enriched.json --out digest.html
  brief.py --weekly --enriched enriched.json --out weekly.html
  brief.py --subject-only --enriched enriched.json
  brief.py --daily --enriched enriched.json --out d.html --text-out d.txt
"""
import argparse
import html
import json
import os
import re
import sys
from datetime import datetime, timezone

PRI = {
    "P1": ("#b3001b", "#fdecee", "Exploited AND present - act today"),
    "P2": ("#b25000", "#fff4e5", "Present in the environment - this patch cycle"),
    "P3": ("#8a6d00", "#fffbe6", "Not detected here - verify scan coverage"),
    "P4": ("#4a5568", "#f4f5f7", "Awareness only"),
}


def esc(v):
    return html.escape(str(v if v is not None else ""))


def subject(data, kind):
    c = data["counts"]
    day = datetime.now().strftime("%b %d")
    if c["P1"]:
        return (f"[P1] CTI {day}: {c['P1']} exploited vuln"
                f"{'s' if c['P1'] != 1 else ''} present in the environment")
    if c["P2"]:
        return f"CTI {day}: {c['P2']} confirmed present, no P1"
    if data["total"] == 0:
        return f"CTI {day}: no new CVEs in the last 24h"
    return f"CTI {day}: {data['total']} CVEs reviewed, nothing exploitable found"


def hosts_cell(f):
    hosts = [h.strip() for h in (f.get("sample_hosts") or "").split(",") if h.strip()]
    if not hosts:
        return "&mdash;"
    # A pseudonym is not a hostname and cannot be looked up anywhere. Label it,
    # or the reader wastes time searching the scanner for "host-69a692a2".
    pseudo = all(re.fullmatch(r"host-[0-9a-f]{8}", h) for h in hosts)
    # Dedupe but keep order - the raw report repeats hosts across QIDs.
    uniq, out = set(), []
    for h in hosts:
        if h.lower() not in uniq:
            uniq.add(h.lower())
            out.append(h)
    shown = ", ".join(esc(h) for h in out[:6])
    if len(out) > 6:
        shown += f" <span style='color:#718096'>+{len(out) - 6} more</span>"
    if pseudo:
        shown += ("  <span style='color:#b25000'>(pseudonymized &mdash; set "
                  "REPORT_HOSTNAMES=full for real names)</span>")
    return shown


def provider_reason_cell(f):
    """The scanner's own explanation, when it gave one.

    Shown separately from Hosts. These previously shared a column in the
    markdown report, so a sentence like "No Qualys KnowledgeBase CVE-to-QID
    mapping found" rendered as if it were a machine name.
    """
    reason = (f.get("provider_reason") or "").strip()
    if not reason:
        return ""
    return (f"<div style=\"font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,"
            f"Arial,sans-serif;color:#744210;background:#fffbe6;padding:6px 8px;"
            f"border-radius:3px;margin-top:6px\"><b>Scanner:</b> "
            f"{esc(reason)}</div>")


def qids_cell(f):
    """Render the scanner's own IDs.

    Without these the digest is not actionable: you cannot look a finding up in
    Qualys by CVE, only by QID. A long list gets truncated, but the count is
    always shown so it is obvious more exist.
    """
    raw = (f.get("qids") or "").strip()
    if not raw:
        return ""
    qids = [q.strip() for q in raw.split(",") if q.strip()]
    if not qids:
        return ""
    shown = ", ".join(esc(q) for q in qids[:8])
    extra = f" <span style='color:#718096'>+{len(qids) - 8} more</span>" if len(qids) > 8 else ""
    label = "QID" if len(qids) == 1 else f"QIDs ({len(qids)})"
    return (f"<div style=\"font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,"
            f"Arial,sans-serif;color:#4a5568;margin-top:4px\">"
            f"<b>{label}:</b> <span style='font-family:ui-monospace,SFMono-Regular,"
            f"Menlo,monospace'>{shown}</span>{extra}</div>")


def finding_block(f):
    color, bg, _ = PRI[f["priority"]]
    cve = esc(f["cve"])
    link = f"https://nvd.nist.gov/vuln/detail/{cve}"
    badges = []
    if f.get("kev"):
        due = f" &middot; due {esc(f['kev_due'])}" if f.get("kev_due") else ""
        badges.append(f"<span style='background:#b3001b;color:#fff;padding:2px 6px;"
                      f"border-radius:3px;font-size:11px;font-weight:700'>KEV{due}</span>")
    if str(f.get("ransomware", "")).lower() == "known":
        badges.append("<span style='background:#5b21b6;color:#fff;padding:2px 6px;"
                      "border-radius:3px;font-size:11px;font-weight:700'>RANSOMWARE</span>")
    if f.get("cvss"):
        badges.append(f"<span style='background:#e2e8f0;color:#1a202c;padding:2px 6px;"
                      f"border-radius:3px;font-size:11px'>CVSS {esc(f['cvss'])}"
                      f" {esc(f.get('cvss_severity') or '')}</span>")
    if f.get("epss") is not None:
        badges.append(f"<span style='background:#e2e8f0;color:#1a202c;padding:2px 6px;"
                      f"border-radius:3px;font-size:11px'>EPSS {f['epss']:.1%}</span>")
    st = f.get("status") or "UNKNOWN"
    st_color = {"PRESENT": "#b3001b", "NOT_PRESENT": "#2f855a"}.get(st, "#8a6d00")
    badges.append(f"<span style='background:{st_color};color:#fff;padding:2px 6px;"
                  f"border-radius:3px;font-size:11px;font-weight:700'>{esc(st)}</span>")

    return f"""
      <tr><td style="padding:0 0 14px 0">
        <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid {color};background:{bg};border-radius:0 4px 4px 0">
          <tr><td style="padding:12px 14px">
            <div style="font:700 15px -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
              <a href="{link}" style="color:{color};text-decoration:none">{cve}</a>
              <span style="color:#4a5568;font-weight:400">
                &middot; {esc(f.get('host_count') or 0)} host(s)</span>
            </div>
            <div style="margin:7px 0">{' '.join(badges)}</div>
            <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#1a202c;margin:6px 0">
              <b>Why it ranks here:</b> {esc(f.get('rationale'))}
            </div>
            <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#2d3748;margin:6px 0">
              {esc((f.get('description') or 'No NVD description available.')[:320])}
            </div>
            {qids_cell(f)}
            <div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#4a5568;margin-top:4px">
              <b>Hosts:</b> {hosts_cell(f)}
            </div>
            {provider_reason_cell(f)}
          </td></tr>
        </table>
      </td></tr>"""


def render(data, kind):
    c, meta = data["counts"], data.get("source_meta", {})
    findings = data["findings"]
    # P2 is capped on the daily because "present in the environment" is a large
    # set in a real estate - the top offenders by host count carry the message,
    # and the attached raw report has the rest.
    limits = {"daily": {"P1": 99, "P2": 12, "P3": 10, "P4": 0},
              "weekly": {"P1": 99, "P2": 40, "P3": 40, "P4": 25}}[kind]
    now = datetime.now().strftime("%A %d %B %Y, %H:%M %Z").strip()

    if c["P1"]:
        lead = (f"<b>{c['P1']} vulnerabilit{'y' if c['P1'] == 1 else 'ies'} "
                f"confirmed present in our environment and known to be exploited.</b> "
                f"These need attention today.")
        lead_bg, lead_border = "#fdecee", "#b3001b"
    elif c["P2"]:
        lead = (f"No actively-exploited vulnerabilities are present. "
                f"{c['P2']} confirmed present in the environment for this week's "
                f"patch cycle.")
        lead_bg, lead_border = "#fff4e5", "#b25000"
    elif data["total"] == 0:
        lead = ("No CVEs appeared in the threat-intel mailbox in this window. "
                "Nothing to action.")
        lead_bg, lead_border = "#f0fff4", "#2f855a"
    else:
        lead = (f"{data['total']} CVEs reviewed. None confirmed present in the "
                f"environment and none on the CISA KEV list. Nothing to action.")
        lead_bg, lead_border = "#f0fff4", "#2f855a"

    degraded = ""
    if data.get("degraded"):
        degraded = f"""
      <tr><td style="padding:0 0 14px 0">
        <div style="background:#fffbe6;border:1px solid #d69e2e;border-radius:4px;
                    padding:10px 12px;font:700 13px -apple-system,Segoe UI,Arial,sans-serif;
                    color:#744210">
          DEGRADED &mdash; these enrichment sources were unavailable this run:
          {esc(', '.join(data['degraded']))}. Priorities below may understate risk.
        </div></td></tr>"""

    tiles = "".join(
        f"""<td width="25%" align="center" style="background:{PRI[p][1]};
              border-top:3px solid {PRI[p][0]};padding:10px 4px">
              <div style="font:700 26px -apple-system,Segoe UI,Arial,sans-serif;
                          color:{PRI[p][0]}">{c[p]}</div>
              <div style="font:700 11px -apple-system,Segoe UI,Arial,sans-serif;
                          color:{PRI[p][0]};letter-spacing:.5px">{p}</div></td>"""
        for p in ("P1", "P2", "P3", "P4"))

    sections = []
    for p in ("P1", "P2", "P3", "P4"):
        group = [f for f in findings if f["priority"] == p]
        if not group or limits[p] == 0:
            continue
        shown, hidden = group[:limits[p]], max(0, len(group) - limits[p])
        more = (f"<tr><td style='font:400 12px -apple-system,Segoe UI,Arial,sans-serif;"
                f"color:#718096;padding:0 0 14px 2px'>+{hidden} more {p} "
                f"in the full report.</td></tr>") if hidden else ""
        sections.append(f"""
      <tr><td style="padding:6px 0 8px 0">
        <div style="font:700 13px -apple-system,Segoe UI,Arial,sans-serif;
                    color:{PRI[p][0]};letter-spacing:.6px;text-transform:uppercase;
                    border-bottom:2px solid {PRI[p][0]};padding-bottom:5px">
          {p} &mdash; {PRI[p][2]} ({len(group)})
        </div></td></tr>{''.join(finding_block(f) for f in shown)}{more}""")

    provenance = " &middot; ".join(filter(None, [
        f"Mailbox {esc(meta['mailbox'])}" if meta.get("mailbox") else "",
        f"{esc(meta['emails'])} emails inspected" if meta.get("emails") else "",
        f"Lookup: {esc(meta.get('provider', 'qualys'))}" if meta.get("provider") else "",
        f"Since {esc(meta['since'])[:16]}" if meta.get("since") else "",
    ]))

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(subject(data, kind))}</title></head>
<body style="margin:0;padding:0;background:#eef1f5">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation"
       style="background:#eef1f5"><tr><td align="center" style="padding:16px 8px">
<table width="640" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:640px;background:#fff;border-radius:6px;overflow:hidden">

  <tr><td style="background:#12203a;padding:16px 20px">
    <div style="font:700 17px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
      CTI {'Weekly' if kind == 'weekly' else 'Daily'} Brief</div>
    <div style="font:400 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;margin-top:3px">{esc(now)}</div></td></tr>

  <tr><td style="padding:16px 20px 0 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      <tr><td style="background:{lead_bg};border-left:4px solid {lead_border};
                     padding:12px 14px;font:400 14px/1.55 -apple-system,Segoe UI,
                     Helvetica,Arial,sans-serif;color:#1a202c">{lead}</td></tr>
    </table></td></tr>

  <tr><td style="padding:14px 20px 0 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      <tr>{tiles}</tr></table></td></tr>

  <tr><td style="padding:16px 20px 4px 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">
      {degraded}{''.join(sections)}
    </table></td></tr>

  <tr><td style="padding:8px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:400 11px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#718096">
      {provenance}<br>
      Presence is determined solely by the vulnerability lookup provider.
      Advisory text supplies urgency, never proof of exposure.
      <b>UNKNOWN</b> means no QID mapping existed &mdash; treat it as unverified
      coverage, not as clean.<br>
      Generated by the CTI agent fleet &middot; {esc(data['generated'])}
    </div></td></tr>

</table></td></tr></table></body></html>"""


def render_text(data, kind):
    c = data["counts"]
    lines = [subject(data, kind), "=" * 68, ""]
    lines.append(f"P1 {c['P1']}   P2 {c['P2']}   P3 {c['P3']}   P4 {c['P4']}"
                 f"   (total {data['total']})")
    if data.get("degraded"):
        lines += ["", f"DEGRADED - unavailable this run: {', '.join(data['degraded'])}"]
    lines.append("")
    for p in ("P1", "P2", "P3", "P4"):
        group = [f for f in data["findings"] if f["priority"] == p]
        if not group or (kind == "daily" and p == "P4"):
            continue
        lines += [f"{p} - {PRI[p][2]} ({len(group)})", "-" * 68]
        for f in group[: 99 if p in ("P1", "P2") else 10]:
            lines.append(f"  {f['cve']}  {f.get('status')}  "
                         f"{f.get('host_count') or 0} host(s)")
            lines.append(f"    {f.get('rationale')}")
        lines.append("")
    lines.append("Presence determined solely by the vulnerability lookup provider.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Render the CTI digest.")
    ap.add_argument("--enriched", required=True)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--daily", action="store_const", const="daily", dest="kind")
    g.add_argument("--weekly", action="store_const", const="weekly", dest="kind")
    ap.add_argument("--subject-only", action="store_true")
    ap.add_argument("--out")
    ap.add_argument("--text-out")
    args = ap.parse_args()
    kind = args.kind or "daily"

    with open(args.enriched) as f:
        data = json.load(f)
    data.setdefault("counts", {p: 0 for p in ("P1", "P2", "P3", "P4")})
    data.setdefault("findings", [])
    data.setdefault("total", len(data["findings"]))
    data.setdefault("generated", datetime.now(timezone.utc).isoformat(timespec="seconds"))

    if args.subject_only:
        print(subject(data, kind))
        return 0
    if not args.out:
        print("--out is required unless --subject-only", file=sys.stderr)
        return 2

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(render(data, kind))
    print(f"[brief] wrote {args.out} ({kind}) "
          f"P1={data['counts']['P1']} P2={data['counts']['P2']}", file=sys.stderr)
    if args.text_out:
        with open(args.text_out, "w") as f:
            f.write(render_text(data, kind))
        print(f"[brief] wrote {args.text_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
