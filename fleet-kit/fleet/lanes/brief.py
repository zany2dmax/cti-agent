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

# Band labels must not claim more than the scanner said.
#
# P2 and P3 each contain two different kinds of finding. P2 is "PRESENT" plus
# "UNKNOWN and actively exploited"; P3 is "exploited but NOT_PRESENT" plus
# "UNKNOWN with a critical CVSS". Labelling P2 "Present in the environment"
# printed a header asserting presence directly above rows whose own status
# read UNKNOWN - the one claim this system exists not to make. A reader who
# notices the contradiction stops trusting the report; one who does not
# notice acts on a presence that was never established.
PRI = {
    "P1": ("#b3001b", "#fdecee",
           "Exploited AND confirmed present - act today"),
    "P2": ("#b25000", "#fff4e5",
           "Confirmed present, or exploited and coverage unverified - this patch cycle"),
    "P3": ("#8a6d00", "#fffbe6",
           "Not detected, or coverage unverified - check the scanner reaches it"),
    "P4": ("#4a5568", "#f4f5f7", "Awareness only"),
}

# Per-band note explaining the mixed contents, shown under the heading
# whenever the band holds any unverified row. A band that is entirely PRESENT
# carries no caveat, because a caveat that appears every day stops being read
# on the day it matters.
MIXED_NOTE = {
    "P2": ("Rows marked <b>UNKNOWN</b> are here because the scanner has no "
           "QID mapping for them and they are being actively exploited. That is "
           "not a confirmed exposure &mdash; it means coverage could not be "
           "established. Treat them as unresolved questions, not as findings."),
    "P3": ("Rows marked <b>UNKNOWN</b> were not checked, not cleared. "
           "<b>NOT_PRESENT</b> rows were checked and the scanner found nothing."),
}


def band_needs_caveat(group):
    """True when a band contains any unverified row.

    An earlier version fired only when the band was *mixed*, which got the
    worst case exactly backwards: a P2 that is entirely UNKNOWN needs the
    caveat more than one where a confirmed finding sits beside it, not less.
    """
    return any((f.get("status") or "UNKNOWN") == "UNKNOWN" for f in group)


def esc(v):
    return html.escape(str(v if v is not None else ""))


def subject(data, kind):
    c = data["counts"]
    day = datetime.now().strftime("%b %d")
    kev = data.get("kev_deadlines") or {}
    overdue = kev.get("overdue") or 0
    # The deadline rides along; it does not displace the priority. P1 means
    # actively exploited and present, which outranks a published date on
    # something less severe - and a subject line that leads with OVERDUE while
    # a P1 sits unmentioned buries the more urgent fact.
    tail = ""
    if overdue:
        tail = (f" — {overdue} KEV deadline{'s' if overdue != 1 else ''} OVERDUE")

    if c["P1"]:
        return (f"[P1] CTI {day}: {c['P1']} exploited vuln"
                f"{'s' if c['P1'] != 1 else ''} present in the environment{tail}")
    if overdue:
        # No P1, but something is past a federal due date - still worth the
        # prefix, because it is the most actionable thing in the mail.
        return (f"[OVERDUE] CTI {day}: {overdue} CISA KEV deadline"
                f"{'s' if overdue != 1 else ''} passed, worst by "
                f"{kev.get('worst_overdue_days', 0)}d")
    # Count what the scanner actually confirmed, not the size of the P2 band.
    # P2 also holds UNKNOWN findings that are being exploited, so "N confirmed
    # present" was wrong whenever the band was wholly or partly unverified -
    # and a subject line is the one part of the digest everyone reads.
    findings = data.get("findings") or []
    present = sum(1 for f in findings
                  if f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0)
    unverified = sum(1 for f in findings
                     if f.get("status") == "UNKNOWN" and f.get("priority") in ("P2", "P3"))

    if present:
        s = f"CTI {day}: {present} confirmed present, no P1"
        if unverified:
            s += f", {unverified} unverified"
        return s
    if unverified:
        # Nothing confirmed, but coverage gaps on things being exploited. Say
        # exactly that rather than implying either a clean day or an exposure.
        return (f"CTI {day}: 0 confirmed present, {unverified} exploited CVE"
                f"{'s' if unverified != 1 else ''} the scanner could not check")
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

    # The lead has to count what the scanner confirmed, not the size of a
    # priority band. P2 holds both PRESENT findings and UNKNOWN ones that are
    # being exploited, so "N confirmed present" was false whenever the band
    # was partly or wholly unverified - and this is the first line anyone
    # reads.
    rows = data.get("findings") or []
    n_present = sum(1 for f in rows
                    if f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0)
    n_unverified = sum(1 for f in rows if f.get("status") == "UNKNOWN"
                       and f.get("priority") in ("P2", "P3"))
    unverified_clause = ""
    if n_unverified:
        unverified_clause = (
            f" A further {n_unverified} exploited CVE"
            f"{'s' if n_unverified != 1 else ''} could not be checked against "
            f"the scanner at all &mdash; unverified coverage, not a clean result.")

    if c["P1"]:
        lead = (f"<b>{c['P1']} vulnerabilit{'y' if c['P1'] == 1 else 'ies'} "
                f"confirmed present in our environment and known to be exploited.</b> "
                f"These need attention today.{unverified_clause}")
        lead_bg, lead_border = "#fdecee", "#b3001b"
    elif n_present:
        lead = (f"No actively-exploited vulnerabilities are confirmed present. "
                f"{n_present} confirmed present in the environment for this "
                f"week's patch cycle.{unverified_clause}")
        lead_bg, lead_border = "#fff4e5", "#b25000"
    elif n_unverified:
        # Nothing confirmed, but coverage gaps on things being exploited. This
        # is neither a clean day nor a confirmed exposure, and saying either
        # would be wrong. Amber, because it is a question, not a finding.
        lead = (f"<b>Nothing confirmed present in the environment.</b> But "
                f"{n_unverified} actively-exploited CVE"
                f"{'s' if n_unverified != 1 else ''} could not be checked "
                f"against the scanner &mdash; there is no QID mapping for "
                f"{'them' if n_unverified != 1 else 'it'}. That means we did "
                f"not look, not that we are clean. Resolving the coverage gap "
                f"is the action here.")
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

    # KEV deadlines. One band, above the priority tiles, and only when there is
    # something to act on - a banner that says "nothing overdue" every morning
    # is a banner nobody reads by Thursday.
    kevd = data.get("kev_deadlines") or {}
    kev_banner = ""
    if kevd.get("overdue"):
        _cves = ", ".join(kevd.get("overdue_cves", [])[:6])
        _more = len(kevd.get("overdue_cves", [])) - 6
        kev_banner = f"""
      <tr><td style="padding:0 0 14px 0">
        <div style="background:#fff5f5;border:1px solid #c53030;border-radius:4px;
                    padding:10px 12px;font:400 13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                    color:#742a2a">
          <b>{kevd['overdue']} CISA KEV remediation deadline{
              's' if kevd['overdue'] != 1 else ''} passed</b>
          &mdash; worst by {kevd.get('worst_overdue_days', 0)} days.
          These are present in the environment and past a published federal
          due date: {esc(_cves)}{f' +{_more} more' if _more > 0 else ''}.
        </div></td></tr>"""
    elif kevd.get("due_within_14d"):
        kev_banner = f"""
      <tr><td style="padding:0 0 14px 0">
        <div style="background:#fffaf0;border:1px solid #dd6b20;border-radius:4px;
                    padding:10px 12px;font:400 13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                    color:#7b341e">
          {kevd['due_within_14d']} CISA KEV deadline{
              's' if kevd['due_within_14d'] != 1 else ''} fall due within 14 days
          on vulnerabilities present here.
        </div></td></tr>"""
    degraded += kev_banner

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
        note = ""
        if p in MIXED_NOTE and band_needs_caveat(group):
            note = f"""
      <tr><td style="padding:0 0 6px 0">
        <div style="font:400 12px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                    color:#4a5568;background:#f7fafc;border-left:3px solid {PRI[p][0]};
                    padding:7px 10px">{MIXED_NOTE[p]}</div></td></tr>"""
        sections.append(f"""
      <tr><td style="padding:6px 0 8px 0">
        <div style="font:700 13px -apple-system,Segoe UI,Arial,sans-serif;
                    color:{PRI[p][0]};letter-spacing:.6px;text-transform:uppercase;
                    border-bottom:2px solid {PRI[p][0]};padding-bottom:5px">
          {p} &mdash; {PRI[p][2]} ({len(group)})
        </div></td></tr>{note}{''.join(finding_block(f) for f in shown)}{more}""")

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
    kev = data.get("kev_deadlines") or {}
    if kev.get("overdue") or kev.get("due_within_14d"):
        lines += ["", f"CISA KEV: {kev.get('overdue', 0)} OVERDUE"
                      f" (worst by {kev.get('worst_overdue_days', 0)}d),"
                      f" {kev.get('due_within_14d', 0)} due within 14d"]
        if kev.get("overdue_cves"):
            lines.append(f"  overdue: {', '.join(kev['overdue_cves'][:8])}")
    lines.append("")
    for p in ("P1", "P2", "P3", "P4"):
        group = [f for f in data["findings"] if f["priority"] == p]
        if not group or (kind == "daily" and p == "P4"):
            continue
        lines += [f"{p} - {PRI[p][2]} ({len(group)})", "-" * 68]
        if p in MIXED_NOTE and band_needs_caveat(group):
            lines.append("  NOTE: UNKNOWN rows below are unverified coverage, "
                         "not confirmed exposure.")
        for f in group[: 99 if p in ("P1", "P2") else 10]:
            lines.append(f"  {f['cve']}  {f.get('status')}  "
                         f"{f.get('host_count') or 0} host(s)")
            lines.append(f"    {f.get('rationale')}")
        lines.append("")
    lines.append("Presence determined solely by the vulnerability lookup provider.")
    lines.append("UNKNOWN means the scanner had no mapping - not that we are clean.")
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
