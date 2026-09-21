#!/usr/bin/env python3
"""brief.py - the @brief lane. Renders the enriched findings as an email digest.

Built for a phone screen at 6am: Sev5 first, host counts visible, action stated.
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
# Sev5 (highest) down to Sev1. Deliberately NOT P1-P4: that is the
# incident-reporting scale here, and a CTI digest labelled "P1" reads as a
# live incident to anyone on the rota. The direction is inverted too - Sev5 is
# the urgent end, where P1 used to be.
#
# Five bands rather than four because the old P2 and P3 each mixed a confirmed
# finding with an unverified one, which forced the heading to claim presence
# the scanner had not established. Separating them lets every label be true on
# its own.
SEV_ORDER = ("Sev5", "Sev4", "Sev3", "Sev2", "Sev1")
PRI = {
    "Sev5": ("#b3001b", "#fdecee",
             "Exploited AND confirmed present - act today"),
    "Sev4": ("#b25000", "#fff4e5",
             "Confirmed present, not known to be exploited - this patch cycle"),
    "Sev3": ("#8a6d00", "#fffbe6",
             "Exploited, coverage UNVERIFIED - we cannot say whether we are exposed"),
    "Sev2": ("#2c5282", "#ebf4ff",
             "Exploited but not detected here, or unverified critical - verify coverage"),
    "Sev1": ("#4a5568", "#f4f5f7", "Awareness only"),
}

# With five bands each label is already honest, so these are explanations of
# *why a band exists*, not corrections to a misleading heading.
# How many rows of each band the digest lists, per kind. 0 means no section
# at all - the band's number still appears in the count tiles at the top of
# the email and in the text header, which is the whole of what an awareness
# item warrants.
#
# THE RULE, FROM THE OPERATOR
#
# The email says "we have this, it is risky, you should know". Anything that is
# not that is a number. Sev1 is awareness only, so it gets a count and no
# prose - listing 25 of them in the weekly was padding, and a large weekly
# earns a mail rule pointing at Trash. That rule cannot tell a Sev5 from a
# Sev1, so padding the weekly costs the Sev5s their audience. The cheapest way
# to make this whole system useless is to make it boring.
#
# Sev5 is deliberately uncapped. If thirty CVEs are both actively exploited and
# on our machines, truncating that list is not a formatting decision.
#
# Both renderers read this table. They used not to: render_text had its own
# hardcoded caps and would print 99 Sev4 rows where the HTML printed 12, so the
# plain-text alternative - which is what some clients show - was the wordier of
# the two.
ROW_LIMITS = {
    "daily":  {"Sev5": 99, "Sev4": 12, "Sev3": 12, "Sev2": 10, "Sev1": 0},
    "weekly": {"Sev5": 99, "Sev4": 15, "Sev3": 15, "Sev2": 12, "Sev1": 0},
}

MIXED_NOTE = {
    "Sev3": ("These are being actively exploited and the scanner has no QID "
             "mapping for them, so it could not tell us whether we are exposed. "
             "That is not a confirmed exposure and it is not a clean result "
             "&mdash; it means nobody looked. Below Sev4 because a gap may "
             "turn out to be nothing, but well above the awareness floor, "
             "because it may equally turn out to be everything."),
    "Sev2": ("<b>NOT_PRESENT</b> rows were checked and the scanner found "
             "nothing. <b>UNKNOWN</b> rows were not checked. Both warrant a "
             "look at scan coverage rather than a patch."),
}


def band_needs_caveat(group):
    """True when a band contains any unverified row.

    Sev3 is entirely unverified by definition, so it always carries its note.
    Sev2 mixes NOT_PRESENT with UNKNOWN, so the note only appears when an
    UNKNOWN is actually in it - a caveat printed every day stops being read on
    the day it matters.
    """
    return any((f.get("status") or "UNKNOWN") == "UNKNOWN" for f in group)


def esc(v):
    return html.escape(str(v if v is not None else ""))


def safe_link_url(raw):
    """Return raw only if it is safe to put in an href, else "".

    This digest is rendered as HTML in Outlook. A scheme other than http or
    https in an href - javascript:, data:, file: - is at best broken and at
    worst a payload, and the value arrives from a config file an installer
    writes. The Go renderer applies the same rule in
    internal/patchtuesday.safeLinkURL; the two emails must not disagree about
    what counts as a link.
    """
    raw = (raw or "").strip()
    m = re.match(r"^(https?)://([^\s/?#]+)", raw, re.I)
    return raw if m else ""


def attribution():
    """The credit line at the foot of the digest, from the environment.

    Configured, not hardcoded. This kit was deliberately genericised - no
    organisation name, no addresses, no internal identifiers - and baking one
    team's wording and one GitHub URL into the shipped renderer would undo
    that. Returns (text, url); ("", "") renders nothing, so a fresh install
    advertises nobody.

    The default text is used only when a URL was given: somebody who sets a
    repo link wants the credit, somebody who sets neither has asked for
    neither.
    """
    text = (os.environ.get("FLEET_ATTRIBUTION") or "").strip()
    raw = (os.environ.get("FLEET_REPO_URL") or "").strip()
    url = safe_link_url(raw)
    if raw and not url:
        # Do not drop it silently. A footer link that vanished because of a
        # typo is the kind of thing nobody notices for months.
        print(f"[brief] ignoring FLEET_REPO_URL={raw!r} - only http:// and "
              f"https:// are rendered as links", file=sys.stderr)
    if not text and not url:
        return "", ""
    if not text:
        org = os.environ.get("FLEET_ORG", "Security")
        text = f"Correlated and published by the {org} Claude Code Agent Fleet"
    return text, url


def subject(data, kind):
    c = data["counts"]
    day = datetime.now().strftime("%b %d")
    kev = data.get("kev_deadlines") or {}
    overdue = kev.get("overdue") or 0
    # The deadline rides along; it does not displace the severity. Sev5 means
    # actively exploited and present, which outranks a published date on
    # something less severe - and a subject line that leads with OVERDUE while
    # a Sev5 sits unmentioned buries the more urgent fact.
    tail = ""
    if overdue:
        tail = (f" — {overdue} KEV deadline{'s' if overdue != 1 else ''} OVERDUE")

    if c.get("Sev5"):
        return (f"[Sev5] CTI {day}: {c['Sev5']} exploited vuln"
                f"{'s' if c['Sev5'] != 1 else ''} present in the environment{tail}")
    if overdue:
        # No Sev5, but something is past a federal due date - still worth the
        # prefix, because it is the most actionable thing in the mail.
        return (f"[OVERDUE] CTI {day}: {overdue} CISA KEV deadline"
                f"{'s' if overdue != 1 else ''} passed, worst by "
                f"{kev.get('worst_overdue_days', 0)}d")
    # Count what the scanner actually confirmed. The bands now separate
    # confirmed from unverified, but the subject still counts rows rather than
    # bands - it is the one part of the digest everyone reads, and it should
    # not need a lookup table to interpret.
    findings = data.get("findings") or []
    present = sum(1 for f in findings
                  if f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0)
    unverified = sum(1 for f in findings
                     if f.get("status") == "UNKNOWN"
                     and f.get("priority") in ("Sev3", "Sev2"))

    if present:
        s = f"CTI {day}: {present} confirmed present, no Sev5"
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

    # The lookback is a time window, so anything still being discussed
    # reappears every run. Without this a reader cannot tell the third day of
    # one finding from three new ones. is_new is None when there was no
    # findings history to compare against, in which case say nothing rather
    # than implying novelty either way.
    if f.get("is_new") is True:
        badges.append("<span style='background:#12203a;color:#fff;padding:2px 6px;"
                      "border-radius:3px;font-size:11px;font-weight:700'>NEW</span>")
    elif f.get("is_new") is False and f.get("first_seen"):
        badges.append(f"<span style='background:#edf2f7;color:#4a5568;padding:2px 6px;"
                      f"border-radius:3px;font-size:11px'>since "
                      f"{esc(str(f['first_seen'])[:10])}</span>")

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


def subjects_section(data):
    """List the email subjects the ingest pass read.

    Answers "what did it actually look at?" - the question the old single
    "emails inspected" count invited and could not answer. Subjects with a CVE
    are marked, so the gap between mail volume and finding volume is visible
    rather than implied.

    Subjects can carry vendor and product names. That is a lower sensitivity
    than the hostnames already in this digest, but it is another reason the
    report is internal-only.
    """
    subs = data.get("email_subjects") or []
    if not subs:
        return ""
    rows = []
    for e in subs[:60]:
        subj = (e.get("subject") or "(no subject)").strip() or "(no subject)"
        has = e.get("has_cve")
        mark = ("<span style='color:#b3001b;font-weight:700'>CVE</span>"
                if has else "<span style='color:#a0aec0'>&mdash;</span>")
        when = esc((e.get("received") or "")[:16].replace("T", " "))
        rows.append(
            f"<tr><td style=\"padding:3px 8px 3px 0;white-space:nowrap;"
            f"vertical-align:top\">{mark}</td>"
            f"<td style=\"padding:3px 8px 3px 0;white-space:nowrap;color:#718096;"
            f"vertical-align:top\">{when}</td>"
            f"<td style=\"padding:3px 0;color:#2d3748\">{esc(subj)}</td></tr>")
    more = ""
    if len(subs) > 60:
        more = (f"<div style='color:#718096;margin-top:6px'>"
                f"+{len(subs) - 60} more in the attached raw report</div>")
    n_cve = sum(1 for e in subs if e.get("has_cve"))
    return f"""
  <tr><td style="padding:4px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;
                color:#4a5568;margin:12px 0 8px 0;letter-spacing:.5px">
      EMAILS READ THIS RUN &mdash; {len(subs)} total, {n_cve} mentioning a CVE</div>
    <table cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">
      {''.join(rows)}
    </table>{more}
  </td></tr>"""


def render(data, kind):
    c, meta = data["counts"], data.get("source_meta", {})
    findings = data["findings"]
    limits = ROW_LIMITS[kind]
    now = datetime.now().strftime("%A %d %B %Y, %H:%M %Z").strip()
    # Whose digest this is. Named in the header and the footer so a forwarded
    # copy is still identifiable, and so nobody mistakes it for a vendor
    # newsletter. Generic default keeps the kit reusable.
    org = os.environ.get("FLEET_ORG", "Security")

    # The footer credit. Falls back to the wording this digest has always
    # carried when nothing is configured, so an install that sets neither
    # variable keeps its line rather than losing one.
    attr_text, attr_url = attribution()
    if attr_text and attr_url:
        credit_html = (f'<a href="{esc(attr_url)}" style="color:#9fb0cc">'
                       f'{esc(attr_text)}</a>')
    elif attr_text:
        credit_html = esc(attr_text)
    else:
        credit_html = f"Generated by the {esc(org)} CTI agent fleet"

    # The lead has to count what the scanner confirmed, not the size of a
    # severity band. The bands now separate confirmed from unverified, but the
    # lead still counts rows: it is the first line anyone reads and should not
    # require knowing what a band contains.
    rows = data.get("findings") or []
    n_present = sum(1 for f in rows
                    if f.get("status") == "PRESENT" and (f.get("host_count") or 0) > 0)
    n_unverified = sum(1 for f in rows if f.get("status") == "UNKNOWN"
                       and f.get("priority") in ("Sev3", "Sev2"))
    unverified_clause = ""
    if n_unverified:
        unverified_clause = (
            f" A further {n_unverified} exploited CVE"
            f"{'s' if n_unverified != 1 else ''} could not be checked against "
            f"the scanner at all &mdash; unverified coverage, not a clean result.")

    if c.get("Sev5"):
        lead = (f"<b>{c['Sev5']} vulnerabilit{'y' if c['Sev5'] == 1 else 'ies'} "
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
        f"""<td width="20%" align="center" style="background:{PRI[p][1]};
              border-top:3px solid {PRI[p][0]};padding:10px 4px">
              <div style="font:700 24px -apple-system,Segoe UI,Arial,sans-serif;
                          color:{PRI[p][0]}">{c.get(p, 0)}</div>
              <div style="font:700 11px -apple-system,Segoe UI,Arial,sans-serif;
                          color:{PRI[p][0]};letter-spacing:.5px">{p}</div></td>"""
        for p in SEV_ORDER)

    sections = []
    for p in SEV_ORDER:
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

    # "N emails inspected" was read as "N emails brought new CVE information".
    # It meant neither: it counted every message in the window, and the window
    # is time-based so the same mail is re-read on every run. Say which number
    # this is, and report novelty separately from volume.
    nv = data.get("novelty") or {}
    if nv.get("undetermined"):
        novelty_txt = "new vs previously reported: no history yet"
    elif nv.get("new") is not None:
        novelty_txt = (f"{nv.get('new', 0)} new, "
                       f"{nv.get('seen_before', 0)} previously reported")
    else:
        novelty_txt = ""

    provenance = " &middot; ".join(filter(None, [
        f"Mailbox {esc(meta['mailbox'])}" if meta.get("mailbox") else "",
        (f"{esc(meta['emails'])} emails in the lookback window"
         if meta.get("emails") else ""),
        f"{esc(meta['with_cves'])} mentioned a CVE" if meta.get("with_cves") else "",
        novelty_txt,
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
    <div style="font:700 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;letter-spacing:1.2px;text-transform:uppercase">
      {esc(org)}</div>
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

{subjects_section(data)}
  <tr><td style="padding:8px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:400 11px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#718096">
      {provenance}<br>
      Presence is determined solely by the vulnerability lookup provider.
      Advisory text supplies urgency, never proof of exposure.
      <b>UNKNOWN</b> means no QID mapping existed &mdash; treat it as unverified
      coverage, not as clean.<br>
      {credit_html} &middot; {esc(data['generated'])}
    </div></td></tr>

</table></td></tr></table></body></html>"""


def render_text(data, kind):
    c = data["counts"]
    lines = [subject(data, kind), "=" * 68, ""]
    lines.append("   ".join(f"{p} {c.get(p, 0)}" for p in SEV_ORDER)
                 + f"   (total {data['total']})")
    if data.get("degraded"):
        lines += ["", f"DEGRADED - unavailable this run: {', '.join(data['degraded'])}"]
    nov = data.get("novelty") or {}
    if nov.get("undetermined"):
        lines += ["", "NEW vs SEEN: undetermined - no findings history yet"]
    elif nov.get("new") is not None:
        lines += ["", f"NEW since last run: {nov.get('new', 0)}"
                      f"   previously reported: {nov.get('seen_before', 0)}"]
        if nov.get("new_cves"):
            lines.append(f"  new: {', '.join(nov['new_cves'][:10])}")
    kev = data.get("kev_deadlines") or {}
    if kev.get("overdue") or kev.get("due_within_14d"):
        lines += ["", f"CISA KEV: {kev.get('overdue', 0)} OVERDUE"
                      f" (worst by {kev.get('worst_overdue_days', 0)}d),"
                      f" {kev.get('due_within_14d', 0)} due within 14d"]
        if kev.get("overdue_cves"):
            lines.append(f"  overdue: {', '.join(kev['overdue_cves'][:8])}")
    lines.append("")
    limits = ROW_LIMITS[kind]
    for p in SEV_ORDER:
        group = [f for f in data["findings"] if f["priority"] == p]
        if not group or limits[p] == 0:
            continue
        lines += [f"{p} - {PRI[p][2]} ({len(group)})", "-" * 68]
        if p in MIXED_NOTE and band_needs_caveat(group):
            lines.append("  NOTE: UNKNOWN rows below are unverified coverage, "
                         "not confirmed exposure.")
        for f in group[:limits[p]]:
            lines.append(f"  {f['cve']}  {f.get('status')}  "
                         f"{f.get('host_count') or 0} host(s)")
            lines.append(f"    {f.get('rationale')}")
        # Truncation is stated, as it is in the HTML. A list that silently
        # stops is one the reader believes is complete.
        if len(group) > limits[p]:
            lines.append(f"  +{len(group) - limits[p]} more {p} in the full report.")
        lines.append("")
    lines.append("Presence determined solely by the vulnerability lookup provider.")
    lines.append("UNKNOWN means the scanner had no mapping - not that we are clean.")
    attr_text, attr_url = attribution()
    if attr_text:
        lines.append("")
        lines.append(attr_text)
        # The URL on its own line, because a text-only reader cannot follow an
        # anchor and a wrapped link is one nobody clicks.
        if attr_url:
            lines.append(attr_url)
    else:
        lines.append("")
        lines.append(f"Generated by the {os.environ.get('FLEET_ORG', 'Security')} "
                     f"CTI agent fleet.")
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
    data.setdefault("counts", {p: 0 for p in SEV_ORDER})
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
    # The `+` is load-bearing. Without it Python concatenates the two adjacent
    # string literals FIRST - the f-string and the " " separator - and then
    # calls .join() on the result, so the message itself becomes the separator
    # between the five counts:
    #
    #   Sev5=3[brief] wrote ....html (daily)  Sev4=0[brief] wrote ....html ...
    #
    # Valid Python, no warning, and the operator's run log reads as though the
    # lane wrote the file four times.
    print(f"[brief] wrote {args.out} ({kind}) "
          + " ".join(f"{p}={data['counts'].get(p, 0)}" for p in SEV_ORDER),
          file=sys.stderr)
    if args.text_out:
        with open(args.text_out, "w") as f:
            f.write(render_text(data, kind))
        print(f"[brief] wrote {args.text_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
