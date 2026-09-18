package patchtuesday

import (
	"fmt"
	"html"
	"strings"
)

// Report is everything the email needs: the public synopsis plus our exposure.
type Report struct {
	Digest   *Digest
	Exposure Exposure
	Org      string

	// QQL is what the reader should paste into Qualys. Preference order:
	// QIDs with live detections here, then whatever the Qualys post published,
	// then a CVE-list fallback. The first is the most useful because it
	// returns our machines, not every machine in the world.
	QQL       string
	QQLSource string

	// Highlights are the CVEs confirmed present, enriched with severity where
	// the enrich lane supplied it.
	Highlights []Highlight
}

// Highlight is one CVE that is actually in the estate.
type Highlight struct {
	CVE       string
	Sev       string // Sev5..Sev1 from the enrich lane, blank if unavailable
	Hosts     int
	QIDs      []int
	KEV       bool
	EPSS      float64
	CVSS      float64
	Rationale string
}

// ChooseQQL picks the query to publish and records why.
func (r *Report) ChooseQQL(detected []int) {
	switch {
	case len(detected) > 0:
		r.QQL = QQLForQIDs(detected)
		r.QQLSource = fmt.Sprintf(
			"built from the %d QID(s) with open detections in our environment", len(detected))
	case len(r.Digest.SourceQQL) > 0:
		r.QQL = r.Digest.SourceQQL[0]
		r.QQLSource = "published by Qualys in this month's review (verbatim)"
	case len(r.Digest.CVEs) > 0:
		r.QQL = QQLForCVEs(r.Digest.CVEs)
		r.QQLSource = "CVE-based fallback - no QID mapping available yet"
	}
}

func e(s string) string { return html.EscapeString(s) }

// Subject matches what has gone out by hand for months, so the thread and any
// mail rules that key on it keep working.
func (r *Report) Subject() string {
	base := fmt.Sprintf("Microsoft Patch Tuesday for %s",
		MonthLabel(r.Digest.Year, r.Digest.Month))
	if n := len(r.Exposure.PresentCVEs); n > 0 {
		return fmt.Sprintf("%s - %d present in our environment", base, n)
	}
	return base
}

// HTML renders the email. Table layout and inline CSS, same as the digest,
// because Outlook ignores most of everything else.
func (r *Report) HTML() string {
	d := r.Digest
	var b strings.Builder

	num := func(n int) string {
		if n == 0 {
			return "not stated in the sources"
		}
		return fmt.Sprintf("<b>%d</b>", n)
	}

	b.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title></head>
<body style="margin:0;padding:0;background:#eef1f5">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
       style="background:#eef1f5"><tr><td align="center" style="padding:16px 8px">
<table width="680" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:680px;background:#fff;border-radius:6px;overflow:hidden">

  <tr><td style="background:#12203a;padding:16px 20px">
    <div style="font:700 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;letter-spacing:1.2px;text-transform:uppercase">%s</div>
    <div style="font:700 18px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
      Microsoft Patch Tuesday &mdash; %s</div>
    <div style="font:400 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;margin-top:3px">Released %s</div></td></tr>
`, e(r.Subject()), e(r.Org), e(MonthLabel(d.Year, d.Month)),
		PatchTuesday(d.Year, d.Month).Format("Monday 2 January 2006")))

	// Degraded banner first: a synopsis assembled from one source instead of
	// two is still useful, but the reader has to know which.
	if deg := d.Degraded(); len(deg) > 0 {
		b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:14px 20px 0 20px">
    <div style="background:#fffbe6;border:1px solid #d69e2e;border-radius:4px;
                padding:10px 12px;font:400 13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                color:#744210">
      <b>Incomplete sources.</b> Could not read: %s. Counts below may be
      missing or low. The exposure figures come from Qualys and are unaffected.
    </div></td></tr>`, e(strings.Join(deg, "; "))))
	}

	// The lead. Microsoft's numbers, then ours, then the query.
	b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:16px 20px 0 20px">
    <div style="font:400 15px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a202c">
      This month's release addresses %s vulnerabilities, including %s critical
      and %s important-severity vulnerabilities.</div>`,
		num(d.Total), num(d.Critical), num(d.Important)))

	b.WriteString(fmt.Sprintf(`
    <div style="margin:12px 0 0 0;padding:12px 14px;background:#fdecee;
                border-left:4px solid #b3001b;font:700 15px/1.55 -apple-system,
                Segoe UI,Helvetica,Arial,sans-serif;color:#1a202c">%s</div>`,
		e(r.Exposure.ExposureLine(r.Org))))

	if r.QQL != "" {
		b.WriteString(fmt.Sprintf(`
    <div style="font:400 14px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#1a202c;margin:12px 0 6px 0">
      You can use the following QQL to query for it yourself
      <span style="color:#718096;font-size:12px">(%s)</span>:</div>
    <div style="font:400 13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
                background:#f4f5f7;border:1px solid #e2e8f0;border-radius:4px;
                padding:10px 12px;color:#1a202c;word-break:break-word;
                white-space:pre-wrap">%s</div>`, e(r.QQLSource), e(r.QQL)))
	}
	b.WriteString("\n  </td></tr>\n")

	// Highlights: the CVEs actually here. This is the section that makes the
	// email ours rather than a forwarded blog post.
	if len(r.Highlights) > 0 {
		b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:18px 20px 0 20px">
    <div style="font:700 13px -apple-system,Segoe UI,Arial,sans-serif;color:#b3001b;
                letter-spacing:.6px;text-transform:uppercase;
                border-bottom:2px solid #b3001b;padding-bottom:5px">
      Present in our environment &mdash; %d of this release's CVEs</div>
    <table width="100%%" cellpadding="6" cellspacing="0" role="presentation"
           style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                  margin-top:8px;border-collapse:collapse">
      <tr style="background:#f4f5f7">
        <th align="left" style="border-bottom:1px solid #e2e8f0">CVE</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">Sev</th>
        <th align="right" style="border-bottom:1px solid #e2e8f0">Hosts</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">QIDs</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">Why</th></tr>`,
			len(r.Highlights)))
		for _, h := range r.Highlights {
			flags := []string{}
			if h.KEV {
				flags = append(flags, "<b style='color:#b3001b'>KEV</b>")
			}
			if h.EPSS > 0 {
				flags = append(flags, fmt.Sprintf("EPSS %.0f%%", h.EPSS*100))
			}
			if h.CVSS > 0 {
				flags = append(flags, fmt.Sprintf("CVSS %.1f", h.CVSS))
			}
			why := h.Rationale
			if why == "" {
				why = strings.Join(flags, " &middot; ")
			}
			qids := "&mdash;"
			if len(h.QIDs) > 0 {
				ps := make([]string, 0, len(h.QIDs))
				for _, q := range h.QIDs {
					ps = append(ps, fmt.Sprint(q))
				}
				qids = strings.Join(ps, ", ")
			}
			sev := h.Sev
			if sev == "" {
				sev = "&mdash;"
			}
			b.WriteString(fmt.Sprintf(`
      <tr><td style="border-bottom:1px solid #edf2f7">
            <a href="https://nvd.nist.gov/vuln/detail/%s" style="color:#1a202c">%s</a></td>
          <td style="border-bottom:1px solid #edf2f7"><b>%s</b></td>
          <td align="right" style="border-bottom:1px solid #edf2f7">%d</td>
          <td style="border-bottom:1px solid #edf2f7;font:400 12px ui-monospace,
                     SFMono-Regular,Menlo,monospace">%s</td>
          <td style="border-bottom:1px solid #edf2f7;color:#4a5568">%s</td></tr>`,
				e(h.CVE), e(h.CVE), sev, h.Hosts, qids, why))
		}
		b.WriteString("\n    </table></td></tr>\n")
	}

	// Coverage caveat. An unmapped CVE is not an absent one, and this email
	// would otherwise imply the difference away.
	if n := len(r.Exposure.UnmappedCVEs); n > 0 {
		stale := ""
		if r.Exposure.KBStale {
			stale = " The KnowledgeBase cache is stale, so treat all of these as unverified."
		}
		b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:14px 20px 0 20px">
    <div style="background:#fffbe6;border-left:4px solid #d69e2e;padding:10px 12px;
                font:400 13px/1.55 -apple-system,Segoe UI,Arial,sans-serif;color:#744210">
      <b>%d of this release's CVEs have no Qualys QID mapping.</b> That is not
      the same as not being present &mdash; it means coverage could not be
      established for them.%s</div></td></tr>`, n, stale))
	}

	// The narrative fields, each omitted when the sources did not carry it.
	sect := func(title, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:16px 20px 0 20px">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;color:#4a5568;
                letter-spacing:.5px;text-transform:uppercase;margin-bottom:5px">%s</div>
    <div style="font:400 14px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#2d3748">%s</div></td></tr>`, e(title), body))
	}

	sect("Zero-days", e(d.ZeroDayText))
	if d.EdgeFixes > 0 {
		sect("Microsoft Edge", fmt.Sprintf(
			"Microsoft has addressed <b>%d</b> vulnerabilities in Microsoft Edge "+
				"(Chromium-based) patched earlier this month.", d.EdgeFixes))
	}
	if len(d.Products) > 0 {
		sect("Products covered", e(strings.Join(d.Products, ", "))+", and more.")
	}

	if len(d.Categories) > 0 {
		var rows strings.Builder
		for _, c := range d.Categories {
			rows.WriteString(fmt.Sprintf(
				`<tr><td style="border-bottom:1px solid #edf2f7;padding:5px 8px">%s</td>`+
					`<td align="right" style="border-bottom:1px solid #edf2f7;padding:5px 8px">%d</td>`+
					`<td style="border-bottom:1px solid #edf2f7;padding:5px 8px">%s</td></tr>`,
				e(c.Name), c.Quantity, e(c.Severities)))
		}
		b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:16px 20px 0 20px">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;color:#4a5568;
                letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px">
      %s vulnerabilities by category</div>
    <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
           style="font:400 13px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                  border-collapse:collapse">
      <tr style="background:#f4f5f7">
        <th align="left" style="padding:5px 8px;border-bottom:1px solid #e2e8f0">Category</th>
        <th align="right" style="padding:5px 8px;border-bottom:1px solid #e2e8f0">Qty</th>
        <th align="left" style="padding:5px 8px;border-bottom:1px solid #e2e8f0">Severities</th></tr>
      %s
    </table></td></tr>`, e(MonthLabel(d.Year, d.Month)), rows.String()))
	}

	sect("Adobe", e(d.AdobeText))

	// Sources, always - a synopsis that does not say where it came from cannot
	// be checked, and this one is assembled by a machine.
	var links strings.Builder
	for _, s := range d.Sources {
		state := ""
		if !s.Fetched {
			state = fmt.Sprintf(" <span style='color:#b3001b'>(unavailable: %s)</span>", e(s.Err))
		}
		links.WriteString(fmt.Sprintf(
			`<div style="margin:3px 0"><a href="%s" style="color:#2c5282">%s</a>%s</div>`,
			e(s.URL), e(s.Name), state))
	}
	b.WriteString(fmt.Sprintf(`
  <tr><td style="padding:16px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;color:#4a5568;
                letter-spacing:.5px;text-transform:uppercase;margin:10px 0 6px 0">Sources</div>
    <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">%s</div>
    <div style="font:400 11px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#718096;margin-top:12px">
      Counts above are Microsoft's, as reported by the sources. Presence in our
      environment is determined solely by Qualys Host Detection &mdash; the
      articles supply context, never proof of exposure.<br>
      Generated by the %s CTI agent fleet.
    </div></td></tr>

</table></td></tr></table></body></html>`, links.String(), e(r.Org)))

	return b.String()
}

// Text is the plain-text alternative, and what --dry-run prints. The QQL is
// the one thing someone will want to copy, so it goes on its own line
// unwrapped.
func (r *Report) Text() string {
	d := r.Digest
	var b strings.Builder
	n := func(v int) string {
		if v == 0 {
			return "not stated"
		}
		return fmt.Sprint(v)
	}
	b.WriteString(r.Subject() + "\n" + strings.Repeat("=", 68) + "\n\n")
	if deg := d.Degraded(); len(deg) > 0 {
		b.WriteString("INCOMPLETE SOURCES: " + strings.Join(deg, "; ") + "\n\n")
	}
	fmt.Fprintf(&b, "Released %s\n\n", PatchTuesday(d.Year, d.Month).Format("Mon 2 Jan 2006"))
	fmt.Fprintf(&b, "This month's release addresses %s vulnerabilities, including %s "+
		"critical and %s important-severity vulnerabilities.\n\n",
		n(d.Total), n(d.Critical), n(d.Important))
	b.WriteString(r.Exposure.ExposureLine(r.Org) + "\n\n")
	if r.QQL != "" {
		fmt.Fprintf(&b, "QQL (%s):\n\n%s\n\n", r.QQLSource, r.QQL)
	}
	if len(r.Highlights) > 0 {
		fmt.Fprintf(&b, "PRESENT IN OUR ENVIRONMENT (%d)\n%s\n", len(r.Highlights),
			strings.Repeat("-", 68))
		for _, h := range r.Highlights {
			sev := h.Sev
			if sev == "" {
				sev = "?"
			}
			fmt.Fprintf(&b, "  %-18s %-5s %4d host(s)  QIDs %v\n", h.CVE, sev, h.Hosts, h.QIDs)
			if h.Rationale != "" {
				fmt.Fprintf(&b, "      %s\n", h.Rationale)
			}
		}
		b.WriteString("\n")
	}
	if len(r.Exposure.UnmappedCVEs) > 0 {
		fmt.Fprintf(&b, "%d CVE(s) have no Qualys QID mapping - coverage unverified, "+
			"not confirmed absent.\n\n", len(r.Exposure.UnmappedCVEs))
	}
	if d.ZeroDayText != "" {
		b.WriteString("Zero-days: " + d.ZeroDayText + "\n\n")
	}
	if d.EdgeFixes > 0 {
		fmt.Fprintf(&b, "Microsoft Edge: %d vulnerabilities patched earlier this month.\n\n", d.EdgeFixes)
	}
	if len(d.Products) > 0 {
		b.WriteString("Products: " + strings.Join(d.Products, ", ") + ", and more.\n\n")
	}
	for _, c := range d.Categories {
		fmt.Fprintf(&b, "  %-40s %4d  %s\n", c.Name, c.Quantity, c.Severities)
	}
	if len(d.Categories) > 0 {
		b.WriteString("\n")
	}
	if d.AdobeText != "" {
		b.WriteString("Adobe: " + d.AdobeText + "\n\n")
	}
	b.WriteString("Sources:\n")
	for _, s := range d.Sources {
		state := ""
		if !s.Fetched {
			state = " (unavailable: " + s.Err + ")"
		}
		fmt.Fprintf(&b, "  %s%s\n  %s\n", s.Name, state, s.URL)
	}
	b.WriteString("\nPresence determined solely by Qualys Host Detection.\n")
	return b.String()
}
