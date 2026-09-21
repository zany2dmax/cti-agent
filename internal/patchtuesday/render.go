package patchtuesday

import (
	"fmt"
	"html"
	neturl "net/url"
	"os"
	"sort"
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

	// Attribution is the credit line at the foot of the email. Zero value
	// renders nothing.
	Attribution Attribution

	// MaxRows caps the present-CVE table. Zero means defaultMaxRows.
	//
	// The August replay produced 353 rows, nearly all of them one of two
	// cumulative-update QIDs, in no particular order. Nobody reads that, and
	// an unread table is indistinguishable from an absent one. The full list
	// stays in the JSON output.
	MaxRows int
}

// defaultMaxRows is a table someone will actually read on a phone before
// they are fully awake, which is the stated audience.
const defaultMaxRows = 25

// Highlight is one CVE that is actually in the estate.
type Highlight struct {
	CVE string
	// Sev is Sev5..Sev1 from the enrich lane, blank when no enriched data was
	// available for this CVE. Blank is rendered by omitting the column
	// entirely rather than by printing a placeholder: the August replay
	// printed a "?" in every row of a column that, as written, could never
	// hold a value, because nothing populated it.
	Sev   string
	Hosts int
	// HostsAreFloor means Hosts is a lower bound, not a count.
	HostsAreFloor bool
	QIDs          []int
	// SharedWith is how many other CVEs in this release resolve to exactly the
	// same QIDs - i.e. are fixed by the same update. Set during rendering.
	SharedWith int
	KEV        bool
	EPSS       float64
	CVSS       float64
	Rationale  string
}

// anySev reports whether the enrich lane supplied a band for anything. When it
// did not, the severity column is left out.
func (r *Report) anySev() bool {
	for _, h := range r.Highlights {
		if h.Sev != "" {
			return true
		}
	}
	return false
}

// rows returns the highlights to print, worst first, and how many CVEs were
// left out.
//
// Ordered by blast radius, then severity, then CVE - and then collapsed by
// QID set, which is the part that makes the table readable. Sorting by host
// count alone floods the top with whichever cumulative update is on the most
// machines: the August replay's first 25 rows were 24 CVEs carrying the
// identical pair [92439 92440] and the same 331 hosts, which tells the reader
// one fact 24 times and hides the other eleven patches below the cut. One row
// per distinct QID set, carrying how many CVEs share it, says the same thing
// in a twelfth of the space.
func (r *Report) rows() (shown []Highlight, hidden int) {
	sorted := make([]Highlight, len(r.Highlights))
	copy(sorted, r.Highlights)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Hosts != sorted[j].Hosts {
			return sorted[i].Hosts > sorted[j].Hosts
		}
		if si, sj := sevRank(sorted[i].Sev), sevRank(sorted[j].Sev); si != sj {
			return si > sj
		}
		return sorted[i].CVE < sorted[j].CVE
	})

	// Collapse, keeping the first (worst) CVE of each QID set. A row with a
	// severity band is never collapsed away behind one without: an actively
	// exploited CVE has to stay visible even when it shares an update with
	// two hundred others.
	byQIDs := map[string]int{} // QID set -> index in shown
	for _, h := range sorted {
		key := qidKey(h.QIDs)
		if at, ok := byQIDs[key]; ok {
			shown[at].SharedWith++
			// A banded CVE displaces the unbanded representative.
			if sevRank(h.Sev) > sevRank(shown[at].Sev) {
				n := shown[at].SharedWith
				h.SharedWith = n
				shown[at] = h
			}
			continue
		}
		byQIDs[key] = len(shown)
		shown = append(shown, h)
	}

	limit := r.MaxRows
	if limit <= 0 {
		limit = defaultMaxRows
	}
	if len(shown) > limit {
		for _, h := range shown[limit:] {
			hidden += 1 + h.SharedWith
		}
		shown = shown[:limit]
	}
	// Everything folded into a shown row is still reported as covered, so the
	// "and N more" figure counts CVEs, not rows.
	return shown, hidden
}

// collapsed reports whether any row stands in for more than itself.
func collapsed(rows []Highlight) bool {
	for _, h := range rows {
		if h.SharedWith > 0 {
			return true
		}
	}
	return false
}

func qidKey(qids []int) string {
	if len(qids) == 0 {
		return "-"
	}
	s := make([]int, len(qids))
	copy(s, qids)
	sort.Ints(s)
	parts := make([]string, len(s))
	for i, q := range s {
		parts[i] = fmt.Sprint(q)
	}
	return strings.Join(parts, ",")
}

// sevRank orders the bands. Unknown sorts last so an unenriched row never
// displaces a known Sev5.
func sevRank(s string) int {
	switch s {
	case "Sev5":
		return 5
	case "Sev4":
		return 4
	case "Sev3":
		return 3
	case "Sev2":
		return 2
	case "Sev1":
		return 1
	}
	return 0
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

// Attribution is the credit line at the foot of the email.
//
// Configured, not hardcoded. This repository was deliberately genericised -
// no organisation name, no addresses, no internal identifiers - and baking one
// team's wording and one GitHub URL into the shipped renderer would undo that.
// Unset means no attribution line at all, so a fresh install advertises
// nobody.
type Attribution struct {
	Text string // FLEET_ATTRIBUTION, or a default built from FLEET_ORG
	URL  string // FLEET_REPO_URL; empty renders as plain text
}

// LoadAttribution reads the attribution from the environment.
//
// Returns a zero Attribution when neither variable is set, which renders
// nothing. The default text is only used when a URL was given: somebody who
// sets a repo link clearly wants the credit, whereas somebody who sets neither
// has not asked for either.
func LoadAttribution(org string) Attribution {
	text := strings.TrimSpace(os.Getenv("FLEET_ATTRIBUTION"))
	raw := strings.TrimSpace(os.Getenv("FLEET_REPO_URL"))
	url := safeLinkURL(raw)
	if raw != "" && url == "" {
		// Do not silently drop it. A footer link that vanished because of a
		// typo is the kind of thing nobody notices for months.
		fmt.Fprintf(os.Stderr,
			"cti-patchtuesday: ignoring FLEET_REPO_URL=%q - only http:// and "+
				"https:// are rendered as links\n", raw)
	}
	if text == "" && url == "" {
		return Attribution{}
	}
	if text == "" {
		text = fmt.Sprintf(
			"Correlated and published by the %s Claude Code Agent Fleet", org)
	}
	return Attribution{Text: text, URL: url}
}

// safeLinkURL returns the URL only if it is safe to put in an href, and ""
// otherwise.
//
// These emails are rendered as HTML in Outlook. A scheme other than http or
// https in an href - javascript:, data:, file: - is at best broken and at
// worst a payload, and this value arrives from a config file that an installer
// writes. Checking the scheme costs nothing; assuming it does not is how
// clickable footers become an incident.
func safeLinkURL(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.String()
	}
	return ""
}

// creditHTML is the footer credit. Falls back to the old wording when no
// attribution is configured, so an install that sets nothing keeps the line it
// has always had rather than losing a line.
func (r *Report) creditHTML() string {
	if s := r.Attribution.HTML(); s != "" {
		return s
	}
	return fmt.Sprintf("Generated by the %s CTI agent fleet.", e(r.Org))
}

// creditText is the same for the plain-text alternative.
func (r *Report) creditText() string {
	if s := r.Attribution.Text(); s != "" {
		return s
	}
	return fmt.Sprintf("Generated by the %s CTI agent fleet.", r.Org)
}

// HTML renders the attribution as an escaped line, linked when there is a URL.
func (a Attribution) HTML() string {
	if a.Text == "" {
		return ""
	}
	if a.URL == "" {
		return e(a.Text)
	}
	return fmt.Sprintf(`<a href="%s" style="color:#2c5282;text-decoration:underline">%s</a>`,
		e(a.URL), e(a.Text))
}

// Text renders the attribution for the plain-text alternative, with the URL on
// the same line because a text-only reader cannot follow an anchor.
func (a Attribution) Text() string {
	switch {
	case a.Text == "":
		return ""
	case a.URL == "":
		return a.Text
	}
	return a.Text + "\n" + a.URL
}

// Subject matches what has gone out by hand for months, so the thread and any
// mail rules that key on it keep working.
func (r *Report) Subject() string {
	base := fmt.Sprintf("Microsoft Patch Tuesday for %s",
		MonthLabel(r.Digest.Year, r.Digest.Month))
	n := len(r.Exposure.PresentCVEs)
	if n == 0 {
		return base
	}
	// "353 present in our environment" alone reads as 353 things to fix. It is
	// 353 CVEs carried by twelve detections, and the detection count is what
	// tells the reader how much work this is - so it goes in the subject,
	// where a phone shows it before anything else.
	if q := len(r.Exposure.DetectingQIDs); q > 0 {
		// ">=" rather than the glyph: a subject header travels through mail
		// gateways and rules, and ASCII cannot be mangled by any of them.
		hosts := fmt.Sprintf("%d", r.Exposure.Hosts)
		if r.Exposure.HostsAreFloor {
			hosts = ">=" + hosts
		}
		return fmt.Sprintf("%s - %d detection(s) on %s hosts, %d CVEs",
			base, q, hosts, n)
	}
	return fmt.Sprintf("%s - %d present in our environment", base, n)
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

	fmt.Fprintf(&b, `<!DOCTYPE html>
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
		PatchTuesday(d.Year, d.Month).Format("Monday 2 January 2006"))

	// Degraded banner first: a synopsis assembled from one source instead of
	// two is still useful, but the reader has to know which.
	if deg := d.Degraded(); len(deg) > 0 {
		// Only claim the exposure numbers survived if they did. This banner
		// used to say "the exposure figures come from Qualys and are
		// unaffected" while listing the Qualys exposure query as one of the
		// things that failed.
		tail := "The exposure figures come from Qualys Host Detection and are unaffected."
		if !r.Exposure.Attempted {
			tail = "The exposure figures are missing too &mdash; see the line below."
		}
		fmt.Fprintf(&b, `
  <tr><td style="padding:14px 20px 0 20px">
    <div style="background:#fffbe6;border:1px solid #d69e2e;border-radius:4px;
                padding:10px 12px;font:400 13px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                color:#744210">
      <b>Incomplete sources.</b> Could not read: %s. Counts below may be
      missing or low. %s
    </div></td></tr>`, e(strings.Join(deg, "; ")), tail)
	}

	// The lead. Microsoft's numbers, then ours, then the query.
	fmt.Fprintf(&b, `
  <tr><td style="padding:16px 20px 0 20px">
    <div style="font:400 15px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a202c">
      This month's release addresses %s vulnerabilities, including %s critical
      and %s important-severity vulnerabilities.</div>`,
		num(d.Total), num(d.Critical), num(d.Important))

	fmt.Fprintf(&b, `
    <div style="margin:12px 0 0 0;padding:12px 14px;background:#fdecee;
                border-left:4px solid #b3001b;font:700 15px/1.55 -apple-system,
                Segoe UI,Helvetica,Arial,sans-serif;color:#1a202c">%s</div>`,
		e(r.Exposure.ExposureLine(r.Org)))

	if r.QQL != "" {
		fmt.Fprintf(&b, `
    <div style="font:400 14px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#1a202c;margin:12px 0 6px 0">
      You can use the following QQL to query for it yourself
      <span style="color:#718096;font-size:12px">(%s)</span>:</div>
    <div style="font:400 13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
                background:#f4f5f7;border:1px solid #e2e8f0;border-radius:4px;
                padding:10px 12px;color:#1a202c;word-break:break-word;
                white-space:pre-wrap">%s</div>`, e(r.QQLSource), e(r.QQL))
	}
	b.WriteString("\n  </td></tr>\n")

	// Highlights: the CVEs actually here. This is the section that makes the
	// email ours rather than a forwarded blog post.
	if len(r.Highlights) > 0 {
		shown, hidden := r.rows()
		withSev := r.anySev()
		sevHead := ""
		if withSev {
			sevHead = `<th align="left" style="border-bottom:1px solid #e2e8f0">Sev</th>`
		}
		caption := fmt.Sprintf("%d of this release's CVEs", len(r.Highlights))
		if collapsed(shown) {
			caption += fmt.Sprintf(" in %d row(s) sharing %d detection(s)",
				len(shown), len(r.Exposure.DetectingQIDs))
		}
		if hidden > 0 {
			caption += fmt.Sprintf(" &mdash; worst %d shown", len(shown))
		}
		fmt.Fprintf(&b, `
  <tr><td style="padding:18px 20px 0 20px">
    <div style="font:700 13px -apple-system,Segoe UI,Arial,sans-serif;color:#b3001b;
                letter-spacing:.6px;text-transform:uppercase;
                border-bottom:2px solid #b3001b;padding-bottom:5px">
      Present in our environment &mdash; %s</div>
    <table width="100%%" cellpadding="6" cellspacing="0" role="presentation"
           style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                  margin-top:8px;border-collapse:collapse">
      <tr style="background:#f4f5f7">
        <th align="left" style="border-bottom:1px solid #e2e8f0">CVE</th>
        %s
        <th align="right" style="border-bottom:1px solid #e2e8f0">Hosts</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">QIDs</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">Why</th></tr>`,
			caption, sevHead)
		for _, h := range shown {
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
			sevCell := ""
			if withSev {
				sev := h.Sev
				if sev == "" {
					sev = "&mdash;"
				}
				sevCell = fmt.Sprintf(
					`<td style="border-bottom:1px solid #edf2f7"><b>%s</b></td>`, sev)
			}
			hosts := fmt.Sprint(h.Hosts)
			if h.HostsAreFloor {
				hosts = "&ge;" + hosts
			}
			cveCell := e(h.CVE)
			if h.SharedWith > 0 {
				cveCell += fmt.Sprintf(
					`<span style="color:#718096;font-size:11px"> +%d more with `+
						`the same QIDs</span>`, h.SharedWith)
			}
			fmt.Fprintf(&b, `
      <tr><td style="border-bottom:1px solid #edf2f7">
            <a href="https://nvd.nist.gov/vuln/detail/%s" style="color:#1a202c">%s</a></td>
          %s
          <td align="right" style="border-bottom:1px solid #edf2f7">%s</td>
          <td style="border-bottom:1px solid #edf2f7;font:400 12px ui-monospace,
                     SFMono-Regular,Menlo,monospace">%s</td>
          <td style="border-bottom:1px solid #edf2f7;color:#4a5568">%s</td></tr>`,
				e(h.CVE), cveCell, sevCell, hosts, qids, why)
		}
		b.WriteString("\n    </table>")
		if hidden > 0 {
			fmt.Fprintf(&b, `
    <div style="font:400 12px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                color:#718096;margin-top:6px">
      and %d more CVE(s) on lower host counts. The %d detection(s) in the QQL
      above are the patching work; the CVE count is large because one
      cumulative update carries many CVEs. Full list in the JSON output.
    </div>`, hidden, len(r.Exposure.DetectingQIDs))
		}
		b.WriteString("</td></tr>\n")
	}

	// Coverage caveat. An unmapped CVE is not an absent one, and this email
	// would otherwise imply the difference away.
	if note := r.Exposure.CoverageNote(); note != "" {
		fmt.Fprintf(&b, `
  <tr><td style="padding:14px 20px 0 20px">
    <div style="background:#fffbe6;border-left:4px solid #d69e2e;padding:10px 12px;
                font:400 13px/1.55 -apple-system,Segoe UI,Arial,sans-serif;color:#744210">
      %s</div></td></tr>`, e(note))
	}

	// The narrative fields, each omitted when the sources did not carry it.
	sect := func(title, body string) {
		if strings.TrimSpace(body) == "" {
			return
		}
		fmt.Fprintf(&b, `
  <tr><td style="padding:16px 20px 0 20px">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;color:#4a5568;
                letter-spacing:.5px;text-transform:uppercase;margin-bottom:5px">%s</div>
    <div style="font:400 14px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#2d3748">%s</div></td></tr>`, e(title), body)
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
			fmt.Fprintf(&rows,
				`<tr><td style="border-bottom:1px solid #edf2f7;padding:5px 8px">%s</td>`+
					`<td align="right" style="border-bottom:1px solid #edf2f7;padding:5px 8px">%d</td>`+
					`<td style="border-bottom:1px solid #edf2f7;padding:5px 8px">%s</td></tr>`,
				e(c.Name), c.Quantity, e(c.Severities))
		}
		fmt.Fprintf(&b, `
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
    </table></td></tr>`, e(MonthLabel(d.Year, d.Month)), rows.String())
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
		fmt.Fprintf(&links,
			`<div style="margin:3px 0"><a href="%s" style="color:#2c5282">%s</a>%s</div>`,
			e(s.URL), e(s.Name), state)
	}
	countNote := ""
	if n := d.CVECountNote(); n != "" {
		countNote = e(n) + "<br>"
	}
	fmt.Fprintf(&b, `
  <tr><td style="padding:16px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:700 12px -apple-system,Segoe UI,Arial,sans-serif;color:#4a5568;
                letter-spacing:.5px;text-transform:uppercase;margin:10px 0 6px 0">Sources</div>
    <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif">%s</div>
    <div style="font:400 11px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#718096;margin-top:12px">
      %s
      Counts above are Microsoft's, as reported by the sources. Presence in our
      environment is determined solely by Qualys Host Detection &mdash; the
      articles supply context, never proof of exposure.<br>
      %s
    </div></td></tr>

</table></td></tr></table></body></html>`,
		links.String(), countNote, r.creditHTML())

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
		shown, hidden := r.rows()
		withSev := r.anySev()
		head := fmt.Sprintf("PRESENT IN OUR ENVIRONMENT (%d CVEs)", len(r.Highlights))
		if collapsed(shown) {
			// Reconcile the two counts explicitly. The first version said "in
			// 14 update(s)" while the exposure line above said "12 missing
			// Qualys detection(s)" - two numbers for the same thing, three
			// paragraphs apart. They differ because a row is a distinct
			// COMBINATION of QIDs and several combinations share a QID, so
			// neither number was wrong and the email never said so.
			head += fmt.Sprintf(", %d row(s) sharing %d detection(s)",
				len(shown), len(r.Exposure.DetectingQIDs))
		}
		if hidden > 0 {
			head += " - worst first"
		}
		fmt.Fprintf(&b, "%s\n%s\n", head, strings.Repeat("-", 68))
		for _, h := range shown {
			hosts := fmt.Sprintf("%4d", h.Hosts)
			if h.HostsAreFloor {
				hosts = fmt.Sprintf(">=%2d", h.Hosts)
			}
			// The severity column is omitted, not filled with a placeholder,
			// when the enrich lane supplied nothing for any row.
			shared := ""
			if h.SharedWith > 0 {
				// "with the same QIDs", not "fixed by the same update". We
				// know the detections, not the KB article: [92440] and
				// [92439 92440] are two rows that share a QID, so calling
				// each row an update asserts a patch identity this lane never
				// established.
				shared = fmt.Sprintf("  (+%d more CVE(s) with the same QIDs)",
					h.SharedWith)
			}
			if withSev {
				sev := h.Sev
				if sev == "" {
					sev = "-"
				}
				fmt.Fprintf(&b, "  %-18s %-5s %s host(s)  QIDs %v%s\n",
					h.CVE, sev, hosts, h.QIDs, shared)
			} else {
				fmt.Fprintf(&b, "  %-18s %s host(s)  QIDs %v%s\n",
					h.CVE, hosts, h.QIDs, shared)
			}
			if h.Rationale != "" {
				fmt.Fprintf(&b, "      %s\n", h.Rationale)
			}
		}
		if hidden > 0 {
			fmt.Fprintf(&b,
				"  ... and %d more CVE(s) on lower host counts. The %d detection(s) in\n"+
					"  the QQL above are the patching work; the CVE count is large because\n"+
					"  one cumulative update carries many CVEs. Full list in the JSON.\n",
				hidden, len(r.Exposure.DetectingQIDs))
		}
		if !withSev {
			b.WriteString(
				"  (No severity band: no enriched data was available for these CVEs.\n" +
					"   Run the digest first, or pass --enriched, to get Sev5-Sev1 here.)\n")
		}
		b.WriteString("\n")
	}
	if note := r.Exposure.CoverageNote(); note != "" {
		b.WriteString(note + "\n\n")
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
	if note := d.CVECountNote(); note != "" {
		b.WriteString("\n" + note + "\n")
	}
	b.WriteString("\nPresence determined solely by Qualys Host Detection.\n")
	b.WriteString(r.creditText() + "\n")
	return b.String()
}
