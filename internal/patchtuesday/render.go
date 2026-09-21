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

	// QQL is the query to paste into the Qualys console, and the review's own
	// is preferred over anything this lane can build.
	//
	// Qualys publishes a QQL with every monthly review, and run in the console
	// it returns the complete list of the release's QIDs that have assets
	// against them - which is the question the reader has. A query built from
	// the QIDs we happened to correlate can only ever be a subset of that, so
	// it is the second block (QQLNarrow), useful for "just show me today's
	// work" and not a substitute for the published one.
	QQL             string
	QQLSource       string
	QQLNarrow       string
	QQLNarrowSource string

	// Patches are the missing updates found here: one row per QID.
	//
	// The unit used to be the CVE, which made this table a restatement of
	// Microsoft's release notes - the August replay produced 353 rows, nearly
	// all of them carrying one of two cumulative-update QIDs and the same host
	// count repeated down the page. A QID is one thing somebody installs.
	// Twelve rows that each mean "patch this" is a report; 353 rows that mean
	// "Microsoft fixed some things" is a press release.
	Patches []Patch

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

// Patch is one QID with open detections: one update somebody has to install.
//
// Everything in it comes out of a single Host Detection response. That is the
// point. The Sev5-Sev1 column this replaces could only be filled from the
// daily enrich lane's output file, so a monthly report about CVEs the daily
// had never seen printed "severity bands for 0 of 353" - a column that, as
// deployed, could not hold a value.
type Patch struct {
	QID int
	// Hosts is the provider's own distinct-machine count for this QID, not the
	// length of a host list that may have been cut off for display.
	Hosts         int
	HostsAreFloor bool
	// QDS is the Qualys Detection Score, 1-100, highest seen across the hosts
	// carrying this detection. 0 means the response carried no score, and is
	// rendered as a dash rather than as a zero: "QDS 0" reads like "no risk".
	//
	// The number is printed without a severity word. Qualys does band QDS, but
	// this lane has not verified the thresholds against Qualys documentation,
	// and a band that is confidently one step wrong is worse than a bare
	// number the reader already knows how to read.
	QDS int
	// LastSeen is the newest LAST_FOUND_DATETIME across those hosts. It
	// answers the question the exposure line otherwise hands back to the
	// reader - "check the last scan date before treating this as good news" -
	// with a date instead of an instruction.
	LastSeen string
	// CVEs are the release's CVEs that resolve to this QID: the evidence for
	// the row, not a ranking. Empty when the QID was reachable only from the
	// published QQL, which is normal in the day or two before the
	// KnowledgeBase mapping catches up.
	CVEs []string
	// Published means Qualys listed this QID in the review's own QQL; FromKB
	// means the KnowledgeBase CVE mapping reached it. Both can be true. Both
	// being false is impossible by construction, and if it ever happens the
	// row arrived from nowhere and should be treated as a bug.
	Published bool
	FromKB    bool
}

// rows returns the patches to print, worst first, and how many were left out.
//
// Worst is host count, then QDS, then QID for a stable order. There is no
// collapsing step any more: one row per QID *is* the collapse, which is why
// this is now ten lines rather than fifty.
//
// The hidden count is patches, and only patches. The previous version summed
// a host figure across hidden rows, which counts the same machine once per
// QID - the same arithmetic that made every row of the August table read
// "10 hosts".
func (r *Report) rows() (shown []Patch, hidden int) {
	shown = make([]Patch, len(r.Patches))
	copy(shown, r.Patches)
	sort.SliceStable(shown, func(i, j int) bool {
		if shown[i].Hosts != shown[j].Hosts {
			return shown[i].Hosts > shown[j].Hosts
		}
		if shown[i].QDS != shown[j].QDS {
			return shown[i].QDS > shown[j].QDS
		}
		return shown[i].QID < shown[j].QID
	})
	limit := r.MaxRows
	if limit <= 0 {
		limit = defaultMaxRows
	}
	if len(shown) > limit {
		hidden = len(shown) - limit
		shown = shown[:limit]
	}
	return shown, hidden
}

// CVEsCovered totals the release CVEs attributed to the given patches.
func CVEsCovered(patches []Patch) int {
	seen := map[string]bool{}
	for _, p := range patches {
		for _, c := range p.CVEs {
			seen[strings.ToUpper(c)] = true
		}
	}
	return len(seen)
}

// ChooseQQL sets both queries: the one Qualys published, and ours.
//
// The published query leads. Run in the console it returns every QID in the
// release that has assets against it - the complete answer, from the vendor,
// for a release Qualys wrote the query for. This used to be third in a
// preference list behind a query built from whatever QIDs this lane had
// managed to correlate, which meant the email's headline query was a subset
// of the release whenever the KnowledgeBase mapping lagged, and said nothing
// about being one.
func (r *Report) ChooseQQL(detected []int) {
	switch {
	case len(r.Digest.SourceQQL) > 0:
		r.QQL = r.Digest.SourceQQL[0]
		r.QQLSource = "published by Qualys in this month's review (verbatim) - " +
			"returns every QID in the release with assets against it"
	case len(detected) > 0:
		r.QQL = QQLForQIDs(detected)
		r.QQLSource = fmt.Sprintf(
			"built from the %d QID(s) with open detections here - the review "+
				"published no QQL this month, so this is our list, not the "+
				"complete release", len(detected))
	case len(r.Digest.CVEs) > 0:
		r.QQL = QQLForCVEs(r.Digest.CVEs)
		r.QQLSource = "CVE-based fallback - no published QQL and no QID mapping yet"
	}

	// The narrowed query, when it adds something the first does not. Identical
	// output would just be the same block twice.
	if len(detected) > 0 && r.QQL != QQLForQIDs(detected) {
		r.QQLNarrow = QQLForQIDs(detected)
		r.QQLNarrowSource = fmt.Sprintf(
			"the %d QID(s) with open detections here - a subset of the query above",
			len(detected))
	}
}

func e(s string) string { return html.EscapeString(s) }

// shortDate trims a Qualys timestamp (2026-09-17T04:11:02Z) to the date.
// Returns the input unchanged if it is not that shape, rather than cutting a
// string it does not recognise down to ten arbitrary characters.
func shortDate(s string) string {
	if len(s) >= 10 && s[4] == '-' && s[7] == '-' {
		return s[:10]
	}
	return s
}

// publishedMarkHTML flags a QID that only the review's published QQL knew
// about. Worth marking on the row: those are the detections a report trusting
// the KnowledgeBase mapping alone would have missed entirely, which is the
// whole reason the published list is queried.
func publishedMarkHTML(p Patch) string {
	if p.Published && !p.FromKB {
		return `<span style="color:#718096;font-size:11px"> (from the review's QQL)</span>`
	}
	return ""
}

// cveCellHTML lists a few CVEs and says how many more there are. The full set
// is in the JSON output; a cell with two hundred CVE IDs in it is a wall.
func cveCellHTML(p Patch) string {
	if len(p.CVEs) == 0 {
		// Not "none". A QID from the published list with no CVE attributed to
		// it means the mapping has not caught up, not that the update fixes
		// nothing.
		return `<span style="color:#718096">mapping not yet available</span>`
	}
	const show = 3
	first := p.CVEs
	if len(first) > show {
		first = first[:show]
	}
	links := make([]string, 0, len(first))
	for _, c := range first {
		links = append(links, fmt.Sprintf(
			`<a href="https://nvd.nist.gov/vuln/detail/%s" style="color:#1a202c">%s</a>`,
			e(c), e(c)))
	}
	out := strings.Join(links, ", ")
	if n := len(p.CVEs) - len(first); n > 0 {
		out += fmt.Sprintf(`<span style="color:#718096;font-size:11px"> +%d more</span>`, n)
	}
	return out
}

// cveLineText is the plain-text counterpart of cveCellHTML.
func cveLineText(p Patch) string {
	if len(p.CVEs) == 0 {
		return "CVEs: mapping not yet available (QID came from the review's QQL)"
	}
	const show = 4
	first := p.CVEs
	if len(first) > show {
		first = first[:show]
	}
	out := "fixes " + strings.Join(first, ", ")
	if n := len(p.CVEs) - len(first); n > 0 {
		out += fmt.Sprintf(" +%d more", n)
	}
	if p.Published && !p.FromKB {
		out += "  (from the review's QQL)"
	}
	return out
}

func hiddenNoteHTML(hidden int) string {
	if hidden == 0 {
		return ""
	}
	return fmt.Sprintf(
		"%d further QID(s) on lower host counts are in the JSON output.", hidden)
}

// Attribution is the credit line at the foot of the email.
//
// Configured, not hardcoded. This repository was deliberately genericised -
// no organisation name, no addresses, no internal identifiers - and baking one
// team's wording and one GitHub URL into the shipped renderer would undo that.
// Unset means no attribution line at all, so a fresh install advertises
// nobody.
// The field is Line rather than Text because the render methods are HTML()
// and Text(), mirroring Report.HTML() and Report.Text(), and Go does not
// allow a field and a method to share a name on one type. The method pair is
// worth more than the field name.
type Attribution struct {
	Line string // FLEET_ATTRIBUTION, or a default built from FLEET_ORG
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
	return Attribution{Line: text, URL: url}
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
	if a.Line == "" {
		return ""
	}
	if a.URL == "" {
		return e(a.Line)
	}
	return fmt.Sprintf(`<a href="%s" style="color:#2c5282;text-decoration:underline">%s</a>`,
		e(a.URL), e(a.Line))
}

// Text renders the attribution for the plain-text alternative, with the URL on
// its own line because a text-only reader cannot follow an anchor.
func (a Attribution) Text() string {
	switch {
	case a.Line == "":
		return ""
	case a.URL == "":
		return a.Line
	}
	return a.Line + "\n" + a.URL
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

	qqlBlock := func(lead, source, query string) {
		if query == "" {
			return
		}
		fmt.Fprintf(&b, `
    <div style="font:400 14px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#1a202c;margin:12px 0 6px 0">
      %s
      <span style="color:#718096;font-size:12px">(%s)</span>:</div>
    <div style="font:400 13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;
                background:#f4f5f7;border:1px solid #e2e8f0;border-radius:4px;
                padding:10px 12px;color:#1a202c;word-break:break-word;
                white-space:pre-wrap">%s</div>`, lead, e(source), e(query))
	}
	qqlBlock("You can use the following QQL to query for it yourself",
		r.QQLSource, r.QQL)
	qqlBlock("Or just this release's QIDs that are already on our machines",
		r.QQLNarrowSource, r.QQLNarrow)
	b.WriteString("\n  </td></tr>\n")

	// The patches actually here. This is the section that makes the email ours
	// rather than a forwarded blog post.
	if len(r.Patches) > 0 {
		shown, hidden := r.rows()
		caption := fmt.Sprintf("%d QID(s) with assets", len(r.Patches))
		if n := CVEsCovered(r.Patches); n > 0 {
			caption += fmt.Sprintf(", covering %d of this release's CVEs", n)
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
        <th align="left" style="border-bottom:1px solid #e2e8f0">QID</th>
        <th align="right" style="border-bottom:1px solid #e2e8f0">Hosts</th>
        <th align="right" style="border-bottom:1px solid #e2e8f0">QDS</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">Last seen</th>
        <th align="left" style="border-bottom:1px solid #e2e8f0">CVEs fixed</th></tr>`,
			caption)
		for _, p := range shown {
			hosts := fmt.Sprint(p.Hosts)
			if p.HostsAreFloor {
				hosts = "&ge;" + hosts
			}
			// A dash, not a zero. "QDS 0" reads as "no risk" when it means
			// "the response carried no score".
			qds := "&mdash;"
			if p.QDS > 0 {
				qds = fmt.Sprint(p.QDS)
			}
			seen := "&mdash;"
			if p.LastSeen != "" {
				seen = e(shortDate(p.LastSeen))
			}
			fmt.Fprintf(&b, `
      <tr><td style="border-bottom:1px solid #edf2f7;font:400 12px ui-monospace,
                     SFMono-Regular,Menlo,monospace">%d%s</td>
          <td align="right" style="border-bottom:1px solid #edf2f7">%s</td>
          <td align="right" style="border-bottom:1px solid #edf2f7">%s</td>
          <td style="border-bottom:1px solid #edf2f7;color:#4a5568">%s</td>
          <td style="border-bottom:1px solid #edf2f7;color:#4a5568">%s</td></tr>`,
				p.QID, publishedMarkHTML(p), hosts, qds, seen, cveCellHTML(p))
		}
		b.WriteString("\n    </table>")
		fmt.Fprintf(&b, `
    <div style="font:400 12px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                color:#718096;margin-top:6px">
      One row per QID, because one QID is one update somebody installs. QDS is
      the Qualys Detection Score (1&ndash;100) from the same Host Detection
      response as the host count. %s</div></td></tr>
`, hiddenNoteHTML(hidden))
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
	if r.QQLNarrow != "" {
		fmt.Fprintf(&b, "QQL, ours only (%s):\n\n%s\n\n", r.QQLNarrowSource, r.QQLNarrow)
	}
	if len(r.Patches) > 0 {
		shown, hidden := r.rows()
		head := fmt.Sprintf("PRESENT IN OUR ENVIRONMENT (%d QID(s) with assets",
			len(r.Patches))
		if n := CVEsCovered(r.Patches); n > 0 {
			head += fmt.Sprintf(", covering %d CVEs", n)
		}
		head += ")"
		if hidden > 0 {
			head += " - worst first"
		}
		fmt.Fprintf(&b, "%s\n%s\n", head, strings.Repeat("-", 68))
		for _, p := range shown {
			hosts := fmt.Sprintf("%5d", p.Hosts)
			if p.HostsAreFloor {
				hosts = fmt.Sprintf(">=%3d", p.Hosts)
			}
			qds := "   -"
			if p.QDS > 0 {
				qds = fmt.Sprintf("%4d", p.QDS)
			}
			seen := "-"
			if p.LastSeen != "" {
				seen = shortDate(p.LastSeen)
			}
			fmt.Fprintf(&b, "  QID %-9d %s host(s)  QDS %s  last seen %s\n",
				p.QID, hosts, qds, seen)
			fmt.Fprintf(&b, "      %s\n", cveLineText(p))
		}
		if hidden > 0 {
			fmt.Fprintf(&b,
				"  ... and %d more QID(s) on lower host counts. Full list in the JSON.\n",
				hidden)
		}
		b.WriteString(
			"  One row per QID: one QID is one update somebody installs. QDS is the\n" +
				"  Qualys Detection Score (1-100) from the same Host Detection response.\n\n")
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
