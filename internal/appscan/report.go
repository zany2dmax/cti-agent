package appscan

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"
)

// Block is the rendered report in both forms the mail needs.
type Block struct {
	Subject string
	Text    string
	HTML    string
}

// maxDetail caps the per-finding lines shown under one application.
//
// The detail exists to let somebody start work without opening Qualys. Past a
// dozen lines it stops being a starting point and becomes a wall, and the
// portal is better at walls. The count always states the true total, so a cap
// never understates the problem.
const maxDetail = 12

// Render builds the weekly application-security report.
//
// # WHAT THE SECTIONS MEAN, AND WHY THEY CHANGED
//
// This report used to open with a section headed COVERAGE GAPS, into which it
// put every scan that had not authenticated. On the first real send it named
// three applications as having a coverage gap. All three are public sites with
// no login: there is no credential missing, nothing to configure, and nothing
// for the App Dev audience to do. A report whose loudest section is a standing
// complaint about applications being what they are teaches its readers to skip
// the top of the page, which is the one habit a security email cannot afford.
//
// So authentication is now TWO different things:
//
//	a LABEL   Every count says which surface it describes - authenticated or
//	          unauthenticated. That caveat is the part worth keeping: a zero
//	          from a scan that only saw the public pages means something
//	          different from a zero from a scan that logged in, and a reader
//	          cannot tell them apart from the number.
//	a FAULT   Only when a credential WAS configured and did not work. Then the
//	          scan covered less than it was set up to cover while still looking
//	          configured in Qualys, and that is a scanner problem the fleet
//	          operator owns. It is alerted, not just printed - see
//	          cmd/cti-appscan.
//
// An incomplete scan is a fault for the same reason: its counts describe a
// measurement that was never finished.
//
// Order: faults, then what is open now, then what changed. Not lifecycle
// totals - one real application here carries 270 "Urgent" on record of which
// 247 are Fixed, and leading with 270 would be a false alarm an order of
// magnitude too large.
//
// # NOTHING IS CLICKABLE
//
// Every URL renders as plain text, including the footer. These reports are
// assembled from mail that arrived at a published address, and the findings
// themselves name attacker-reachable paths on our own sites. Neither belongs
// in an anchor.
func Render(week []ScanResult, weekEnding time.Time) Block {
	r := &report{weekEnding: weekEnding, org: orgName()}
	r.scans = append([]ScanResult(nil), week...)
	sortScans(r.scans)

	// THE TWO PARTITIONS OVERLAP, ON PURPOSE.
	//
	// A scan appears in faults because something is wrong with the SCAN, and in
	// counted because it produced numbers worth printing. An authentication
	// failure is both: the credential is broken AND the application's open
	// findings are still open.
	//
	// Making these exclusive - the obvious first implementation - dropped an
	// application with 23 Urgent open out of OPEN NOW entirely the week its
	// login broke, and the severity tiles went to zero with it. A report that
	// reads "0 Urgent" because the scanner had a bad password is the exact
	// failure mode this lane exists to prevent.
	//
	// An INCOMPLETE scan is the one case with no numbers to print: its counts
	// describe a crawl that stopped partway, so it is in faults only.
	for _, s := range r.scans {
		if s.Fault() {
			r.faults = append(r.faults, s)
		}
		if s.Complete {
			r.counted = append(r.counted, s)
		}
	}
	return Block{Subject: r.subject(), Text: r.text(), HTML: r.html()}
}

// report is one rendering's worth of state, so the text and HTML paths read
// the same partitioned input rather than each re-deriving it.
type report struct {
	scans      []ScanResult
	faults     []ScanResult // authentication failed, or the scan did not finish
	counted    []ScanResult // ran to completion, so its numbers mean something
	weekEnding time.Time
	org        string
}

// orgName is the banner label, shared with the daily brief's FLEET_ORG.
//
// Read here rather than passed in so the renderer keeps the two-argument
// signature the lane and its tests already use. Default matches brief.py.
func orgName() string {
	if s := strings.TrimSpace(os.Getenv("FLEET_ORG")); s != "" {
		return s
	}
	return "Security"
}

func e(s string) string { return html.EscapeString(s) }

// ─── content: computed once, rendered twice ─────────────────────────────────
//
// Every fact below is produced by one of these helpers and then laid out by
// both the text and the HTML path. Writing the two renderings independently is
// how a fact ends up in one and not the other.

const emptyWeek = "No completed web application scans this week. That is " +
	"either a quiet week or a scheduling problem; the scan schedule in Qualys " +
	"is the place to tell which."

// title heads the plain-text rendering.
//
// ASCII only. text() underlines it with strings.Repeat("=", len(title)), and
// len() counts bytes - an em dash is three of them, so a prettier title gives
// a crooked underline.
func (r *report) title() string {
	return "CTI Fleet AppSec - week ending " +
		r.weekEnding.Format("2 January 2006")
}

// faultCounts splits the faults by kind.
//
// One helper, because the subject line and the lead sentence must agree. They
// were two independent loops over the same slice, which is how a subject ends
// up saying something the body contradicts. A scan that is both incomplete and
// unauthenticated counts as failed: that is the more specific fact.
func (r *report) faultCounts() (failed, incomplete int) {
	for _, s := range r.faults {
		if s.Auth.Failed() {
			failed++
		} else {
			incomplete++
		}
	}
	return failed, incomplete
}

// subject names the most actionable thing in the mail.
//
// # IT SAYS CTI FLEET
//
// The first version read "[AppSec] Week of Oct 4: ...", which nowhere says
// where the mail came from. Every other message this fleet sends opens with
// CTI, so a reader sorting by subject, or a mail rule keyed on it, groups them
// - and somebody receiving one of these for the first time can tell it is the
// fleet rather than a Qualys notification that got reworded.
//
// A scanner fault outranks a finding count. "23 Urgent open" is a known
// quantity somebody is already working through; "the scanner could not log in
// to this application" means this week's numbers are not comparable with last
// week's, and nobody has looked at why.
func (r *report) subject() string {
	label := "CTI Fleet AppSec " + r.weekEnding.Format("Jan 02")

	if len(r.scans) == 0 {
		return label + ": no completed scans this week"
	}

	failed, incomplete := r.faultCounts()
	switch {
	case failed > 0:
		return fmt.Sprintf("[AUTH FAILED] %s: the scanner could not log in to "+
			"%d application(s)", label, failed)
	case incomplete > 0:
		return fmt.Sprintf("[INCOMPLETE] %s: %d scan(s) did not finish", label, incomplete)
	}

	urgent, apps := 0, 0
	for _, s := range r.counted {
		if n := s.AppState.Active.Urgent; n > 0 {
			urgent += n
			apps++
		}
	}
	if urgent > 0 {
		return fmt.Sprintf("%s: %d Urgent finding(s) open across %d application(s)",
			label, urgent, apps)
	}
	return label + ": nothing urgent open"
}

// leadLine is the one-sentence state of the week, in the banner's lead block.
//
// Named leadLine rather than lead because the package-level lead() renders a
// count line, and two things called lead in one file is how the wrong one gets
// called.
func (r *report) leadLine() string {
	if len(r.scans) == 0 {
		return emptyWeek
	}
	failed, incomplete := r.faultCounts()
	if failed+incomplete > 0 {
		var p []string
		if failed > 0 {
			p = append(p, fmt.Sprintf("%d scan(s) could not authenticate", failed))
		}
		if incomplete > 0 {
			p = append(p, fmt.Sprintf("%d did not finish", incomplete))
		}
		return fmt.Sprintf("%d application(s) scanned this week. %s - the counts "+
			"for those are not comparable with last week's, and the fleet "+
			"operator has been told.", len(r.scans), strings.Join(p, " and "))
	}
	urgent := 0
	for _, s := range r.counted {
		urgent += s.AppState.Active.Urgent
	}
	if urgent > 0 {
		return fmt.Sprintf("%d application(s) scanned this week, with %d Urgent "+
			"finding(s) open. Every scan ran as configured.",
			len(r.scans), urgent)
	}
	return fmt.Sprintf("%d application(s) scanned this week. Nothing Urgent is "+
		"open and every scan ran as configured.", len(r.scans))
}

// faultLine is the headline and the explanation for one scan-level fault.
func faultLine(s ScanResult) (head, detail string) {
	if s.Auth.Failed() {
		status := s.Auth.Status
		if status == "" {
			status = "no authentication status in the notification"
		}
		// Name the credential when the notification named one. It is what
		// somebody opens in Qualys to fix this, and "the credential" sends them
		// looking. When the vendor reported a failure without naming a record,
		// say that instead of printing an empty pair of quotes.
		which := "The credential configured for this application"
		if s.Auth.Record != "" {
			which = fmt.Sprintf("Credential %q", s.Auth.Record)
		}
		return fmt.Sprintf("%s - authentication failed (%s)", s.App, status),
			fmt.Sprintf("%s did not work, so this scan covered only the pages a "+
				"visitor can reach while still appearing configured in Qualys. Its "+
				"%d links crawled and %d Urgent describe a smaller surface than the "+
				"scan was set up to cover, so they are not comparable with the "+
				"previous run. This is a scanner problem rather than an application "+
				"one - the fleet operator has been alerted.",
				which, s.LinksCrawled, s.ScanCounts.Urgent)
	}
	return fmt.Sprintf("%s - scan did not complete (%s)", s.App, s.Status),
		"Counts from a partial crawl describe a measurement that was never " +
			"finished, so none are reported for this application."
}

// openLabel is the authenticated/unauthenticated tag that travels with every
// count. Both values are normal; neither is a defect.
func openLabel(s ScanResult) string { return "[" + s.Auth.Label() + "]" }

// scopeNote explains what the labels mean, listing only the kinds present.
//
// Deliberately a statement of SCOPE, not a verdict. The renderer knows that no
// credential was configured; it does not know whether the application has a
// login at all, and the three that triggered the original complaint do not.
// Saying "no authentication record" as though a record were missing is exactly
// the inference that was wrong.
func scopeNote(counted []ScanResult) string {
	var auth, unauth int
	for _, s := range counted {
		switch {
		case s.Auth.Failed():
			// Not described here. A broken login is a fault with its own
			// section; folding it into "these ran unauthenticated" is how it
			// would come to look like one of the normal ones.
		case s.Auth.Authenticated():
			auth++
		default:
			unauth++
		}
	}
	switch {
	case unauth == 0:
		return ""
	case auth == 0:
		// Not "all of the above". A scan whose login FAILED is also listed
		// above and is not counted here, so "all 3" under four rows was wrong
		// in exactly the week the note matters most.
		return fmt.Sprintf("%d scan(s) above ran unauthenticated: they cover "+
			"what a visitor can reach without logging in. For a site with no "+
			"login that is the whole application; where a login does exist, "+
			"nothing behind it was tested.", unauth)
	}
	return fmt.Sprintf("%d of the scans above ran unauthenticated and %d logged "+
		"in. An unauthenticated scan covers what a visitor can reach without "+
		"logging in - for a site with no login that is the whole application, "+
		"and where a login does exist, nothing behind it was tested. Which "+
		"applies is a property of the application, so these are labelled rather "+
		"than flagged.", unauth, auth)
}

// changePartsHTML joins the parts with a separator that must NOT be escaped.
//
// Each part is escaped individually. Escaping the joined string instead turns
// the separator into visible "&nbsp;" in the mail, which is what happened the
// first time this was written as one call.
func changePartsHTML(s ScanResult) string {
	parts := changeParts(s)
	for i := range parts {
		parts[i] = e(parts[i])
	}
	return strings.Join(parts, " &nbsp; ")
}

// changeParts is the new/reopened summary for one application.
func changeParts(s ScanResult) []string {
	var parts []string
	if n := s.AppState.New; n.Total() > 0 {
		parts = append(parts, "new: "+counts(n))
	}
	if r := s.AppState.Reopened; r.Total() > 0 {
		parts = append(parts, "reopened: "+counts(r))
	}
	return parts
}

// changed splits the completed scans into the ones worth listing individually
// and a count of the ones whose only movement was below the floor.
//
// The floor is the same one Attention() uses. The two disagreeing is how an
// unauthenticated scan's five reopened Minimal findings ended up as the lead
// item in the section meant to carry the week's actionable news.
func (r *report) changed() (worth []ScanResult, lowerOnly int) {
	for _, s := range r.scans {
		// An incomplete scan's counts are withheld in the faults section, so
		// printing them here would make the report contradict itself - and the
		// second number is the one people act on.
		if !s.Complete {
			continue
		}
		n, rp := s.AppState.New, s.AppState.Reopened
		switch {
		case n.Urgent+n.Crit+n.Serious+rp.Urgent+rp.Crit+rp.Serious > 0:
			worth = append(worth, s)
		case n.Total()+rp.Total() > 0:
			lowerOnly++
		}
	}
	return worth, lowerOnly
}

// detailLines is the per-finding detail for one application: the lines, then
// the cap note, then the report-link line. Only NEW and REOPENED - the backlog
// is a remediation programme, what appeared since the last scan is the thing a
// weekly report exists to surface.
func detailLines(s ScanResult) []string {
	var worth []Finding
	for _, f := range s.Findings {
		if f.Status == "NEW" || f.Status == "REOPENED" {
			worth = append(worth, f)
		}
	}
	sort.SliceStable(worth, func(i, j int) bool { return worth[i].Severity > worth[j].Severity })

	var out []string
	for i, f := range worth {
		if i >= maxDetail {
			out = append(out, fmt.Sprintf(
				"... and %d more; the full list is in Qualys", len(worth)-i))
			break
		}
		line := fmt.Sprintf("sev %d  %s  %s", f.Severity, f.ID, f.Title)
		if f.URL != "" {
			line += "  " + f.URL
			if f.Param != "" {
				line += "  (parameter: " + f.Param + ")"
			}
		}
		out = append(out, line)
	}
	if len(s.Findings) == 0 {
		out = append(out, "(per-finding detail not available for this run - "+
			"counts are from the scan notification)")
	}
	switch {
	case s.ReportURL != "":
		out = append(out, "report: "+s.ReportURL)
	case s.LinkProblem != "":
		out = append(out, "report link was not usable: "+s.LinkProblem)
	}
	return out
}

func lowerOnlyNote(n int) string {
	return fmt.Sprintf("%d other application(s) had Medium or Minimal findings "+
		"open or reopen this week. Not listed individually.", n)
}

// tiles totals open findings across every scan that ran to completion.
//
// Including one whose login failed. Those counts are a floor rather than a
// full picture, which the row's own label says - but they are real open
// findings, and dropping them would have the tiles read zero in the week a
// credential broke.
func (r *report) tiles() Counts {
	var c Counts
	for _, s := range r.counted {
		a := s.AppState.Active
		c.Urgent += a.Urgent
		c.Crit += a.Crit
		c.Serious += a.Serious
		c.Medium += a.Medium
		c.Minimal += a.Minimal
	}
	return c
}

// band is one severity tile: Qualys's label and the daily brief's colours.
//
// The colours are the daily's Sev5-Sev1 palette and the LABELS ARE NOT. Qualys
// severity 5 is a claim about one HTTP response; the fleet's Sev5 means
// "exploited in the wild and confirmed present here". Reusing the palette
// keeps one visual language across the fleet's mail; reusing the words would
// let a web finding borrow a KEV entry's urgency, so the footer states the
// scale every time.
type band struct {
	label  string
	n      int
	fg, bg string
}

func (r *report) bands() []band {
	c := r.tiles()
	return []band{
		{"URGENT", c.Urgent, "#b3001b", "#fdecee"},
		{"CRITICAL", c.Crit, "#b25000", "#fff4e5"},
		{"SERIOUS", c.Serious, "#8a6d00", "#fffbe6"},
		{"MEDIUM", c.Medium, "#2c5282", "#ebf4ff"},
		{"MINIMAL", c.Minimal, "#4a5568", "#f4f5f7"},
	}
}

const scaleNote = "Severities are Qualys WAS severities (Urgent down to " +
	"Minimal), NOT the fleet's Sev5-Sev1 bands. A Qualys Urgent is a finding " +
	"in one HTTP response; a fleet Sev5 means exploited in the wild and " +
	"confirmed present in the estate. The two scales are not comparable."

// activeNote says which of Qualys's two count systems these numbers are.
//
// Generic on purpose. The numbers that motivated it - 270 Urgent on record of
// which 247 are fixed, so 23 open - belong to one tenant's application, and
// this repository is public and deliberately carries no estate detail.
const activeNote = "Counts are findings currently open, not lifecycle totals. " +
	"A lifecycle total includes everything the application has ever had, and " +
	"most of that is usually already fixed - it can run an order of magnitude " +
	"higher than the open count."

// ─── the plain-text rendering ───────────────────────────────────────────────

func (r *report) text() string {
	var b strings.Builder
	t := r.title()
	fmt.Fprintf(&b, "%s\n%s\n\n", t, strings.Repeat("=", len(t)))
	fmt.Fprintf(&b, "%s\n", r.leadLine())

	if len(r.scans) == 0 {
		fmt.Fprintf(&b, "\n%s\n", r.credit())
		return b.String()
	}

	if len(r.faults) > 0 {
		section(&b, fmt.Sprintf("SCANNER FAULTS (%d)", len(r.faults)))
		for _, s := range r.faults {
			head, detail := faultLine(s)
			fmt.Fprintf(&b, "  %s\n      %s\n", head, detail)
		}
	}

	section(&b, "OPEN NOW")
	for _, s := range r.counted {
		// 24, not 22: "[authentication FAILED]" is 23 characters, so a 22-wide
		// column pushed the counts out by one on exactly the row a reader is
		// most likely to be comparing against the others.
		fmt.Fprintf(&b, "  %-28s %-24s %s\n", s.App, openLabel(s), lead(s.AppState.Active))
	}
	if len(r.counted) == 0 {
		b.WriteString("  No scan ran to completion this week, so there are no " +
			"counts to report; see SCANNER FAULTS above.\n")
	}
	if n := scopeNote(r.counted); n != "" {
		fmt.Fprintf(&b, "\n  %s\n", n)
	}

	section(&b, "CHANGED THIS WEEK")
	worth, lowerOnly := r.changed()
	if len(worth) == 0 {
		b.WriteString("  Nothing new or reopened at Serious or above.\n")
	}
	for _, s := range worth {
		fmt.Fprintf(&b, "  %-28s %s\n", s.App, strings.Join(changeParts(s), "   "))
		for _, line := range detailLines(s) {
			fmt.Fprintf(&b, "      %s\n", line)
		}
	}
	// Counted, not hidden. Quiet is not the same as absent.
	if lowerOnly > 0 {
		fmt.Fprintf(&b, "  %s\n", lowerOnlyNote(lowerOnly))
	}

	fmt.Fprintf(&b, "\n%s\n%s\n%s\n", scaleNote, activeNote, r.credit())
	return b.String()
}

func section(b *strings.Builder, title string) {
	fmt.Fprintf(b, "\n%s\n%s\n", title, strings.Repeat("-", len(title)))
}

func (r *report) credit() string {
	return fmt.Sprintf("Generated by the %s CTI agent fleet.", r.org)
}

// ─── the HTML rendering ─────────────────────────────────────────────────────
//
// Table layout, inline CSS, 640px, the daily brief's palette and header band.
// Not because it is pleasant to write but because Outlook ignores most of
// everything else, and because a reader should recognise this as one of the
// fleet's emails before reading a word of it.

func (r *report) html() string {
	var b strings.Builder

	fmt.Fprintf(&b, `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title></head>
<body style="margin:0;padding:0;background:#eef1f5">
<table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
       style="background:#eef1f5"><tr><td align="center" style="padding:16px 8px">
<table width="640" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:640px;background:#fff;border-radius:6px;overflow:hidden">

  <tr><td style="background:#12203a;padding:16px 20px">
    <div style="font:700 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;letter-spacing:1.2px;text-transform:uppercase">%s</div>
    <div style="font:700 17px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
      CTI AppSec Weekly</div>
    <div style="font:400 12px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#9fb0cc;margin-top:3px">Week ending %s</div></td></tr>
`, e(r.subject()), e(r.org), e(r.weekEnding.Format("Monday 2 January 2006")))

	// The lead block. Red when something is broken, green when nothing is -
	// the same two states the daily's lead uses.
	leadFg, leadBg := "#2f855a", "#f0fff4"
	if len(r.faults) > 0 {
		leadFg, leadBg = "#b3001b", "#fdecee"
	} else if r.tiles().Urgent > 0 {
		leadFg, leadBg = "#b25000", "#fff4e5"
	}
	fmt.Fprintf(&b, `
  <tr><td style="padding:16px 20px 0 20px">
    <table width="100%%" cellpadding="0" cellspacing="0" role="presentation">
      <tr><td style="background:%s;border-left:4px solid %s;padding:12px 14px;
                     font:400 14px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                     color:#1a202c">%s</td></tr>
    </table></td></tr>
`, leadBg, leadFg, e(r.leadLine()))

	if len(r.scans) == 0 {
		b.WriteString(r.footerHTML())
		return b.String()
	}

	// Tiles.
	b.WriteString(`
  <tr><td style="padding:14px 20px 0 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation"><tr>`)
	for _, t := range r.bands() {
		fmt.Fprintf(&b, `
      <td width="20%%" align="center" style="background:%s;border-top:3px solid %s;
             padding:10px 4px">
        <div style="font:700 24px -apple-system,Segoe UI,Arial,sans-serif;
                    color:%s">%d</div>
        <div style="font:700 10px -apple-system,Segoe UI,Arial,sans-serif;
                    color:%s;letter-spacing:.5px">%s</div></td>`,
			t.bg, t.fg, t.fg, t.n, t.fg, t.label)
	}
	fmt.Fprintf(&b, `
    </tr></table>
    <div style="font:400 11px/1.5 -apple-system,Segoe UI,Arial,sans-serif;
                color:#718096;margin-top:5px">
      Open findings across %d application(s) whose scan ran to completion.
      Qualys WAS severities, not the fleet's Sev bands.</div></td></tr>
`, len(r.counted))

	b.WriteString(`
  <tr><td style="padding:16px 20px 4px 20px">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation">`)

	// Scanner faults. The only loud section, and only when there is one.
	if len(r.faults) > 0 {
		sectionHTML(&b, fmt.Sprintf("SCANNER FAULTS (%d)", len(r.faults)), "#b3001b")
		for _, s := range r.faults {
			head, detail := faultLine(s)
			fmt.Fprintf(&b, `
      <tr><td style="padding:0 0 12px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid #b3001b;background:#fdecee;
                      border-radius:0 4px 4px 0">
          <tr><td style="padding:11px 13px">
            <div style="font:700 14px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#b3001b">%s</div>
            <div style="font:400 13px/1.55 -apple-system,Segoe UI,Helvetica,Arial,
                        sans-serif;color:#1a202c;margin-top:5px">%s</div>
          </td></tr></table></td></tr>`, e(head), e(detail))
		}
	}

	// Open now.
	sectionHTML(&b, "OPEN NOW", "#12203a")
	b.WriteString(`
      <tr><td style="padding:0 0 6px 0">
        <table width="100%" cellpadding="0" cellspacing="0" role="presentation"
               style="font:400 13px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                      border-collapse:collapse">`)
	for _, s := range r.counted {
		// The label is grey, not a warning colour. It describes which surface
		// the number covers; it is not a finding about the application.
		fmt.Fprintf(&b, `
          <tr><td style="padding:6px 8px 6px 0;border-bottom:1px solid #edf2f7;
                         color:#1a202c;font-weight:700">%s</td>
              <td style="padding:6px 8px;border-bottom:1px solid #edf2f7;
                         color:#718096;font-size:11px;white-space:nowrap">%s</td>
              <td align="right" style="padding:6px 0 6px 8px;
                         border-bottom:1px solid #edf2f7;color:#1a202c">%s</td></tr>`,
			e(s.App), e(s.Auth.Label()), e(lead(s.AppState.Active)))
	}
	b.WriteString(`
        </table></td></tr>`)
	if len(r.counted) == 0 {
		itemHTML(&b, "No scan ran to completion this week, so there are no counts "+
			"to report; see SCANNER FAULTS above.")
	}
	if n := scopeNote(r.counted); n != "" {
		fmt.Fprintf(&b, `
      <tr><td style="padding:2px 0 10px 0">
        <div style="font:400 12px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                    color:#744210;background:#fffbe6;padding:8px 10px;
                    border-radius:3px">%s</div></td></tr>`, e(n))
	}

	// Changed this week.
	sectionHTML(&b, "CHANGED THIS WEEK", "#b25000")
	worth, lowerOnly := r.changed()
	if len(worth) == 0 {
		itemHTML(&b, "Nothing new or reopened at Serious or above.")
	}
	for _, s := range worth {
		fmt.Fprintf(&b, `
      <tr><td style="padding:0 0 12px 0">
        <table width="100%%" cellpadding="0" cellspacing="0" role="presentation"
               style="border-left:4px solid #b25000;background:#fff4e5;
                      border-radius:0 4px 4px 0">
          <tr><td style="padding:11px 13px">
            <div style="font:700 14px -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                        color:#1a202c">%s
              <span style="color:#718096;font-weight:400;font-size:11px">
                &middot; %s</span></div>
            <div style="font:400 13px/1.5 -apple-system,Segoe UI,Helvetica,Arial,
                        sans-serif;color:#1a202c;margin-top:5px">%s</div>`,
			e(s.App), e(s.Auth.Label()), changePartsHTML(s))
		for _, line := range detailLines(s) {
			// Monospace and unlinked. These are attacker-reachable paths on our
			// own sites, arriving from mail sent to a published address.
			fmt.Fprintf(&b, `
            <div style="font:400 12px/1.5 ui-monospace,SFMono-Regular,Menlo,
                        Consolas,monospace;color:#2d3748;background:#fff;
                        border:1px solid #f0e0c8;border-radius:3px;
                        padding:5px 7px;margin-top:5px;word-break:break-word">%s</div>`,
				e(line))
		}
		b.WriteString(`
          </td></tr></table></td></tr>`)
	}
	if lowerOnly > 0 {
		itemHTML(&b, lowerOnlyNote(lowerOnly))
	}

	b.WriteString(`
    </table></td></tr>`)
	b.WriteString(r.footerHTML())
	return b.String()
}

func (r *report) footerHTML() string {
	return fmt.Sprintf(`
  <tr><td style="padding:8px 20px 18px 20px;border-top:1px solid #e2e8f0">
    <div style="font:400 11px/1.6 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                color:#718096">
      %s<br>
      %s<br>
      Every URL above is plain text by design &mdash; these are attacker-reachable
      paths on our own applications, assembled from mail sent to a published
      address.<br>
      %s
    </div></td></tr>

</table></td></tr></table></body></html>`,
		e(scaleNote), e(activeNote), e(r.credit()))
}

// sectionHTML is the underlined caps heading the daily uses for its bands.
func sectionHTML(b *strings.Builder, title, colour string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:6px 0 8px 0">
        <div style="font:700 13px -apple-system,Segoe UI,Arial,sans-serif;
                    color:%s;letter-spacing:.6px;text-transform:uppercase;
                    border-bottom:2px solid %s;padding-bottom:5px">%s</div></td></tr>`,
		colour, colour, e(title))
}

func itemHTML(b *strings.Builder, s string) {
	fmt.Fprintf(b, `
      <tr><td style="padding:0 0 12px 0">
        <div style="font:400 13px/1.55 -apple-system,Segoe UI,Helvetica,Arial,
                    sans-serif;color:#4a5568">%s</div></td></tr>`, e(s))
}

// ─── shared number formatting ───────────────────────────────────────────────

// counts renders every band, omitting empty ones.
//
// "0 Urgent, 0 Critical, 0 Serious, 0 Medium, 2 Minimal" is five numbers to
// read before finding the one that is not zero.
func counts(c Counts) string {
	var p []string
	for _, b := range []struct {
		n     int
		label string
	}{
		{c.Urgent, "Urgent"},
		{c.Crit, "Critical"},
		{c.Serious, "Serious"},
		{c.Medium, "Medium"},
		{c.Minimal, "Minimal"},
	} {
		if b.n > 0 {
			p = append(p, fmt.Sprintf("%d %s", b.n, b.label))
		}
	}
	if len(p) == 0 {
		return "nothing open"
	}
	return strings.Join(p, " - ")
}

// lead renders Serious and above, with Medium and Minimal as a tail count.
//
// Medium and Minimal are real findings and are not hidden. But a line reading
// "0 Urgent - 0 Critical - 1 Serious - 2 Medium - 67 Minimal" puts 67 where
// the eye lands, and 67 Minimal findings on a web application is weather, not
// news.
//
// The tail is there because silence and zero must not look the same. "23
// Urgent - 21 Serious" with nothing after it would read as an application
// with no Medium or Minimal findings at all, which is a different and
// untrue claim.
func lead(c Counts) string {
	var p []string
	for _, b := range []struct {
		n     int
		label string
	}{
		{c.Urgent, "Urgent"},
		{c.Crit, "Critical"},
		{c.Serious, "Serious"},
	} {
		if b.n > 0 {
			p = append(p, fmt.Sprintf("%d %s", b.n, b.label))
		}
	}
	lower := c.Medium + c.Minimal
	switch {
	case len(p) == 0 && lower == 0:
		return "nothing open"
	case len(p) == 0:
		return fmt.Sprintf("nothing at Serious or above (%d lower)", lower)
	case lower == 0:
		return strings.Join(p, " - ")
	}
	return fmt.Sprintf("%s  (+%d lower)", strings.Join(p, " - "), lower)
}

// sortScans orders worst first, then by name so two runs over the same week
// produce the same document.
func sortScans(s []ScanResult) {
	sort.SliceStable(s, func(i, j int) bool {
		a, b := s[i], s[j]
		if a.Attention() != b.Attention() {
			return a.Attention()
		}
		if x, y := a.AppState.Active.Worst(), b.AppState.Active.Worst(); x != y {
			return x > y
		}
		return a.App < b.App
	})
}
