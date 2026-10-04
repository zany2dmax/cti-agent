package appscan

import (
	"fmt"
	"html"
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
// # THE ORDER IS THE ARGUMENT
//
// Coverage gaps come FIRST, before any vulnerability count. A scan that ran
// without authentication did not find nothing - it was never able to look.
// Reporting its zeroes alongside real results, sorted by severity, puts the
// least-known application at the bottom of the page looking like the best one.
//
// Then what is open now, then what changed. Not lifecycle totals: one real
// application here carries 270 "Urgent" on record of which 247 are Fixed, and
// leading with 270 would be a false alarm an order of magnitude too large.
//
// # NOTHING IS CLICKABLE
//
// Every URL renders as plain text. These reports are assembled from mail that
// arrived at a published address, and the findings themselves name attacker-
// reachable paths on our own sites. Neither belongs in an anchor.
func Render(week []ScanResult, weekEnding time.Time) Block {
	scans := append([]ScanResult(nil), week...)
	sortScans(scans)

	var blind, incomplete, ok []ScanResult
	for _, s := range scans {
		switch {
		case !s.Complete:
			incomplete = append(incomplete, s)
		case s.Auth.Blind():
			blind = append(blind, s)
		default:
			ok = append(ok, s)
		}
	}

	var t, h strings.Builder
	title := fmt.Sprintf("Application security - week ending %s",
		weekEnding.Format("2 January 2006"))
	fmt.Fprintf(&t, "%s\n%s\n", title, strings.Repeat("=", len(title)))
	fmt.Fprintf(&h, "<h2>%s</h2>\n", html.EscapeString(title))

	if len(scans) == 0 {
		const none = "No completed web application scans this week. That is " +
			"either a quiet week or a scheduling problem; the scan schedule in " +
			"Qualys is the place to tell which."
		fmt.Fprintf(&t, "%s\n", none)
		fmt.Fprintf(&h, "<p>%s</p>\n", html.EscapeString(none))
		return Block{Subject: subject(nil, nil, weekEnding), Text: t.String(), HTML: h.String()}
	}

	renderCoverage(&t, &h, blind, incomplete)
	renderOpen(&t, &h, ok, blind)
	renderChanged(&t, &h, scans)

	return Block{
		Subject: subject(ok, blind, weekEnding),
		Text:    t.String(),
		HTML:    h.String(),
	}
}

// subject leads with the thing most likely to need action.
//
// A coverage gap outranks a finding count. "Three applications have open
// Urgent findings" is a known quantity somebody is already working through;
// "one application cannot be assessed" is a question nobody has answered.
func subject(ok, blind []ScanResult, weekEnding time.Time) string {
	wk := weekEnding.Format("Jan 2")
	if len(blind) > 0 {
		return fmt.Sprintf("[AppSec] Week of %s: %d application(s) scanned without authentication",
			wk, len(blind))
	}
	urgent := 0
	for _, s := range ok {
		urgent += s.AppState.Active.Urgent
	}
	if urgent > 0 {
		return fmt.Sprintf("[AppSec] Week of %s: %d Urgent finding(s) open", wk, urgent)
	}
	return fmt.Sprintf("[AppSec] Week of %s: nothing urgent open", wk)
}

func renderCoverage(t, h *strings.Builder, blind, incomplete []ScanResult) {
	if len(blind) == 0 && len(incomplete) == 0 {
		return
	}
	head := fmt.Sprintf("COVERAGE GAPS (%d)", len(blind)+len(incomplete))
	section(t, h, head)

	for _, s := range blind {
		reason := "no authentication record configured"
		if s.Auth.Record != "" {
			reason = fmt.Sprintf("authentication configured but %s", strings.ToLower(s.Auth.Status))
		}
		line := fmt.Sprintf("%s - %s", s.App, reason)
		detail := fmt.Sprintf(
			"%d links crawled, %d Urgent, %d Critical. An unauthenticated scan "+
				"tests only the public surface, so these numbers are not evidence "+
				"that the application is clean.",
			s.LinksCrawled, s.ScanCounts.Urgent, s.ScanCounts.Crit)
		item(t, h, line, detail)
	}
	for _, s := range incomplete {
		item(t, h, fmt.Sprintf("%s - scan did not complete (%s)", s.App, s.Status),
			"Counts from a partial crawl describe a measurement that was never "+
				"finished, so none are reported for this application.")
	}
}

func renderOpen(t, h *strings.Builder, ok, blind []ScanResult) {
	section(t, h, "OPEN NOW")

	all := append(append([]ScanResult(nil), ok...), blind...)
	sortScans(all)
	for _, s := range all {
		a := s.AppState.Active
		line := fmt.Sprintf("%-28s %s", s.App, lead(a))
		if s.Auth.Blind() {
			// The caveat travels with the number, every time it is printed.
			// A zero from a blind scan read on its own is the whole problem.
			line += "   [unauthenticated - see above]"
		}
		item(t, h, line, "")
	}
}

func renderChanged(t, h *strings.Builder, scans []ScanResult) {
	// The same floor Attention() uses. The two disagreeing is how an
	// unauthenticated scan's five reopened Minimal findings ended up as the
	// lead item in the section meant to carry the week's actionable news.
	var changed []ScanResult
	lowerOnly := 0
	for _, s := range scans {
		// An incomplete scan's counts are withheld in the coverage section
		// above, so printing them here would make the report contradict
		// itself - and the second number is the one people act on.
		if !s.Complete {
			continue
		}
		n, r := s.AppState.New, s.AppState.Reopened
		if n.Urgent+n.Crit+n.Serious+r.Urgent+r.Crit+r.Serious > 0 {
			changed = append(changed, s)
		} else if n.Total()+r.Total() > 0 {
			lowerOnly++
		}
	}
	section(t, h, "CHANGED THIS WEEK")
	if len(changed) == 0 {
		item(t, h, "Nothing new or reopened at Serious or above.", "")
	}
	for _, s := range changed {
		var parts []string
		if n := s.AppState.New; n.Total() > 0 {
			parts = append(parts, "new: "+counts(n))
		}
		if r := s.AppState.Reopened; r.Total() > 0 {
			parts = append(parts, "reopened: "+counts(r))
		}
		item(t, h, fmt.Sprintf("%-28s %s", s.App, strings.Join(parts, "   ")), "")

		// Per-finding detail, when the API filled it in. Only NEW and REOPENED:
		// the backlog is a programme, what appeared since the last scan is the
		// thing a weekly report exists to surface.
		shown := 0
		var worth []Finding
		for _, f := range s.Findings {
			if f.Status == "NEW" || f.Status == "REOPENED" {
				worth = append(worth, f)
			}
		}
		sort.SliceStable(worth, func(i, j int) bool { return worth[i].Severity > worth[j].Severity })
		for _, f := range worth {
			if shown >= maxDetail {
				more := fmt.Sprintf("... and %d more; the full list is in Qualys",
					len(worth)-shown)
				sub(t, h, more)
				break
			}
			detail := fmt.Sprintf("sev %d  %s  %s", f.Severity, f.ID, f.Title)
			if f.URL != "" {
				detail += "\n        " + f.URL
				if f.Param != "" {
					detail += "  (parameter: " + f.Param + ")"
				}
			}
			sub(t, h, detail)
			shown++
		}
		if len(s.Findings) == 0 {
			sub(t, h, "(per-finding detail not available for this run - "+
				"counts are from the scan notification)")
		}
		if s.ReportURL != "" {
			sub(t, h, "report: "+s.ReportURL)
		} else if s.LinkProblem != "" {
			sub(t, h, "report link was not usable: "+s.LinkProblem)
		}
	}

	// Counted, not hidden. Quiet is not the same as absent.
	if lowerOnly > 0 {
		item(t, h, fmt.Sprintf(
			"%d other application(s) had Medium or Minimal findings open or "+
				"reopen this week. Not listed individually.", lowerOnly), "")
	}
}

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

func section(t, h *strings.Builder, title string) {
	fmt.Fprintf(t, "\n%s\n%s\n", title, strings.Repeat("-", len(title)))
	fmt.Fprintf(h, "<h3>%s</h3>\n", html.EscapeString(title))
}

func item(t, h *strings.Builder, line, detail string) {
	fmt.Fprintf(t, "  %s\n", line)
	fmt.Fprintf(h, "<p>%s", html.EscapeString(line))
	if detail != "" {
		fmt.Fprintf(t, "      %s\n", detail)
		fmt.Fprintf(h, "<br><small>%s</small>", html.EscapeString(detail))
	}
	h.WriteString("</p>\n")
}

func sub(t, h *strings.Builder, s string) {
	fmt.Fprintf(t, "      %s\n", s)
	fmt.Fprintf(h, "<p style=\"margin-left:2em\"><code>%s</code></p>\n",
		html.EscapeString(s))
}
