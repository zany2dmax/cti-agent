package vmscan

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// DefaultScans are the two scheduled scans the weekly combines, by title.
var DefaultScans = []string{"Weekly Scheduled Scan for non-REDACTED-SUB/REDACTED-SUB", "REDACTED-SUB/REDACTED-SUB Weekly"}

// Week is the combined picture: for each expected scan, its newest result.
type Week struct {
	// Scans holds one entry per expected title that has a result, in the
	// expected order.
	Scans []Scan
	// Missing are expected titles with no result in the window. A scheduled
	// scan that left no notice did not finish, or its mail never arrived, and
	// either is worth saying first.
	Missing []string
	// Other are results for scans that were not expected, newest first. They
	// are listed, not reported on.
	Other []Scan
}

func norm(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// Combine picks, for each expected title, the newest result in scans.
//
// Two notices for one run (the same report reference) count once. Titles are
// compared ignoring case and spacing, since a scan renamed in Qualys by a
// trailing space should still be found.
func Combine(scans []Scan, expected []string) Week {
	seen := map[string]bool{}
	var uniq []Scan
	for _, s := range scans {
		if s.Ref != "" {
			if seen[s.Ref] {
				continue
			}
			seen[s.Ref] = true
		}
		uniq = append(uniq, s)
	}
	best := map[string]Scan{}
	var other []Scan
	want := map[string]bool{}
	for _, t := range expected {
		want[norm(t)] = true
	}
	for _, s := range uniq {
		k := norm(s.Title)
		if !want[k] {
			other = append(other, s)
			continue
		}
		if cur, ok := best[k]; !ok || s.Start.After(cur.Start) {
			best[k] = s
		}
	}
	var w Week
	for _, t := range expected {
		if s, ok := best[norm(t)]; ok {
			w.Scans = append(w.Scans, s)
		} else {
			w.Missing = append(w.Missing, t)
		}
	}
	sort.SliceStable(other, func(i, j int) bool { return other[i].Start.After(other[j].Start) })
	w.Other = other
	return w
}

// Block is a rendered report.
type Block struct {
	Subject string
	Text    string
	HTML    string
}

var sevNames = [6]string{"", "Minimal", "Medium", "Serious", "Critical", "Urgent"}

func e(s string) string { return html.EscapeString(s) }

func (w Week) incomplete() []Scan {
	var out []Scan
	for _, s := range w.Scans {
		if !s.Finished() {
			out = append(out, s)
		}
	}
	return out
}

func (w Week) total(sev int) int {
	n := 0
	for _, s := range w.Scans {
		n += s.Confirmed[sev].Total
	}
	return n
}

// Subject names the most actionable thing first: a scan that left no result,
// then one that did not finish, then the Urgent count.
func (w Week) Subject(org string, weekEnding time.Time) string {
	label := org + " VM Scans Weekly " + weekEnding.Format("Jan 02")
	switch {
	case len(w.Missing) > 0:
		return fmt.Sprintf("[NO RESULT] %s: %d scheduled scan(s) left no result", label, len(w.Missing))
	case len(w.incomplete()) > 0:
		return fmt.Sprintf("[INCOMPLETE] %s: %d scan(s) did not finish", label, len(w.incomplete()))
	}
	return fmt.Sprintf("%s: %d Urgent and %d Critical open across %d scans",
		label, w.total(5), w.total(4), len(w.Scans))
}

func (w Week) leadLine() string {
	if len(w.Missing) > 0 {
		return "No result came back for: " + strings.Join(w.Missing, "; ") +
			". Either the scan did not finish or its notice never arrived, so the totals below " +
			"are not the whole estate."
	}
	if inc := w.incomplete(); len(inc) > 0 {
		var t []string
		for _, s := range inc {
			t = append(t, fmt.Sprintf("%s (%s)", s.Title, strings.TrimSpace(s.Status)))
		}
		return "Not every scan ran to completion: " + strings.Join(t, "; ") +
			". Its counts describe a partial scan."
	}
	hosts, active := 0, 0
	for _, s := range w.Scans {
		hosts += s.HostsScanned
		active += s.ActiveHosts
	}
	return fmt.Sprintf("%d scheduled scans finished, covering %d addresses of which %d were alive. "+
		"Each is shown separately below; the tiles add them.", len(w.Scans), hosts, active)
}

func trend(c Counts) string {
	return fmt.Sprintf("+%d new, %d reopened, %d active, %d fixed", c.New, c.Reopened, c.Active, -c.Closed)
}

// Text is the plain-text report.
func (w Week) Text(org string, weekEnding time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%s\n\n", w.Subject(org, weekEnding), strings.Repeat("=", 72))
	fmt.Fprintf(&b, "%s\n\n", w.leadLine())
	for _, s := range w.Scans {
		fmt.Fprintf(&b, "%s\n%s\n", strings.ToUpper(s.Title), strings.Repeat("-", 72))
		fmt.Fprintf(&b, "  Started %s, ran %s, %s\n", s.Start.UTC().Format("Mon 2 Jan 15:04 MST"),
			FormatDuration(s.Duration), strings.TrimSpace(s.Status))
		fmt.Fprintf(&b, "  Addresses scanned %d, alive %d\n", s.HostsScanned, s.ActiveHosts)
		fmt.Fprintf(&b, "  Target groups (%d): %s\n\n", len(s.TargetGroups), strings.Join(s.TargetGroups, ", "))
		fmt.Fprintf(&b, "  %-9s %7s   %s\n", "Confirmed", "open", "since the last scan")
		for sev := 5; sev >= 1; sev-- {
			fmt.Fprintf(&b, "  %-9s %7d   %s\n", sevNames[sev], s.Confirmed[sev].Total, trend(s.Confirmed[sev]))
		}
		fmt.Fprintf(&b, "  Potential (not confirmed): %d, of which Urgent %d, Critical %d\n",
			s.Potential.Sum(), s.Potential[5].Total, s.Potential[4].Total)
		if s.ReportURL != "" {
			fmt.Fprintf(&b, "  Full report in Qualys: %s\n", s.ReportURL)
		}
		b.WriteString("\n")
	}
	if len(w.Other) > 0 {
		var t []string
		for _, s := range w.Other {
			t = append(t, s.Title)
		}
		fmt.Fprintf(&b, "Other scans that reported this week, not covered here: %s\n\n", strings.Join(t, "; "))
	}
	b.WriteString("Severities are Qualys VM severities. Potential findings are listed apart, not added to the confirmed counts.\n")
	b.WriteString(emailkit.CreditText(org, "cti-vmscan", "Generated by the "+org+" fleet") + "\n")
	return b.String()
}

// HTML is the combined email.
func (w Week) HTML(org string, weekEnding time.Time) string {
	var b strings.Builder
	emailkit.Open(&b, w.Subject(org, weekEnding), org, org+" VM Scans Weekly",
		"Week ending "+weekEnding.Format("Monday 2 January 2006"))

	lead := emailkit.Green
	switch {
	case len(w.Missing) > 0 || len(w.incomplete()) > 0:
		lead = emailkit.Red
	case w.total(5) > 0:
		lead = emailkit.Amber
	}
	emailkit.Lead(&b, lead, e(w.leadLine()))

	if len(w.Scans) > 0 {
		tiles := []emailkit.Tile{
			{Label: "Urgent", N: w.total(5), Tone: emailkit.Red},
			{Label: "Critical", N: w.total(4), Tone: emailkit.Amber},
			{Label: "Serious", N: w.total(3), Tone: emailkit.Yellow},
			{Label: "Medium", N: w.total(2), Tone: emailkit.Blue},
			{Label: "Minimal", N: w.total(1), Tone: emailkit.Grey},
		}
		emailkit.Tiles(&b, tiles, "Confirmed open vulnerabilities added across the scans below. "+
			"Qualys VM severities. Potential findings are listed apart.")
	}

	emailkit.BodyOpen(&b)
	for _, t := range w.Missing {
		emailkit.Card(&b, emailkit.Red, "NO RESULT: "+t,
			"No results notice arrived in the window. Check the schedule in Qualys, and that "+
				"its notifications still reach this mailbox.")
	}
	for _, s := range w.Scans {
		tone := emailkit.Blue
		if !s.Finished() {
			tone = emailkit.Red
		}
		var l strings.Builder
		fmt.Fprintf(&l, "Started %s, ran %s, <b>%s</b>.<br>", e(s.Start.UTC().Format("Mon 2 Jan 15:04 MST")),
			e(FormatDuration(s.Duration)), e(strings.TrimSpace(s.Status)))
		fmt.Fprintf(&l, "%d addresses scanned, %d alive.<br><br>", s.HostsScanned, s.ActiveHosts)
		l.WriteString(`<table cellpadding="0" cellspacing="0" style="font:400 13px/1.6 monospace">`)
		for sev := 5; sev >= 1; sev-- {
			fmt.Fprintf(&l, `<tr><td style="padding-right:14px">%s</td><td align="right" style="padding-right:14px">%d</td><td>%s</td></tr>`,
				sevNames[sev], s.Confirmed[sev].Total, e(trend(s.Confirmed[sev])))
		}
		l.WriteString("</table>")
		fmt.Fprintf(&l, "<br>Potential, not confirmed: %d (Urgent %d, Critical %d).<br><br>",
			s.Potential.Sum(), s.Potential[5].Total, s.Potential[4].Total)
		fmt.Fprintf(&l, "<b>Target groups (%d):</b> %s", len(s.TargetGroups), e(strings.Join(s.TargetGroups, ", ")))
		if s.ReportURL != "" {
			fmt.Fprintf(&l, `<br><br>Full report in Qualys (plain text, by design): <span style="font-family:monospace">%s</span>`, e(s.ReportURL))
		}
		emailkit.Card(&b, tone, s.Title, l.String())
	}
	emailkit.BodyClose(&b)

	if len(w.Other) > 0 {
		var t []string
		for _, s := range w.Other {
			t = append(t, e(s.Title))
		}
		emailkit.Note(&b, "Other scans that reported this week, not covered here: "+strings.Join(t, "; "))
	}
	emailkit.Foot(&b,
		"Severities are Qualys VM severities; potential findings are not added to the confirmed counts.",
		emailkit.Credit(org, "cti-vmscan", "Generated by the "+org+" fleet"))
	return b.String()
}

// Render builds the report block.
func Render(w Week, org string, weekEnding time.Time) Block {
	return Block{Subject: w.Subject(org, weekEnding), Text: w.Text(org, weekEnding), HTML: w.HTML(org, weekEnding)}
}
