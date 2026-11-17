package vmscan

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// EVERY SCHEDULED SCAN COUNTS
//
// The weekly reports every scheduled VM scan whose results notice arrived in
// the window, and the coverage check uses all of their Target Groups. It used
// to report only the scans named in VMSCAN_SCANS: when the scans were renamed
// in Qualys the names stopped matching, the real scan was filed as "other",
// and the coverage check compared every location against nothing. A list of
// names to expect is still useful - a named scan that sends nothing is the
// clearest sign one stopped - so VMSCAN_SCANS remains, as that list only.
//
// A scan launched by hand (Launch Type other than Scheduled) is listed but not
// counted: one person's one-off scan does not make a location covered.

// Scheduled reports whether a notice is from a scheduled scan.
func (s Scan) Scheduled() bool {
	return strings.EqualFold(strings.TrimSpace(s.LaunchType), "scheduled")
}

// Reported reports whether a scan belongs in the week: every scheduled scan,
// and any scan named in expected however it was launched.
func Reported(s Scan, expected []string) bool {
	if s.Scheduled() {
		return true
	}
	for _, t := range expected {
		if norm(t) == norm(s.Title) {
			return true
		}
	}
	return false
}

// Week is the combined picture: the newest result of each scheduled scan in the window.
type Week struct {
	// Scans holds the newest result of each scheduled scan in the window (and
	// of any expected scan): the expected titles first, in their order, then
	// the rest by title.
	Scans []Scan
	// Missing are expected titles with no result in the window. A scheduled
	// scan that left no notice did not finish, or its mail never arrived, and
	// either is worth saying first.
	Missing []string
	// Other are scans launched by hand, newest first. They are listed, not
	// reported on or counted for coverage.
	Other []Scan
	// Coverage is the check of the scans' locations against the network
	// spreadsheet; nil when it was not asked for.
	Coverage *Coverage
	// ListUnavailable is why Qualys's scan list could not be read, so the
	// week is built from the notices alone; empty when it was read.
	ListUnavailable string
}

// noNotice is the reported scans whose results notice did not arrive.
func (w Week) noNotice() []Scan {
	var out []Scan
	for _, s := range w.Scans {
		if s.NoNotice {
			out = append(out, s)
		}
	}
	return out
}

func norm(s string) string { return strings.ToLower(strings.Join(strings.Fields(s), " ")) }

// Combine picks the newest result of each reported scan (see Reported), and
// names the expected titles that have none.
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
	for _, s := range uniq {
		if !Reported(s, expected) {
			other = append(other, s)
			continue
		}
		k := norm(s.Title)
		if cur, ok := best[k]; !ok || s.Start.After(cur.Start) {
			best[k] = s
		}
	}
	var w Week
	placed := map[string]bool{}
	for _, t := range expected {
		k := norm(t)
		if placed[k] {
			continue
		}
		placed[k] = true
		if s, ok := best[k]; ok {
			w.Scans = append(w.Scans, s)
		} else {
			w.Missing = append(w.Missing, t)
		}
	}
	var rest []Scan
	for k, s := range best {
		if !placed[k] {
			rest = append(rest, s)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return norm(rest[i].Title) < norm(rest[j].Title) })
	w.Scans = append(w.Scans, rest...)
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

// groups is the number of distinct Target Groups across the reported scans.
func (w Week) groups() int {
	seen := map[string]bool{}
	for _, s := range w.Scans {
		for _, g := range s.TargetGroups {
			seen[norm(g)] = true
		}
	}
	return len(seen)
}

// Subject names the most actionable thing first: a scan that left no result,
// then one that did not finish, then simply that they ran.
func (w Week) Subject(org string, weekEnding time.Time) string {
	label := org + " VM Scans Weekly " + weekEnding.Format("Jan 02")
	switch {
	case len(w.Missing) > 0:
		return fmt.Sprintf("[NO RESULT] %s: %d scheduled scan(s) left no result", label, len(w.Missing))
	case len(w.Scans) == 0:
		return fmt.Sprintf("[NO RESULT] %s: no scheduled scan reported this week", label)
	case len(w.incomplete()) > 0:
		return fmt.Sprintf("[INCOMPLETE] %s: %d scan(s) did not finish", label, len(w.incomplete()))
	}
	if n := len(w.Coverage.Gaps()); n > 0 {
		return fmt.Sprintf("%s: %d scheduled scans ran, %d locations covered, %d network(s) NOT SCANNED",
			label, len(w.Scans), w.groups(), n)
	}
	return fmt.Sprintf("%s: %d scheduled scans ran, %d locations covered", label, len(w.Scans), w.groups())
}

func (w Week) leadLine() string {
	if len(w.Missing) == 0 && len(w.Scans) == 0 {
		if w.ListUnavailable == "" {
			return "Qualys lists no scheduled scan this week, so nothing below says what was scanned. " +
				"Check the schedules in Qualys."
		}
		return "No scheduled scan's results notice arrived this week, so nothing below says what was " +
			"scanned. Check the schedules in Qualys, and that their notifications still reach this mailbox."
	}
	if len(w.Missing) > 0 {
		return "No result came back for: " + strings.Join(w.Missing, "; ") +
			". Either the scan did not finish or its notice never arrived, so the coverage " +
			"below is not the whole estate."
	}
	if inc := w.incomplete(); len(inc) > 0 {
		var t []string
		for _, s := range inc {
			t = append(t, fmt.Sprintf("%s (%s)", s.Title, strings.TrimSpace(s.Status)))
		}
		return "Not every scan ran to completion: " + strings.Join(t, "; ") +
			". What it covered below is what it was asked to scan, not what it finished."
	}
	hosts, active := 0, 0
	for _, s := range w.Scans {
		hosts += s.HostsScanned
		active += s.ActiveHosts
	}
	ran := "The scheduled scan ran and finished."
	if len(w.Scans) > 1 {
		ran = fmt.Sprintf("All %d scheduled scans ran and finished.", len(w.Scans))
	}
	lead := fmt.Sprintf("%s Together they covered %d locations (%d addresses scanned, %d alive). "+
		"Each scan is listed separately below.", ran, w.groups(), hosts, active)
	if nn := w.noNotice(); len(nn) > 0 {
		var t []string
		for _, s := range nn {
			t = append(t, s.Title)
		}
		lead = fmt.Sprintf("%s Together they covered %d locations. Qualys lists every scan as finished, but "+
			"the results notice of %s never arrived (mail lost or late), so its host counts are not "+
			"shown. Each scan is listed separately below.", ran, w.groups(), strings.Join(t, "; "))
	}
	if n := len(w.Coverage.Gaps()); n > 0 {
		lead += fmt.Sprintf(" The coverage check found %d network(s) in the network spreadsheet that the scans do not reach.", n)
	}
	return lead
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
		if s.NoNotice {
			b.WriteString("  Results notice did not arrive; from the Qualys scan list, so host counts are unknown\n")
		} else {
			fmt.Fprintf(&b, "  Addresses scanned %d, alive %d\n", s.HostsScanned, s.ActiveHosts)
		}
		fmt.Fprintf(&b, "  Locations covered (%d):\n", len(s.TargetGroups))
		for _, g := range s.TargetGroups {
			fmt.Fprintf(&b, "    %s\n", g)
		}
		b.WriteString("\n")
	}
	if w.ListUnavailable != "" {
		fmt.Fprintf(&b, "Qualys's scan list could not be read (%s), so this week is built from the results "+
			"notices alone: a scan whose notice was lost is missing from it.\n\n", w.ListUnavailable)
	}
	b.WriteString(w.Coverage.text())
	if len(w.Other) > 0 {
		var t []string
		for _, s := range w.Other {
			t = append(t, s.Title)
		}
		fmt.Fprintf(&b, "Scans launched by hand this week, not counted here: %s\n\n", strings.Join(t, "; "))
	}
	b.WriteString("Locations are the Qualys Target Groups each scan was configured to cover.\n")
	b.WriteString(emailkit.CreditText(org, "cti-vmscan", "Generated by the "+org+" fleet") + "\n")
	return b.String()
}

// HTML is the combined email.
func (w Week) HTML(org string, weekEnding time.Time) string {
	var b strings.Builder
	emailkit.Open(&b, w.Subject(org, weekEnding), org, "VM Scans Weekly",
		"Week ending "+weekEnding.Format("Monday 2 January 2006"))

	lead := emailkit.Green
	if len(w.Missing) > 0 || len(w.Scans) == 0 || len(w.incomplete()) > 0 {
		lead = emailkit.Red
	} else if len(w.Coverage.Gaps()) > 0 {
		lead = emailkit.Amber
	}
	emailkit.Lead(&b, lead, e(w.leadLine()))

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
		if s.NoNotice {
			l.WriteString("Its results notice did not arrive (mail lost or late). This is from the Qualys " +
				"scan list, so the host counts are not known.<br><br>")
		} else {
			fmt.Fprintf(&l, "%d addresses scanned, %d alive.<br><br>", s.HostsScanned, s.ActiveHosts)
		}
		fmt.Fprintf(&l, "<b>Locations covered (%d):</b><br>", len(s.TargetGroups))
		for i, g := range s.TargetGroups {
			if i > 0 {
				l.WriteString(" &middot; ")
			}
			l.WriteString(e(g))
		}
		emailkit.Card(&b, tone, s.Title, l.String())
	}
	if w.ListUnavailable != "" {
		emailkit.Item(&b, "Qualys's scan list could not be read ("+e(w.ListUnavailable)+"), so this week is "+
			"built from the results notices alone: a scan whose notice was lost is missing from it.")
	}
	w.Coverage.html(&b)
	emailkit.BodyClose(&b)

	if len(w.Other) > 0 {
		var t []string
		for _, s := range w.Other {
			t = append(t, e(s.Title))
		}
		emailkit.Note(&b, "Scans launched by hand this week, not counted here: "+strings.Join(t, "; "))
	}
	emailkit.Foot(&b,
		"Locations are the Qualys Target Groups each scan was configured to cover.",
		emailkit.Credit(org, "cti-vmscan", "Generated by the "+org+" fleet"))
	return b.String()
}

// Render builds the report block.
func Render(w Week, org string, weekEnding time.Time) Block {
	return Block{Subject: w.Subject(org, weekEnding), Text: w.Text(org, weekEnding), HTML: w.HTML(org, weekEnding)}
}
