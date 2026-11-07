package vmscan

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/netmap"
)

// Coverage is the result of checking the scans' locations against the network
// spreadsheet, or the reason it could not be checked.
//
// It is written for the people who have to act on it: the security team (add a
// network to Qualys) and the network and acquisitions teams (fix or add to the
// spreadsheet), so every line names the location, the spreadsheet row and what
// to do about it.
type Coverage struct {
	Checked   int
	Covered   int
	Findings  []netmap.Finding
	Questions []netmap.Question
	// Unavailable is why the check did not run; empty when it did. A check that
	// could not run is said so in the report, never presented as a clean result.
	Unavailable string
}

// Gaps are the findings that mean a network is not being scanned.
func (c *Coverage) Gaps() []netmap.Finding {
	var out []netmap.Finding
	if c == nil {
		return nil
	}
	for _, f := range c.Findings {
		switch f.Kind {
		case netmap.NotInAnyGroup, netmap.GroupNotScanned, netmap.PartlyCovered:
			out = append(out, f)
		}
	}
	return out
}

// Oddities are findings about the scans' own groups: a scanned group whose
// addresses are not in the spreadsheet, or a Target Group Qualys does not list.
func (c *Coverage) Oddities() []netmap.Finding {
	var out []netmap.Finding
	if c == nil {
		return nil
	}
	for _, f := range c.Findings {
		if f.Kind == netmap.ScannedNotInSheet || f.Kind == netmap.UnknownTargetGroup {
			out = append(out, f)
		}
	}
	return out
}

func rowRef(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" (sheet row %d)", n)
}

// gapLine is one network that is not scanned, and what to do.
func gapLine(f netmap.Finding) string {
	switch f.Kind {
	case netmap.NotInAnyGroup:
		return fmt.Sprintf("%s%s: %s is in no Qualys Asset Group.", f.Location, rowRef(f.Row), f.Subnet)
	case netmap.GroupNotScanned:
		return fmt.Sprintf("%s%s: %s is in the Asset Group %q, which neither weekly scan covers.", f.Location, rowRef(f.Row), f.Subnet, f.Group)
	default:
		return fmt.Sprintf("%s%s: only part of %s is in the groups the weekly scans cover.", f.Location, rowRef(f.Row), f.Subnet)
	}
}

func gapAction(k netmap.Kind) string {
	switch k {
	case netmap.NotInAnyGroup:
		return "Create a Qualys Asset Group for this network and add it to a scheduled scan."
	case netmap.GroupNotScanned:
		return "Add this Asset Group to a scheduled scan, or confirm another scan already covers it."
	default:
		return "Extend the Asset Group(s) to the whole network, or correct the spreadsheet if it is the sheet that is wrong."
	}
}

// questionAction is what the network team is asked to do. The security team only
// reads the spreadsheet; where it is wrong or unclear the fix is the network
// team's, so none of these asks the security team to work around it.
func questionAction(k netmap.QuestionKind) string {
	switch k {
	case netmap.QBlank:
		return "Network team: fill in this location's corp network."
	case netmap.QInvalid:
		return "Network team: correct the network. It is not a valid CIDR (for example 10.4.30.0/24)."
	case netmap.QOutside:
		return "Network team: this corp network is outside the location's own block, so one of the two has a typo. Correct it."
	case netmap.QOverlap:
		return "Network team: two locations claim overlapping networks. Correct one of them."
	default:
		return "Network team: label the location's corporate network row corp, so it can be checked. If the location has no corporate network (cloud only, for example), say so."
	}
}

func questionTitle(k netmap.QuestionKind) string {
	switch k {
	case netmap.QBlank:
		return "Corp row with no network written in it"
	case netmap.QInvalid:
		return "Corp network that is not a valid CIDR"
	case netmap.QOutside:
		return "Corp network outside the location's own block"
	case netmap.QOverlap:
		return "Networks that overlap another location's"
	default:
		return "No row counts as the location's corp network"
	}
}

var questionOrder = []netmap.QuestionKind{netmap.QBlank, netmap.QInvalid, netmap.QOutside, netmap.QOverlap, netmap.QNoCorpRow}

func (c *Coverage) questionsOf(k netmap.QuestionKind) []netmap.Question {
	var out []netmap.Question
	for _, q := range c.Questions {
		if q.Kind == k {
			out = append(out, q)
		}
	}
	return out
}

func (c *Coverage) gapsOf(k netmap.Kind) []netmap.Finding {
	var out []netmap.Finding
	for _, f := range c.Gaps() {
		if f.Kind == k {
			out = append(out, f)
		}
	}
	return out
}

func oddLine(f netmap.Finding) string {
	return fmt.Sprintf("%s: %s", f.Group, f.Detail)
}

var gapOrder = []netmap.Kind{netmap.NotInAnyGroup, netmap.GroupNotScanned, netmap.PartlyCovered}

// layoutGuide is how the spreadsheet has to be laid out to be read. It is in
// the email because the people who maintain the sheet are on it.
var layoutGuide = []string{
	"One header row per location: the name on its own in the first column, ideally ending with the location's /16 block, for example \"Example Site - ST - 10.4.0.0/16\".",
	"Under it, a row labelled corp with the corporate network as a CIDR, for example 10.4.30.0/24. Other rows (security, netman, guest, voice, and so on) are fine and are ignored by this check.",
	"Do not leave the network cell blank or write it without a mask length: \"10.29.30\" cannot be read.",
	"A location that has been retired: put DECOMMISSIONED in its header. A block that is free: put \"Open to use\" in the header or label. Both are skipped.",
	"Every location needs one, including headquarters and the datacenter: a location with no row labelled corp cannot be checked, and is listed for the network team to correct.",
}

// text is the coverage section of the plain-text report.
func (c *Coverage) text() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("COVERAGE CHECK: THE NETWORK SPREADSHEET AGAINST WHAT THE SCANS COVER\n" + strings.Repeat("=", 72) + "\n")
	if c.Unavailable != "" {
		fmt.Fprintf(&b, "  Not run this week: %s\n\n", c.Unavailable)
		return b.String()
	}
	fmt.Fprintf(&b, "  %d corporate networks checked, %d fully inside the groups the scans cover.\n", c.Checked, c.Covered)
	if g := c.Gaps(); len(g) > 0 {
		fmt.Fprintf(&b, "\nADD TO QUALYS (%d) - networks in the spreadsheet that no weekly scan reaches\n%s\n", len(g), strings.Repeat("-", 72))
		for _, k := range gapOrder {
			for _, f := range c.gapsOf(k) {
				fmt.Fprintf(&b, "  - %s\n      -> %s\n", gapLine(f), gapAction(k))
			}
		}
	}
	if len(c.Questions) > 0 {
		fmt.Fprintf(&b, "\nFOR THE NETWORK TEAM: FIX IN THE SPREADSHEET (%d)\n%s\n", len(c.Questions), strings.Repeat("-", 72))
		b.WriteString("  The security team only reads this spreadsheet. These rows cannot be read as written,\n  so these locations are not checked until the network team corrects them.\n")
		for _, k := range questionOrder {
			for _, q := range c.questionsOf(k) {
				fmt.Fprintf(&b, "  - %s%s: %s\n      -> %s\n", q.Location, rowRef(q.Row), q.Why, questionAction(k))
			}
		}
	}
	if o := c.Oddities(); len(o) > 0 {
		fmt.Fprintf(&b, "\nCHECK IN QUALYS (%d)\n%s\n", len(o), strings.Repeat("-", 72))
		for _, f := range o {
			fmt.Fprintf(&b, "  - %s\n", oddLine(f))
		}
	}
	if len(c.Gaps()) == 0 && len(c.Oddities()) == 0 && len(c.Questions) == 0 {
		b.WriteString("  Nothing missing.\n")
	}
	b.WriteString("\nHOW THE SPREADSHEET IS READ\n" + strings.Repeat("-", 72) + "\n")
	for _, l := range layoutGuide {
		fmt.Fprintf(&b, "  - %s\n", l)
	}
	b.WriteString("\n")
	return b.String()
}

// html writes the coverage section into the body.
func (c *Coverage) html(b *strings.Builder) {
	if c == nil {
		return
	}
	emailkit.Section(b, "Coverage check: the network spreadsheet against what the scans cover", emailkit.Navy)
	if c.Unavailable != "" {
		emailkit.Item(b, "Not run this week: "+c.Unavailable)
		return
	}
	emailkit.Item(b, fmt.Sprintf("%d corporate networks checked, %d fully inside the groups the scans cover.", c.Checked, c.Covered))
	if g := c.Gaps(); len(g) > 0 {
		var l strings.Builder
		for _, k := range gapOrder {
			for _, f := range c.gapsOf(k) {
				fmt.Fprintf(&l, "&bull; %s<br><span style=\"color:%s\">&rarr; %s</span><br>", e(gapLine(f)), emailkit.Muted, e(gapAction(k)))
			}
		}
		emailkit.Card(b, emailkit.Red, fmt.Sprintf("ADD TO QUALYS (%d)", len(g)),
			"Networks in the spreadsheet that no weekly scan reaches.<br><br>"+l.String())
	}
	if len(c.Questions) > 0 {
		var l strings.Builder
		for _, k := range questionOrder {
			qs := c.questionsOf(k)
			if len(qs) == 0 {
				continue
			}
			fmt.Fprintf(&l, "<b>%s</b><br>", e(questionTitle(k)))
			for _, q := range qs {
				fmt.Fprintf(&l, "&bull; %s<br>", e(q.Location+rowRef(q.Row)+": "+q.Why))
			}
			fmt.Fprintf(&l, "<span style=\"color:%s\">&rarr; %s</span><br><br>", emailkit.Muted, e(questionAction(k)))
		}
		emailkit.Card(b, emailkit.Yellow, fmt.Sprintf("FOR THE NETWORK TEAM: FIX IN THE SPREADSHEET (%d)", len(c.Questions)),
			"The security team only reads this spreadsheet. These rows cannot be read as written, "+
				"so these locations are not checked until the network team corrects them.<br><br>"+l.String())
	}
	if o := c.Oddities(); len(o) > 0 {
		var l strings.Builder
		for _, f := range o {
			l.WriteString("&bull; " + e(oddLine(f)) + "<br>")
		}
		emailkit.Card(b, emailkit.Amber, fmt.Sprintf("CHECK IN QUALYS (%d)", len(o)), l.String())
	}
	if len(c.Gaps()) == 0 && len(c.Oddities()) == 0 && len(c.Questions) == 0 {
		emailkit.Item(b, "Nothing missing.")
	}
	var g strings.Builder
	for _, l := range layoutGuide {
		g.WriteString("&bull; " + e(l) + "<br>")
	}
	emailkit.Card(b, emailkit.Grey, "How the spreadsheet is read", g.String())
}

// CSV is every finding as a worksheet the teams can work through: one row per
// thing to do, with the spreadsheet row and what to do about it.
func (c *Coverage) CSV() string {
	if c == nil || c.Unavailable != "" {
		return ""
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	// A spreadsheet opens a cell that starts with = + - or @ as a formula. The
	// text here came from a spreadsheet and from Qualys, so it is made inert.
	w := csvWriter{cw}
	_ = w.Write([]string{"category", "location", "sheet_row", "network", "asset_group", "what_to_do"})
	row := func(n int) string {
		if n <= 0 {
			return ""
		}
		return fmt.Sprint(n)
	}
	for _, k := range gapOrder {
		for _, f := range c.gapsOf(k) {
			_ = w.Write([]string{"ADD TO QUALYS", f.Location, row(f.Row), f.Subnet, f.Group, gapAction(k)})
		}
	}
	for _, k := range questionOrder {
		for _, q := range c.questionsOf(k) {
			_ = w.Write([]string{"NETWORK TEAM: FIX IN THE SPREADSHEET", q.Location, row(q.Row), "", "", questionTitle(k) + ": " + q.Why + ". " + questionAction(k)})
		}
	}
	for _, f := range c.Oddities() {
		_ = w.Write([]string{"CHECK IN QUALYS", "", "", "", f.Group, f.Detail})
	}
	cw.Flush()
	return buf.String()
}

type csvWriter struct{ *csv.Writer }

func (w csvWriter) Write(rec []string) error {
	out := make([]string, len(rec))
	for i, v := range rec {
		if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
			v = "'" + v
		}
		out[i] = v
	}
	return w.Writer.Write(out)
}
