package vmscan

import (
	"fmt"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/netmap"
)

// Coverage is the result of checking the scans' locations against the network
// spreadsheet, or the reason it could not be checked.
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

func gapLine(f netmap.Finding) string {
	switch f.Kind {
	case netmap.NotInAnyGroup:
		return fmt.Sprintf("%s: %s is in no Qualys Asset Group, so no scan reaches it.", f.Location, f.Subnet)
	case netmap.GroupNotScanned:
		return fmt.Sprintf("%s: %s is in the Asset Group %q, but neither weekly scan covers that group.", f.Location, f.Subnet, f.Group)
	default:
		return fmt.Sprintf("%s: only part of %s is in the groups the weekly scans cover.", f.Location, f.Subnet)
	}
}

func oddLine(f netmap.Finding) string {
	return fmt.Sprintf("%s: %s", f.Group, f.Detail)
}

// text is the coverage section of the plain-text report.
func (c *Coverage) text() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("COVERAGE CHECK: THE NETWORK SPREADSHEET AGAINST WHAT THE SCANS COVER\n" + strings.Repeat("-", 72) + "\n")
	if c.Unavailable != "" {
		fmt.Fprintf(&b, "  Not run this week: %s\n\n", c.Unavailable)
		return b.String()
	}
	fmt.Fprintf(&b, "  %d corporate networks checked, %d fully inside the groups the scans cover.\n", c.Checked, c.Covered)
	if g := c.Gaps(); len(g) > 0 {
		fmt.Fprintf(&b, "\n  NOT SCANNED (%d):\n", len(g))
		for _, f := range g {
			fmt.Fprintf(&b, "    - %s\n", gapLine(f))
		}
	}
	if o := c.Oddities(); len(o) > 0 {
		fmt.Fprintf(&b, "\n  CHECK THESE (%d):\n", len(o))
		for _, f := range o {
			fmt.Fprintf(&b, "    - %s\n", oddLine(f))
		}
	}
	if len(c.Questions) > 0 {
		fmt.Fprintf(&b, "\n  NOT CHECKED, NEEDS A DECISION (%d):\n", len(c.Questions))
		for _, q := range c.Questions {
			fmt.Fprintf(&b, "    - %s: %s\n", q.Location, q.Why)
		}
	}
	if len(c.Gaps()) == 0 && len(c.Oddities()) == 0 && len(c.Questions) == 0 {
		b.WriteString("  Nothing missing.\n")
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
		for _, f := range g {
			l.WriteString("&bull; " + e(gapLine(f)) + "<br>")
		}
		emailkit.Card(b, emailkit.Red, fmt.Sprintf("NOT SCANNED (%d)", len(g)), l.String())
	}
	if o := c.Oddities(); len(o) > 0 {
		var l strings.Builder
		for _, f := range o {
			l.WriteString("&bull; " + e(oddLine(f)) + "<br>")
		}
		emailkit.Card(b, emailkit.Amber, fmt.Sprintf("CHECK THESE (%d)", len(o)), l.String())
	}
	if len(c.Questions) > 0 {
		var l strings.Builder
		for _, q := range c.Questions {
			l.WriteString("&bull; " + e(q.Location+": "+q.Why) + "<br>")
		}
		emailkit.Card(b, emailkit.Yellow, fmt.Sprintf("NOT CHECKED, NEEDS A DECISION (%d)", len(c.Questions)), l.String())
	}
	if len(c.Gaps()) == 0 && len(c.Oddities()) == 0 && len(c.Questions) == 0 {
		emailkit.Item(b, "Nothing missing.")
	}
}
