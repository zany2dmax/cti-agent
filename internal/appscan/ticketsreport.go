package appscan

import (
	"fmt"
	"html"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

// THE TICKETS IN THE WEEKLY EMAIL
//
// The email is rendered first, the tickets are filed next (cti-jira needs the
// tickets file cti-appscan writes), and the outcome is stamped into the email
// before it is sent - the domains lane's order. A slot nobody stamps is an
// HTML comment, invisible; the runner clears it from the text.

// TicketsSlot marks where the tickets section goes.
const TicketsSlot = "<!--CTI_APPSCAN_TICKETS-->"

// ticketsSentinel is what the renderer writes; see renderReport.
const ticketsSentinel = "\x00cti-appscan-tickets\x00"

// FixSummary is the first sentence of a remedy's solution, for one line in
// the email. "" when there is none.
func FixSummary(r *Remedy) string {
	if r == nil {
		return ""
	}
	s := strings.Join(strings.Fields(strings.TrimPrefix(strings.TrimSpace(r.Solution), "- ")), " ")
	if s == "" {
		return ""
	}
	if i := strings.Index(s, ". "); i > 0 && i < 220 {
		s = s[:i+1]
	}
	if r := []rune(s); len(r) > 220 {
		s = string(r[:220]) + "..."
	}
	return s
}

// TicketLine is one application's line, and its validated link ("" when
// none). ok is false when there is nothing worth a line.
func TicketLine(t AppTicket, r *ticketref.Ref) (line, url string, ok bool) {
	app := strings.Join(strings.Fields(t.App), " ")
	owner := ""
	if !t.OwnerListed {
		owner = " No owner in app-owners.txt."
	}
	if r == nil {
		return fmt.Sprintf("%s: ticket status unavailable this run - see the run-appscan journal.%s", app, owner), "", true
	}
	key, st, note := r.SafeKey(), r.SafeStatus(), r.SafeNote()
	url = r.SafeURL()
	switch r.Action {
	case "skipped":
		return fmt.Sprintf("%s: ticket not updated - %s.", app, note), url, true
	case "created":
		who := " Unassigned."
		if r.Assignee != "" {
			who = " Assigned to " + ticketref.Clean(r.Assignee) + "."
		} else if note != "" {
			r := []rune(note)
			who = " " + strings.ToUpper(string(r[:1])) + string(r[1:]) + "."
		}
		if key == "" {
			return fmt.Sprintf("%s: filed a new ticket.%s", app, who), "", true
		}
		return fmt.Sprintf("%s: filed %s with %d finding(s) to fix.%s", app, key, len(t.Findings), who), url, true
	case "commented":
		return fmt.Sprintf("%s: %s%s - findings changed, update added.%s", app, key, st, owner), url, true
	case "unchanged":
		return fmt.Sprintf("%s: %s%s - %d finding(s), no change this week.%s", app, key, st, len(t.Findings), owner), url, true
	case "resolved":
		return fmt.Sprintf("%s: %s%s - nothing of Serious or above left; it can be closed.", app, key, st), url, true
	case "would-create":
		return fmt.Sprintf("%s: (dry run) would file a ticket with %d finding(s).%s", app, len(t.Findings), owner), "", true
	case "would-comment":
		return fmt.Sprintf("%s: (dry run) would update %s%s.%s", app, key, st, owner), url, true
	case "would-resolve":
		return fmt.Sprintf("%s: (dry run) would tell %s%s nothing is left.", app, key, st), url, true
	case "gate-closed", "error":
		if note == "" {
			note = "see the run-appscan journal"
		}
		if key != "" {
			return fmt.Sprintf("%s: %s%s NOT updated this run - %s.", app, key, st, note), url, true
		}
		return fmt.Sprintf("%s: ticket NOT filed this run - %s.", app, note), "", true
	case "none":
		return "", "", false
	}
	if key != "" {
		return fmt.Sprintf("%s: %s%s.", app, key, st), url, true
	}
	return "", "", false
}

// StampTickets fills the slot. refs nil means cti-jira wrote nothing: every
// application then says its status is unavailable.
func StampTickets(body string, isHTML bool, tf TicketsFile, refs map[string]ticketref.Ref) string {
	type row struct{ line, url string }
	var rows []row
	for _, t := range tf.Tickets {
		var r *ticketref.Ref
		if refs != nil {
			if v, ok := refs[t.Key]; ok {
				r = &v
			}
		}
		if line, url, ok := TicketLine(t, r); ok {
			rows = append(rows, row{line, url})
		}
	}
	if n := len(tf.Unowned); n > 0 {
		names := make([]string, 0, n)
		for i, a := range tf.Unowned {
			if i >= 15 {
				names = append(names, fmt.Sprintf("and %d more", n-i))
				break
			}
			names = append(names, strings.Join(strings.Fields(a), " "))
		}
		rows = append(rows, row{fmt.Sprintf("No owner in app-owners.txt (%d): %s - their tickets are unassigned. "+
			"cti-appscan --list-apps prints the file with these added.", n, strings.Join(names, ", ")), ""})
	}
	var out strings.Builder
	switch {
	case len(rows) == 0:
	case isHTML:
		sectionHTML(&out, fmt.Sprintf("JIRA TICKETS (%d)", len(rows)), "#2c5282")
		for _, r := range rows {
			text := html.EscapeString(r.line)
			if r.url != "" {
				text += ` <a href="` + html.EscapeString(r.url) + `" style="color:#2c5282">Open</a>`
			}
			fmt.Fprintf(&out, `
      <tr><td style="padding:0 0 8px 0">
        <div style="font:400 13px/1.55 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;
                    color:#1a202c">%s</div></td></tr>`, text)
		}
	default:
		title := fmt.Sprintf("JIRA TICKETS (%d)", len(rows))
		fmt.Fprintf(&out, "\n%s\n%s\n", title, strings.Repeat("-", len(title)))
		for _, r := range rows {
			fmt.Fprintf(&out, "  %s\n", r.line)
			if r.url != "" {
				fmt.Fprintf(&out, "      %s\n", r.url)
			}
		}
	}
	return strings.ReplaceAll(body, TicketsSlot, out.String())
}
