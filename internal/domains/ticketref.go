package domains

import (
	"fmt"
	"html"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

// THE LOCK-DOWN TICKET IN THE EMAIL
//
// cti-jira files the week's DNS changes as one ticket, and the report is what
// people read - so the report has to say which ticket, and what happened to it
// this week. The ticket cannot exist when cti-domains renders (cti-jira needs
// the actions file cti-domains writes), so the runner renders with a slot,
// runs cti-jira --ref-out, and stamps the result into the slot before the
// send. A slot nobody stamps is invisible in HTML and removed from text by
// the stamp step's fallback; the report is never held back for Jira.

// TicketSlot marks where the stamp goes. An HTML comment, so a report that
// is never stamped still renders cleanly.
const TicketSlot = "<!--CTI_DOMAINS_TICKET-->"

// TicketRef is what cti-jira --ref-out writes.
type TicketRef = ticketref.Ref

// WriteTicketRef writes a ref file, 0600.
func WriteTicketRef(path string, r TicketRef) error { return ticketref.Write(path, r) }

// ReadTicketRef reads one; nil and an error when it is missing or unreadable.
func ReadTicketRef(path string) (*TicketRef, error) {
	var r TicketRef
	if err := ticketref.Read(path, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// TicketLine is the sentence for the report, "" when there is nothing to
// say (no ticket and none needed). url is "" unless it passed validation.
func TicketLine(r *TicketRef) (line, url string) {
	if r == nil {
		return "Jira: the lock-down ticket's status is unavailable this run - see the run-domains journal.", ""
	}
	key, st, note := r.SafeKey(), r.SafeStatus(), r.SafeNote()
	if key != "" {
		url = r.SafeURL()
	}
	switch r.Action {
	case "created":
		if key == "" {
			return "Jira: filed a new lock-down ticket for IT with this week's DNS changes.", ""
		}
		return fmt.Sprintf("Jira: filed %s for IT with this week's DNS changes.", key), url
	case "commented":
		return fmt.Sprintf("Jira: %s%s - the list changed, so this week's version was added as a comment.", key, st), url
	case "unchanged":
		return fmt.Sprintf("Jira: %s%s already has this exact list - nothing new posted.", key, st), url
	case "resolved":
		return fmt.Sprintf("Jira: %s%s was told nothing is left to change - it can be closed.", key, st), url
	case "would-create":
		return "Jira (dry run): would file a new lock-down ticket with these changes.", ""
	case "would-comment":
		return fmt.Sprintf("Jira (dry run): would add this week's changed list to %s%s.", key, st), url
	case "would-resolve":
		return fmt.Sprintf("Jira (dry run): would tell %s%s nothing is left to change.", key, st), url
	case "gate-closed", "error":
		if note == "" {
			note = "see the run-domains journal"
		}
		if key != "" {
			return fmt.Sprintf("Jira: %s%s was NOT updated this run - %s.", key, st, note), url
		}
		return fmt.Sprintf("Jira: the lock-down ticket was NOT filed this run - %s.", note), ""
	case "none":
		return "", ""
	}
	if key != "" {
		return fmt.Sprintf("Jira: lock-down ticket %s%s.", key, st), url
	}
	return "", ""
}

// StampTicket replaces the slot in a rendered report. Every slot is replaced,
// with nothing when there is nothing to say.
func StampTicket(body string, isHTML bool, r *TicketRef) string {
	line, url := TicketLine(r)
	var out string
	switch {
	case line == "":
	case isHTML:
		text := html.EscapeString(line)
		if url != "" {
			text += ` <a href="` + html.EscapeString(url) + `" style="color:#2c5282">Open the ticket</a>`
		}
		out = fmt.Sprintf(`
      <tr><td style="padding:0 0 10px 0">
        <div style="font:400 13px/1.55 %s;color:#1a202c;background:#ebf4ff;
                    border-left:4px solid #2c5282;padding:8px 12px">%s</div></td></tr>`, font, text)
	default:
		out = "\n" + line
		if url != "" {
			out += "\n  " + url
		}
		out += "\n"
	}
	return strings.ReplaceAll(body, TicketSlot, out)
}
