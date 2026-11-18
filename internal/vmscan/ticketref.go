package vmscan

import (
	"fmt"
	"html"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
	"github.com/zany2dmax/cti-agent/internal/ticketref"
)

// THE SPREADSHEET TICKET IN THE EMAIL
//
// cti-jira files the spreadsheet fixes as one ticket for the network team, and
// the weekly report is what people read - so the report has to name the ticket
// and say what happened to it this week. The ticket cannot exist when
// cti-vmscan renders (cti-jira needs the --fixes-out list cti-vmscan writes),
// so run-vmscan renders with a slot (--ticket-slot), runs cti-jira
// --vmscan-fixes --ref-out, and stamps the result in (--stamp-ticket) before
// the send. A slot nobody stamps is an HTML comment, invisible, and the
// runner's fallback deletes it from the text; the report is never held back
// for Jira. The domains lane's lock-down ticket works the same way.

// TicketSlot marks where the stamp goes.
const TicketSlot = "<!--CTI_VMSCAN_TICKET-->"

// slotSentinel is what the renderer writes where the real slot goes. Render
// deletes any TicketSlot that arrived inside observed data first - a location
// name in the network spreadsheet can carry the marker text, and the text
// report does not escape it - then turns the sentinel into the one real slot.
const slotSentinel = "\x00cti-vmscan-ticket-slot\x00"

// fixSlot is that step, for both forms of the report. The removal repeats:
// one pass over "<!--CTI_VMSCAN_<!--CTI_VMSCAN_TICKET-->TICKET-->" would leave
// a whole marker behind for the stamp to fill a second time.
func fixSlot(s string) string {
	for strings.Contains(s, TicketSlot) {
		s = strings.ReplaceAll(s, TicketSlot, "")
	}
	return strings.ReplaceAll(s, slotSentinel, TicketSlot)
}

// TicketRef is what cti-jira --vmscan-fixes --ref-out writes.
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

// TicketLine is the sentence for the report, "" when there is nothing to say
// (no ticket open and none needed). url is "" unless it passed validation.
func TicketLine(r *TicketRef) (line, url string) {
	if r == nil {
		return "Jira: the spreadsheet ticket's status is unavailable this run - see the run-vmscan journal.", ""
	}
	key, st, note := r.SafeKey(), r.SafeStatus(), r.SafeNote()
	if key != "" {
		url = r.SafeURL()
	}
	switch r.Action {
	case "created":
		if key == "" {
			return "Jira: filed a new ticket for the network team with the spreadsheet rows above.", ""
		}
		return fmt.Sprintf("Jira: filed %s for the network team with the spreadsheet rows above.", key), url
	case "commented":
		return fmt.Sprintf("Jira: %s%s - the list changed, so this week's version was added as a comment.", key, st), url
	case "unchanged":
		return fmt.Sprintf("Jira: %s%s already has this exact list - nothing new posted.", key, st), url
	case "resolved":
		return fmt.Sprintf("Jira: %s%s was told every row is corrected - it can be closed.", key, st), url
	case "resolved-earlier":
		return fmt.Sprintf("Jira: %s%s was told in an earlier week that every row is corrected - it can be closed.", key, st), url
	case "would-create":
		return "Jira (preview): would file a new ticket for the network team with these rows.", ""
	case "would-comment":
		return fmt.Sprintf("Jira (preview): would add this week's changed list to %s%s.", key, st), url
	case "would-resolve":
		return fmt.Sprintf("Jira (preview): would tell %s%s every row is corrected.", key, st), url
	case "held":
		if key != "" {
			return fmt.Sprintf("Jira: %s%s was left alone this run - the coverage check did not run.", key, st), url
		}
		return "", ""
	case "gate-closed", "error":
		if note == "" {
			note = "see the run-vmscan journal"
		}
		if key != "" {
			return fmt.Sprintf("Jira: %s%s was NOT updated this run - %s.", key, st, note), url
		}
		return fmt.Sprintf("Jira: the spreadsheet ticket was NOT filed this run - %s.", note), ""
	case "none":
		return "", ""
	}
	if key != "" {
		return fmt.Sprintf("Jira: spreadsheet ticket %s%s.", key, st), url
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
                    border-left:4px solid #2c5282;padding:8px 12px">%s</div></td></tr>`, emailkit.Font, text)
	default:
		out = "\n  " + line
		if url != "" {
			out += "\n    " + url
		}
		out += "\n"
	}
	return strings.ReplaceAll(body, TicketSlot, out)
}
