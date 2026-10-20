package domains

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
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
type TicketRef struct {
	// Action is one of: created, commented, unchanged, resolved, none,
	// would-create, would-comment, would-resolve, error, gate-closed.
	Action string `json:"action"`
	Key    string `json:"key,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`
	Note   string `json:"note,omitempty"`
}

var (
	ticketKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}-[0-9]{1,9}$`)
	// The URL is put in an email, so it must be the ticket's own browse link
	// on https - not whatever a file on disk says.
	ticketURLRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+/browse/[A-Z][A-Z0-9]{0,15}-[0-9]{1,9}$`)
)

// WriteTicketRef writes a ref file, 0600.
func WriteTicketRef(path string, r TicketRef) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// ReadTicketRef reads one; nil and an error when it is missing or unreadable.
func ReadTicketRef(path string) (*TicketRef, error) {
	// #nosec G304 -- the runner's own --ref-out file under $FLEET_HOME/state.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r TicketRef
	if err := json.Unmarshal(b, &r); err != nil {
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
	key := ""
	if ticketKeyRE.MatchString(r.Key) {
		key = r.Key
		if ticketURLRE.MatchString(r.URL) && strings.HasSuffix(r.URL, "/"+key) {
			url = r.URL
		}
	}
	st := ""
	if s := strings.TrimSpace(clean(r.Status)); s != "" && len(s) < 60 {
		st = " (" + s + ")"
	}
	note := strings.TrimSpace(clean(r.Note))
	if len(note) > 200 {
		note = note[:200] + "..."
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

// clean drops control characters, so a field from Jira cannot break a line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
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
