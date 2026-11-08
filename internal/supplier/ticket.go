package supplier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Request is one supplier request as the lane worked it out: who asked, what
// the form said, what code decided. A request is a conversation, not a
// message: the request, the approval and the replies are one thread, and one
// Kanban item.
type Request struct {
	MessageID      string
	ConversationID string
	Subject        string
	From           string
	Received       time.Time
	State          FormState
	// Form is set when State is StateRead.
	Form *Form
	// Skipped are the attachments that were not opened, and why.
	Skipped  []Skipped
	Decision Decision

	// TicketKey and TicketURL are filled in by the lane once the Jira item
	// exists, so the digest can point at it. Empty when there is none.
	TicketKey string
	TicketURL string
}

// Name is the supplier's name for display: the form's, else the subject.
func (r Request) Name() string {
	if r.Form != nil && strings.TrimSpace(r.Form.Name) != "" {
		return oneLine(r.Form.Name, 100)
	}
	return oneLine(stripReplyPrefixes(r.Subject), 100)
}

// stripReplyPrefixes drops leading "Re:", "Fw:" and "Fwd:" (any case, repeated),
// which say a message was forwarded, not what it is about.
func stripReplyPrefixes(s string) string {
	for {
		t := strings.TrimSpace(s)
		l := strings.ToLower(t)
		switch {
		case strings.HasPrefix(l, "re:"):
			s = t[3:]
		case strings.HasPrefix(l, "fw:"):
			s = t[3:]
		case strings.HasPrefix(l, "fwd:"):
			s = t[4:]
		default:
			return t
		}
	}
}

// NeedsTicket is true for a request that needs a person on the Kanban board: a
// Yes, and an Unsure, which is treated as a Yes. A No gets no item unless the
// operator asks for one (includeNo): there is nothing for anyone to do.
func (r Request) NeedsTicket(includeNo bool) bool {
	return r.Decision.NeedsTPRM() || includeNo
}

// VerdictLabel is the verdict in words a reader of the board understands.
func VerdictLabel(v string) string {
	switch v {
	case Yes:
		return "Critical"
	case No:
		return "Not critical"
	}
	return "Unsure"
}

// oneLine makes hostile text safe to show in a line: whitespace collapsed,
// cut to max runes with an ellipsis.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return strings.TrimSpace(string(r[:max-1])) + "…"
	}
	return s
}

// wiki makes text from outside safe inside Jira wiki markup. A pipe ends a
// table cell, a newline ends a row, braces start a macro, brackets a link, and
// !…! embeds an image from any address the sender chooses. Escaped, not
// stripped, so the text still says what the sender wrote.
func wiki(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for _, c := range []string{"\\", "|", "{", "}", "[", "]", "!"} {
		s = strings.ReplaceAll(s, c, "\\"+c)
	}
	return s
}

// Label is the idempotency label: one per conversation, so a rerun finds the
// item it already filed instead of filing another. Hashed because a Graph
// conversation id is long and Jira labels cannot hold spaces.
func (r Request) Label() string {
	id := r.ConversationID
	if id == "" {
		id = r.MessageID
	}
	sum := sha256.Sum256([]byte(id))
	return "fleet-supplier-" + hex.EncodeToString(sum[:])[:16]
}

// Labels are the Jira labels for the item.
func (r Request) Labels() []string {
	return []string{"fleet-supplier", r.Label(), "supplier-" + r.Decision.Verdict}
}

// FindJQL finds the item already filed for a request, in any state.
func FindJQL(projectKey string, r Request) string {
	return fmt.Sprintf(`project = "%s" AND labels = "%s"`, strings.ReplaceAll(projectKey, `"`, ""), r.Label())
}

// TicketSummary is the item's title.
func TicketSummary(r Request) string {
	return fmt.Sprintf("Supplier request - %s: %s", strings.ToLower(VerdictLabel(r.Decision.Verdict)), r.Name())
}

func row(k, v string) string {
	if strings.TrimSpace(v) == "" {
		v = "(blank)"
	}
	return "|" + wiki(k) + "|" + wiki(v) + "|\n"
}

// TicketDescription is the item's text, in Jira wiki markup.
//
// It says why in plain words, shows the quotes the answer rests on, says
// what code distrusted, and names what was left unopened. It carries the
// request's business fields and nothing from the tax or bank side: no
// remittance address, no contact or bank detail.
func TicketDescription(r Request, cfg Config, board string) string {
	var b strings.Builder
	d := r.Decision

	switch d.Verdict {
	case Yes:
		fmt.Fprintf(&b, "*Critical.* This supplier looks critical, so it has to go through the %s.\n\n", cfg.tprm())
	case Unsure:
		b.WriteString("*Unsure.* " + wiki(cfg.unsureText(board)) + " It is treated as critical until a person decides: it has to go through the " + cfg.tprm() + " unless you judge it is not critical.\n\n")
	default:
		b.WriteString("*Not critical.* The lane judged this supplier is not critical. Nothing is needed unless you disagree.\n\n")
	}
	if d.Reason != "" {
		b.WriteString("h3. Why\n" + wiki(d.Reason) + "\n\n")
	}
	if len(d.Evidence) > 0 {
		b.WriteString("h3. What the request says\n")
		for _, q := range d.Evidence {
			b.WriteString("* " + wiki(oneLine(q, 300)) + "\n")
		}
		b.WriteString("\n")
	}
	if len(d.Notes) > 0 {
		b.WriteString("h3. What to be careful about\n")
		for _, n := range d.Notes {
			b.WriteString("* " + wiki(oneLine(n, 300)) + "\n")
		}
		b.WriteString("\n")
	}

	b.WriteString("h3. The request\n||Field||Value||\n")
	b.WriteString(row("Supplier", r.Name()))
	b.WriteString(row("Sent by", r.From))
	b.WriteString(row("Received", r.Received.UTC().Format("2006-01-02")))
	b.WriteString(row("Subject", oneLine(r.Subject, 200)))
	switch r.State {
	case StateRead:
		if f := r.Form; f != nil {
			b.WriteString(row("Request type", f.Request))
			b.WriteString(row("Branch/market", f.Branch))
			b.WriteString(row("Expense or inventory", f.Class))
			b.WriteString(row("Monthly spend", f.MonthlySpend))
			b.WriteString(row("Requested by", f.RequestedBy))
			b.WriteString(row("Approved by", f.ApprovedBy))
			b.WriteString(row("Notes on the form", oneLine(f.Notes, 300)))
			if len(f.Missing) > 0 {
				b.WriteString(row("Required fields left blank", strings.Join(f.Missing, ", ")))
			}
		}
	case StateLinked:
		b.WriteString(row("Form", "arrived as a link in the message, which the lane does not open: read it there"))
	case StateUnreadable:
		b.WriteString(row("Form", "an attachment was there but is not a supplier form"))
	default:
		b.WriteString(row("Form", "none attached: judged from the message text"))
	}
	b.WriteString("\n")

	if len(r.Skipped) > 0 {
		b.WriteString("h3. Left unopened\n")
		for _, s := range r.Skipped {
			b.WriteString("* " + wiki(s.Name) + " - " + wiki(s.Reason) + "\n")
		}
		b.WriteString("\nThe lane never opens the tax and bank forms.\n\n")
	}

	b.WriteString("Filed automatically by the supplier-request lane. It reads the request and the form only; ")
	b.WriteString("it never replies to the requester, never moves their mail and never opens the tax or bank attachments. ")
	b.WriteString("Close this item when the " + cfg.tprm() + " is done, or when you decide the supplier is not critical.\n")
	return b.String()
}
