package supplier

import (
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/emailkit"
)

// Block is a rendered email: subject, plain text and HTML. The lane hands it to
// the mailer, which sends to the security team's list and nobody else.
type Block struct {
	Subject string
	Text    string
	HTML    string
}

func e(s string) string { return html.EscapeString(s) }

// safeLink returns u only when it is a plain https link, so a value that came
// back from anywhere else cannot become a clickable link in the email.
func safeLink(u string) string {
	p, err := url.Parse(strings.TrimSpace(u))
	if err != nil || p.Scheme != "https" || p.Host == "" {
		return ""
	}
	return p.String()
}

// order puts what needs a person first: critical, then unsure, then not
// critical, oldest first within each so nothing waits behind newer mail.
func order(reqs []Request) []Request {
	out := append([]Request(nil), reqs...)
	rank := func(v string) int {
		switch v {
		case Yes:
			return 0
		case Unsure:
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank(out[i].Decision.Verdict), rank(out[j].Decision.Verdict); a != b {
			return a < b
		}
		return out[i].Received.Before(out[j].Received)
	})
	return out
}

func counts(reqs []Request) (yes, unsure, no int) {
	for _, r := range reqs {
		switch r.Decision.Verdict {
		case Yes:
			yes++
		case No:
			no++
		default:
			unsure++
		}
	}
	return
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Digest renders the email that tells the security team to go to the Kanban
// board. It is a pointer, not the work: the board holds the items. ok is false
// when there are no requests, because a day with none sends nothing.
//
// board is the link to the board (https only, else it is left out) and
// boardName is what to call it ("the CYBR board").
func Digest(reqs []Request, org string, day time.Time, board, boardName string) (b Block, ok bool) {
	if len(reqs) == 0 {
		return Block{}, false
	}
	if strings.TrimSpace(boardName) == "" {
		boardName = "the Kanban board"
	}
	reqs = order(reqs)
	yes, unsure, no := counts(reqs)
	todo := yes + unsure
	dateStr := day.Format("Monday 2 January 2006")

	lead := fmt.Sprintf("%d supplier %s came in and none needs a to-do.", len(reqs), plural(len(reqs), "request", "requests"))
	if todo > 0 {
		lead = fmt.Sprintf("%d supplier %s came in. %d %s a to-do on %s.",
			len(reqs), plural(len(reqs), "request", "requests"), todo, plural(todo, "has", "have"), boardName)
	}

	subject := fmt.Sprintf("Supplier requests: %d - %d critical, %d unsure, %d not critical", len(reqs), yes, unsure, no)
	if org = strings.TrimSpace(org); org != "" {
		subject = org + " " + subject
	}

	// Plain text.
	var t strings.Builder
	t.WriteString(lead + "\n")
	if link := safeLink(board); link != "" && todo > 0 {
		t.WriteString("Board: " + link + "\n")
	}
	t.WriteString("\n")
	for _, r := range reqs {
		fmt.Fprintf(&t, "%s - %s", strings.ToUpper(VerdictLabel(r.Decision.Verdict)), r.Name())
		if r.TicketKey != "" {
			t.WriteString(" (" + r.TicketKey + ")")
		}
		t.WriteString("\n")
		if r.Decision.Reason != "" {
			t.WriteString("  " + oneLine(r.Decision.Reason, 300) + "\n")
		}
		if r.Decision.Verdict == Unsure {
			t.WriteString("  Treated as critical until a person decides.\n")
		}
		fmt.Fprintf(&t, "  Sent by %s, %s\n\n", oneLine(r.From, 80), r.Received.UTC().Format("2006-01-02"))
	}

	// HTML.
	var h strings.Builder
	emailkit.Open(&h, subject, org, "Supplier requests", dateStr)
	tone := emailkit.Green
	switch {
	case yes > 0:
		tone = emailkit.Red
	case unsure > 0:
		tone = emailkit.Amber
	}
	leadHTML := "<b>" + e(lead) + "</b>"
	if link := safeLink(board); link != "" && todo > 0 {
		leadHTML += fmt.Sprintf(` <a href="%s" style="color:%s">Open %s</a>.`, e(link), emailkit.Navy, e(boardName))
	}
	emailkit.Lead(&h, tone, leadHTML)
	emailkit.Tiles(&h, []emailkit.Tile{
		{Label: "Critical", N: yes, Tone: emailkit.Red},
		{Label: "Unsure", N: unsure, Tone: emailkit.Amber},
		{Label: "Not critical", N: no, Tone: emailkit.Grey},
	}, "An unsure is treated as critical until a person decides.")
	emailkit.BodyOpen(&h)
	for _, r := range reqs {
		rt := emailkit.Grey
		switch r.Decision.Verdict {
		case Yes:
			rt = emailkit.Red
		case Unsure:
			rt = emailkit.Amber
		}
		var lines strings.Builder
		if r.Decision.Reason != "" {
			lines.WriteString(e(oneLine(r.Decision.Reason, 300)) + "<br>")
		}
		fmt.Fprintf(&lines, "Sent by %s, %s", e(oneLine(r.From, 80)), r.Received.UTC().Format("2006-01-02"))
		if r.TicketKey != "" {
			if link := safeLink(r.TicketURL); link != "" {
				fmt.Fprintf(&lines, ` &middot; <a href="%s" style="color:%s">%s</a>`, e(link), emailkit.Navy, e(r.TicketKey))
			} else {
				lines.WriteString(" &middot; " + e(r.TicketKey))
			}
		}
		emailkit.Card(&h, rt, VerdictLabel(r.Decision.Verdict)+": "+r.Name(), lines.String())
	}
	emailkit.BodyClose(&h)
	emailkit.Note(&h, "The lane reads the request and its form only. It never opens the tax or bank attachments, never replies to the requester and never moves their mail.")
	emailkit.Foot(&h, "Supplier-request lane")
	return Block{Subject: subject, Text: t.String(), HTML: h.String()}, true
}
