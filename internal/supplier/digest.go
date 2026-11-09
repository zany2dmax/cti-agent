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
		case NotRequest:
			return 3
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

func counts(reqs []Request) (yes, unsure, no, aside int) {
	for _, r := range reqs {
		switch r.Decision.Verdict {
		case Yes:
			yes++
		case No:
			no++
		case NotRequest:
			aside++
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
// when there is nothing to say, because a day with no new requests and no
// updates sends nothing, and neither does a day whose only news is requests set
// aside as not being supplier requests: they are listed when a digest goes out
// for another reason, and the lane's log names them every run.
//
// reqs holds the new requests and the earlier ones that got new information
// (Request.Updated). board is the link to the board (https only, else it is left
// out) and boardName is what to call it ("the CYBR board"). automatic is how
// many messages from the fleet's own machine senders were left out, said in a
// line so nothing is skipped silently; it does not by itself make a digest.
func Digest(reqs []Request, org string, day time.Time, board, boardName string, automatic int) (b Block, ok bool) {
	return DigestRead(reqs, org, day, board, boardName, automatic, nil)
}

// maxRead is how many messages the list of emails read shows; the rest are
// counted in a line under it.
const maxRead = 60

// DigestRead is Digest with the list of emails read: every message the lane
// looked at in the window and what came of it, as the daily digest lists the
// subjects its ingest pass read. read is shown newest first (see Annotate); an
// empty list leaves the section out.
func DigestRead(reqs []Request, org string, day time.Time, board, boardName string, automatic int, read []MailRow) (b Block, ok bool) {
	if len(reqs) == 0 {
		return Block{}, false
	}
	if strings.TrimSpace(boardName) == "" {
		boardName = "the Kanban board"
	}
	reqs = order(reqs)
	yes, unsure, no, aside := counts(reqs)
	updated, todoNew, asideNew := 0, 0, 0
	for _, r := range reqs {
		switch {
		case r.Updated:
			updated++
		case r.Decision.Verdict == NotRequest:
			asideNew++
		case r.Decision.NeedsTPRM():
			todoNew++
		}
	}
	newN := len(reqs) - updated - asideNew
	if newN == 0 && updated == 0 {
		return Block{}, false
	}
	dateStr := day.Format("Monday 2 January 2006")

	var lead string
	switch {
	case newN == 0:
		lead = fmt.Sprintf("%d earlier supplier %s got new information and was judged again.", updated, plural(updated, "request", "requests"))
	case todoNew == 0:
		lead = fmt.Sprintf("%d supplier %s came in and none needs a to-do.", newN, plural(newN, "request", "requests"))
	default:
		lead = fmt.Sprintf("%d supplier %s came in. %d %s a to-do on %s.",
			newN, plural(newN, "request", "requests"), todoNew, plural(todoNew, "has", "have"), boardName)
	}
	if updated > 0 && newN > 0 {
		lead += fmt.Sprintf(" %d earlier %s got new information.", updated, plural(updated, "request", "requests"))
	}
	if asideNew > 0 {
		lead += fmt.Sprintf(" %d more %s set aside as not a request to set up a supplier; they are listed last.", asideNew, plural(asideNew, "thread was", "threads were"))
	}

	subject := fmt.Sprintf("Supplier requests: %d - %d critical, %d unsure, %d not critical", len(reqs), yes, unsure, no)
	if aside > 0 {
		subject = strings.Replace(subject, " not critical", fmt.Sprintf(" not critical, %d set aside", aside), 1)
	}
	if updated > 0 {
		subject += fmt.Sprintf(" (%d updated)", updated)
	}
	if org = strings.TrimSpace(org); org != "" {
		subject = org + " " + subject
	}
	link := safeLink(board)
	showBoard := link != "" && (todoNew > 0 || updated > 0)

	// Plain text.
	var t strings.Builder
	t.WriteString(lead + "\n")
	autoLine := ""
	if automatic > 0 {
		autoLine = fmt.Sprintf("%d automatic %s from the mail filter left out: not %s.", automatic,
			plural(automatic, "message", "messages"), plural(automatic, "a request", "requests"))
		t.WriteString(autoLine + "\n")
	}
	if showBoard {
		t.WriteString("Board: " + link + "\n")
	}
	t.WriteString("\n")
	for _, r := range reqs {
		prefix := ""
		if r.Updated {
			prefix = "UPDATED, "
		}
		fmt.Fprintf(&t, "%s%s - %s", prefix, strings.ToUpper(VerdictLabel(r.Decision.Verdict)), r.Name())
		if r.TicketKey != "" {
			t.WriteString(" (" + r.TicketKey + ")")
		}
		t.WriteString("\n")
		if r.Updated {
			t.WriteString("  " + changeLine(r) + "\n")
		}
		if r.Decision.Reason != "" {
			t.WriteString("  " + oneLine(r.Decision.Reason, 300) + "\n")
		}
		if r.Decision.Verdict == Unsure {
			t.WriteString("  Treated as critical until a person decides.\n")
		}
		if r.Decision.Verdict == NotRequest {
			t.WriteString("  Not a request to set up a supplier, so no item was filed.\n")
		}
		if n := strings.Join(r.Needs(), " "); n != "" {
			t.WriteString("  Still needed: " + n + "\n")
		}
		fmt.Fprintf(&t, "  Sent by %s, %s\n\n", oneLine(r.From, 80), r.Received.UTC().Format("2006-01-02"))
	}

	if len(read) > 0 {
		t.WriteString(readText(read))
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
	if showBoard {
		leadHTML += fmt.Sprintf(` <a href="%s" style="color:%s">Open %s</a>.`, e(link), emailkit.Navy, e(boardName))
	}
	emailkit.Lead(&h, tone, leadHTML)
	tiles := []emailkit.Tile{
		{Label: "Critical", N: yes, Tone: emailkit.Red},
		{Label: "Unsure", N: unsure, Tone: emailkit.Amber},
		{Label: "Not critical", N: no, Tone: emailkit.Grey},
	}
	if aside > 0 {
		tiles = append(tiles, emailkit.Tile{Label: "Set aside", N: aside, Tone: emailkit.Grey})
	}
	emailkit.Tiles(&h, tiles, "An unsure is treated as critical until a person decides.")
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
		if r.Updated {
			lines.WriteString("<b>" + e(changeLine(r)) + "</b><br>")
		}
		if r.Decision.Reason != "" {
			lines.WriteString(e(oneLine(r.Decision.Reason, 300)) + "<br>")
		}
		if n := strings.Join(r.Needs(), " "); n != "" {
			lines.WriteString("Still needed: " + e(n) + "<br>")
		}
		fmt.Fprintf(&lines, "Sent by %s, %s", e(oneLine(r.From, 80)), r.Received.UTC().Format("2006-01-02"))
		if r.TicketKey != "" {
			if tl := safeLink(r.TicketURL); tl != "" {
				fmt.Fprintf(&lines, ` &middot; <a href="%s" style="color:%s">%s</a>`, e(tl), emailkit.Navy, e(r.TicketKey))
			} else {
				lines.WriteString(" &middot; " + e(r.TicketKey))
			}
		}
		title := VerdictLabel(r.Decision.Verdict) + ": " + r.Name()
		if r.Updated {
			title = "Updated - " + title
		}
		emailkit.Card(&h, rt, title, lines.String())
	}
	emailkit.BodyClose(&h)
	if len(read) > 0 {
		h.WriteString(readHTML(read))
	}
	if autoLine != "" {
		emailkit.Note(&h, e(autoLine))
	}
	emailkit.Note(&h, "The lane reads the request and its form only. It never opens the tax or bank attachments, never replies to the requester and never moves their mail.")
	emailkit.Foot(&h, "Supplier-request lane", emailkit.Credit(org, "cti-supplier", "Generated by the "+orgName(org)))
	t.WriteString(emailkit.CreditText(org, "cti-supplier", "Supplier-request lane") + "\n")
	return Block{Subject: subject, Text: t.String(), HTML: h.String()}, true
}

// readHeading is the list's heading: how many messages, in how many requests.
func readHeading(read []MailRow) string {
	labels := map[string]bool{}
	for _, r := range read {
		if r.Label != "" {
			labels[r.Label] = true
		}
	}
	return fmt.Sprintf("Emails read this run - %d %s in %d %s",
		len(read), plural(len(read), "message", "messages"),
		len(labels), plural(len(labels), "request", "requests"))
}

func readText(read []MailRow) string {
	var t strings.Builder
	t.WriteString(strings.ToUpper(readHeading(read)) + "\n")
	for i, r := range read {
		if i == maxRead {
			fmt.Fprintf(&t, "+%d more in the lane's log\n", len(read)-maxRead)
			break
		}
		fmt.Fprintf(&t, "  %s  %s  %s  [%s]\n", r.Received.UTC().Format("2006-01-02 15:04"),
			oneLine(r.From, 40), oneLine(r.Subject, 100), r.Result)
	}
	t.WriteString("\n")
	return t.String()
}

// readHTML is the list as a table: result, when, sender and subject. Sender and
// subject come from the mail, so both go through e().
func readHTML(read []MailRow) string {
	var b strings.Builder
	rows := read
	if len(rows) > maxRead {
		rows = rows[:maxRead]
	}
	for _, r := range rows {
		colour := emailkit.Soft
		switch {
		case strings.HasPrefix(r.Result, "Critical"), strings.HasPrefix(r.Result, "Updated: critical"):
			colour = emailkit.Red.Fg
		case strings.HasPrefix(r.Result, "Unsure"), strings.HasPrefix(r.Result, "Updated: unsure"):
			colour = emailkit.Amber.Fg
		}
		fmt.Fprintf(&b, `<tr><td style="padding:3px 10px 3px 0;white-space:nowrap;vertical-align:top;font-weight:700;color:%s">%s</td>`+
			`<td style="padding:3px 10px 3px 0;white-space:nowrap;vertical-align:top;color:%s">%s</td>`+
			`<td style="padding:3px 0;color:%s">%s<br><span style="color:%s">%s</span></td></tr>`,
			colour, e(r.Result), emailkit.Soft, r.Received.UTC().Format("2006-01-02 15:04"),
			emailkit.Ink, e(oneLine(r.Subject, 100)), emailkit.Soft, e(oneLine(r.From, 60)))
	}
	more := ""
	if len(read) > maxRead {
		more = fmt.Sprintf(`<div style="color:%s;margin-top:6px">+%d more in the lane's log</div>`, emailkit.Soft, len(read)-maxRead)
	}
	return fmt.Sprintf(`
  <tr><td style="padding:4px 20px 18px 20px;border-top:1px solid %s">
    <div style="font:700 12px %s;color:%s;margin:12px 0 8px 0;letter-spacing:.5px">%s</div>
    <table cellpadding="0" cellspacing="0" role="presentation" style="font:400 12px/1.5 %s">%s</table>%s
  </td></tr>`, emailkit.Rule, emailkit.Font, emailkit.Soft, e(strings.ToUpper(readHeading(read))), emailkit.Font, b.String(), more)
}

// orgName is the organisation for the fallback credit line.
func orgName(org string) string {
	if org = strings.TrimSpace(org); org != "" {
		return org
	}
	return "security team"
}

// changeLine says what changed for an updated request.
func changeLine(r Request) string {
	if r.PriorVerdict != "" && r.PriorVerdict != r.Decision.Verdict {
		return fmt.Sprintf("Was %s, now %s.", strings.ToLower(VerdictLabel(r.PriorVerdict)), strings.ToLower(VerdictLabel(r.Decision.Verdict)))
	}
	return "New information arrived; the judgement is unchanged."
}
