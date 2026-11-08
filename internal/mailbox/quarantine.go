package mailbox

import (
	"html"
	"regexp"
	"strings"
	"time"
)

// # QUARANTINE DIGESTS
//
// The mail filter sends an "End User Digest" listing the messages it held in
// quarantine. Nobody reviews quarantine through this mailbox, so a digest is
// noise - except in the rare case that the filter held something the fleet
// itself reads: a Qualys notice or a threat-intel feed. Then the operator has
// to release it, or the lane that needed it never sees it.
//
// So a digest is read before it is deleted. Each held message's sender is
// checked against the senders the fleet depends on (Qualys, built in, and
// MAILBOX_FEED_SENDERS). No match: Deleted Items, on sight. A match: the
// digest stays, the operator is told, and it goes after DigestKeep.
//
// THE FLEET NEVER RELEASES ANYTHING. Each row carries signed one-click
// links - Release, Release and Allow Sender, Block Sender - that act on a
// plain GET with no login. Following one is the action. ParseDigest reads the
// sender and subject TEXT and discards every link, so nothing downstream can
// follow one, and a forged digest cannot steer the fleet into releasing mail.

// digestSubject is how a digest's subject starts ("End User Digest: 1 New
// Message").
const digestSubject = "end user digest"

// DigestKeep is how long a digest that holds mail the fleet reads stays in
// the inbox after the operator has been told, before it goes too.
const DigestKeep = 7 * 24 * time.Hour

// QuarantineDigest reports whether a message is a quarantine digest: from an
// address in senders (MAILBOX_DIGEST_SENDERS), exactly, with a subject that
// starts "End User Digest". Empty senders turns the rule off - the digest's
// sending address is the organisation's own and is never guessed. A person's
// "Re:" or "FW:" of one is not one.
func QuarantineDigest(from, subject string, senders []string) bool {
	if len(senders) == 0 {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(subject)), digestSubject) {
		return false
	}
	addr := bareAddress(from)
	for _, s := range senders {
		if strings.EqualFold(strings.TrimSpace(s), addr) {
			return true
		}
	}
	return false
}

// Held is one message a digest says was quarantined.
type Held struct {
	Section string // "Low Priority Mail - Quarantined", "Spam", ...
	From    string
	Subject string
}

var (
	digestHeaderRE = regexp.MustCompile(`(?is)<td[^>]*class="tableheader"[^>]*>(.*?)</td>`)
	digestRowRE    = regexp.MustCompile(`(?i)<tr[^>]*class="tableitem\d*"[^>]*>`)
	digestCellRE   = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
	anyTagRE       = regexp.MustCompile(`(?s)<[^>]*>`)
	ctrlRE         = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// ParseDigest lists the held messages in a digest's HTML body. Text only:
// links are dropped with the tags (see the package note above). Each row's
// first cell is the sender and its second the subject; the section is the
// nearest heading above the row.
func ParseDigest(body string) []Held {
	var out []Held
	heads := digestHeaderRE.FindAllStringSubmatchIndex(body, -1)
	rows := digestRowRE.FindAllStringIndex(body, -1)
	for i, r := range rows {
		end := len(body)
		if i+1 < len(rows) {
			end = rows[i+1][0]
		}
		cells := digestCellRE.FindAllStringSubmatch(body[r[1]:end], 2)
		if len(cells) < 2 {
			continue
		}
		h := Held{From: cellText(cells[0][1]), Subject: cellText(cells[1][1])}
		for _, hd := range heads {
			if hd[0] < r[0] {
				h.Section = cellText(body[hd[2]:hd[3]])
			}
		}
		if h.From != "" {
			out = append(out, h)
		}
	}
	return out
}

// cellText is a cell's visible text: tags gone, entities decoded, control
// characters and runs of space collapsed, and bounded - it is attacker-chosen
// (a held phish's subject) and ends up in an alert.
func cellText(s string) string {
	s = html.UnescapeString(anyTagRE.ReplaceAllString(s, " "))
	s = strings.Join(strings.Fields(ctrlRE.ReplaceAllString(s, " ")), " ")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// builtInFleetDomains are senders every install depends on: the scanner's
// notices drive the AppSec and VM scan weeklies.
var builtInFleetDomains = []string{"qualys.net", "qualys.com"}

// FleetSender reports whether addr is a sender the fleet reads: a Qualys
// domain (or a subdomain of one), or an entry in feed (MAILBOX_FEED_SENDERS)
// - "name@example.com" for that address exactly, "@example.com" for that
// domain exactly.
func FleetSender(addr string, feed []string) bool {
	addr = strings.ToLower(bareAddress(addr))
	at := strings.LastIndex(addr, "@")
	if at <= 0 {
		return false
	}
	domain := addr[at+1:]
	for _, d := range builtInFleetDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	for _, f := range feed {
		f = strings.ToLower(strings.TrimSpace(f))
		switch {
		case f == "":
		case strings.HasPrefix(f, "@"):
			if domain == f[1:] {
				return true
			}
		case f == addr:
			return true
		}
	}
	return false
}

// HeldForFleet is the held messages a lane would have read, rendered for the
// operator ("sender - subject"), joined with "; ". Empty when there are none.
func HeldForFleet(held []Held, feed []string) string {
	var out []string
	for _, h := range held {
		if FleetSender(h.From, feed) {
			out = append(out, h.From+" - "+h.Subject)
		}
	}
	return strings.Join(out, "; ")
}

func bareAddress(from string) string {
	a := strings.TrimSpace(from)
	if i := strings.LastIndex(a, "<"); i >= 0 {
		a = strings.TrimSpace(strings.TrimSuffix(a[i+1:], ">"))
	}
	return a
}
