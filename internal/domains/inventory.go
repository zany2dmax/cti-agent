// Package domains is the weekly check of the organisation's domains: what is
// registered, what is live, and whether each one's mail records match what it
// is supposed to do.
//
// Forked from a standalone checker (sitecheck.go) and reshaped for the fleet:
// the probe logic is the same idea, but every result is a fact with a stated
// source, an absent record is kept distinct from a lookup that failed, and the
// report says what was NOT checked as plainly as what was.
//
// # THE INVENTORY IS A FILE, AND IT IS NOT IN THIS REPOSITORY
//
// The list of domains is an operator file - /etc/cti-agent/domains.txt by
// default - for the same reason ORG-PROFILE.md lives there: this repository is
// public, and a list of every domain an organisation owns, with which of them
// send mail, is a map for anybody planning to impersonate it.
package domains

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Entry is one domain from the inventory file.
type Entry struct {
	// Name is lower-case, with no scheme, path or trailing dot.
	Name string
	// Sends marks a domain that is supposed to send mail. Everything else is
	// expected NOT to, and is checked for the records that stop anybody else
	// sending as it.
	Sends bool
	// Receives marks a domain whose MX must keep delivering mail. Without it
	// the domain should publish a null MX ("MX 0 .").
	Receives bool
	// SaaS: the domain's mail is sent by an application or service rather
	// than our mail platform (implies Sends).
	SaaS bool
	// Unknown: nobody can yet say what sends as this domain. Reported, never
	// tightened - a DMARC reject on a domain with unknown senders drops real
	// mail.
	Unknown bool
	// Legacy: an old brand. With Receives and no Sends, its outbound has moved
	// to the main domain and it only keeps its inbound path.
	Legacy bool
	// Landing: the website is a landing page - a single marketing or
	// holding page with nothing to test - so the AppSec lane does not ask
	// for a web application scan of it. Registrar landers, parked pages and
	// redirects are recognised without it.
	Landing bool
	// Line is where it came from, for error messages.
	Line int
}

// ParseInventory reads the inventory file.
//
//	example.com send receive    # active mail domain (chart row 1)
//	example.org,send            # send-only, comma works too (row 2)
//	example.info receive legacy # old brand, outbound moved (row 9)
//	example.app send saas       # an application sends as it (row 6)
//	example.biz unknown         # senders not known yet: report, never tighten (row 7)
//	example.net                 # no mail at all: must be locked down (rows 4 and 5)
//	# comments and blank lines are ignored
//
// Problems are returned, not fatal: one malformed line must not cost the
// report on every other domain, and a report that silently skipped a domain
// would claim it had been checked. Each problem names its line.
func ParseInventory(r io.Reader) ([]Entry, []string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []Entry
	var problems []string
	seen := map[string]int{}
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		// Commas count as spaces: "example.com,send" is what a list kept in a
		// spreadsheet exports to, and skipping it as "not a domain" dropped the
		// very domains somebody had taken the trouble to mark as senders.
		fields := strings.Fields(strings.ReplaceAll(line, ",", " "))
		if len(fields) == 0 {
			continue
		}
		name, ok := Normalise(fields[0])
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"line %d: %q is not a domain name - skipped", n, fields[0]))
			continue
		}
		e := Entry{Name: name, Line: n}
		for _, marker := range fields[1:] {
			switch strings.ToLower(marker) {
			case "send", "sends":
				e.Sends = true
			case "receive", "receives":
				e.Receives = true
			case "saas":
				e.SaaS, e.Sends = true, true
			case "unknown":
				e.Unknown = true
			case "legacy":
				e.Legacy = true
			case "landing":
				e.Landing = true
			default:
				// Unknown is a problem, not a silent no-op. "sned" read as
				// "does not send" would lock down the checks the wrong way.
				problems = append(problems, fmt.Sprintf(
					"line %d: unknown marker %q on %s (understood: send, receive, saas, unknown, legacy)",
					n, marker, name))
			}
		}
		if first, dup := seen[name]; dup {
			problems = append(problems, fmt.Sprintf(
				"line %d: %s is already listed on line %d - the later line is ignored",
				n, name, first))
			continue
		}
		seen[name] = n
		out = append(out, e)
	}
	return out, problems, sc.Err()
}

// Normalise turns a line's first word into a bare domain name, or reports
// that it is not one.
//
// Accepts what people paste - "https://www.example.com/", "Example.COM." - as
// the original tool did, but then REJECTS anything that is not a hostname
// rather than probing it. A typo probed as a domain is a report row about
// somebody else's name.
func Normalise(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i] // a port
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 ||
			strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, r := range label {
			if !labelRune(r) {
				return "", false
			}
		}
	}
	return s, true
}

// labelRune reports whether r may appear in a hostname label: ASCII letters
// (already lower-cased), digits and hyphen. IDNs must be listed in their
// xn-- form.
func labelRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-'
}

// coveredBy reports whether name is domain itself or a subdomain of it.
//
// How an inventory entry is matched to a registration without a public-suffix
// list (this project is standard-library only): shop.example.com is covered by
// the registration of example.com. On a label boundary, so example.com does
// not cover badexample.com.
func coveredBy(name, domain string) bool {
	return name == domain || strings.HasSuffix(name, "."+domain)
}
