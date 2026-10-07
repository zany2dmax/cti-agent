package domains

import (
	"context"
	"strconv"
	"strings"
)

// DefaultDKIMSelectors are the selectors probed when DOMAINS_DKIM_SELECTORS
// is not set.
//
// DKIM cannot be enumerated: a key lives at <selector>._domainkey.<domain> and
// nothing lists the selectors. So "no DKIM found" only ever means "none at the
// selectors we tried", and the report says exactly that. selector1/selector2
// are Microsoft 365's; google is Workspace's; the rest are common defaults.
// Add the mail gateway's selector to fleet.env once it is known.
var DefaultDKIMSelectors = []string{"selector1", "selector2", "google", "default", "mail", "s1", "s2", "k1", "dkim"}

// wildcardSelector is a name nobody publishes. If it answers, the zone has a
// wildcard TXT and every selector will appear to exist, so the DKIM result
// cannot be trusted either way.
const wildcardSelector = "cti-agent-probe-nonexistent"

// Mail is what DNS says about a domain's mail.
type Mail struct {
	MX Lookup
	// SPF is every v=spf1 TXT at the name. More than one is itself a fault:
	// receivers treat it as a permanent error, which is the same as none.
	SPF Lookup
	// SPFLookups counts DNS-querying mechanisms across includes. Over 10 is a
	// permanent error at the receiver (RFC 7208 4.6.4).
	SPFLookups int
	// SPFLookupErr is set when an include could not be followed, so the count
	// is a lower bound.
	SPFLookupErr string

	DMARC Lookup
	// DMARCFrom is where the policy came from: the name itself, or the
	// organisational domain whose policy covers a subdomain with none.
	DMARCFrom string

	DKIM DKIMResult
}

// DKIMResult is the selector probe.
type DKIMResult struct {
	Tried    []string
	Found    []string // a key is published
	Revoked  []string // record exists with an empty p= - a deliberately revoked key
	Failed   []string // the lookup itself failed
	Wildcard bool     // the zone answers for any selector; result is meaningless
}

func isSPF(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "v=spf1")
}

func isDMARC(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "v=dmarc1")
}

// only keeps the TXT values matching keep. An answer with TXT records but no
// SPF among them is Absent for SPF: the name exists, the record does not.
func only(l Lookup, keep func(string) bool) Lookup {
	if !l.Known() || l.Absent {
		return l
	}
	var v []string
	for _, s := range l.Values {
		if keep(s) {
			v = append(v, strings.TrimSpace(s))
		}
	}
	if len(v) == 0 {
		return Lookup{Absent: true}
	}
	return Lookup{Values: v}
}

// ProbeMail queries MX, SPF, DMARC and DKIM for name.
//
// org is the registered domain covering name ("" if unknown). A subdomain with
// no DMARC record of its own is covered by the organisational domain's policy
// (its sp=, or p=), so that is looked up rather than reporting "no DMARC" on
// every subdomain of a domain that has one.
func ProbeMail(ctx context.Context, r Resolver, name, org string, selectors []string) Mail {
	m := Mail{
		MX:  lookupMX(ctx, r, name),
		SPF: only(lookupTXT(ctx, r, name), isSPF),
	}
	if len(m.SPF.Values) == 1 {
		m.SPFLookups, m.SPFLookupErr = countSPFLookups(ctx, r, m.SPF.Values[0], map[string]bool{name: true}, 0)
	}

	m.DMARC = only(lookupTXT(ctx, r, "_dmarc."+name), isDMARC)
	m.DMARCFrom = name
	if m.DMARC.Absent && org != "" && org != name {
		if parent := only(lookupTXT(ctx, r, "_dmarc."+org), isDMARC); parent.Present() || !parent.Known() {
			m.DMARC, m.DMARCFrom = parent, org
		}
	}

	m.DKIM.Tried = selectors
	if w := lookupTXT(ctx, r, wildcardSelector+"._domainkey."+name); w.Present() {
		m.DKIM.Wildcard = true
		return m
	}
	for _, sel := range selectors {
		l := lookupTXT(ctx, r, sel+"._domainkey."+name)
		switch {
		case !l.Known():
			m.DKIM.Failed = append(m.DKIM.Failed, sel)
		case l.Present():
			rec := strings.Join(l.Values, "")
			if p, ok := tag(rec, "p"); ok && p == "" {
				m.DKIM.Revoked = append(m.DKIM.Revoked, sel)
			} else {
				m.DKIM.Found = append(m.DKIM.Found, sel)
			}
		}
	}
	return m
}

// countSPFLookups counts the mechanisms that cost a DNS query, following
// include: and redirect=. Depth- and loop-bounded: a record that includes
// itself must end, not recurse.
func countSPFLookups(ctx context.Context, r Resolver, rec string, seen map[string]bool, depth int) (int, string) {
	if depth > 10 {
		return 0, "include chain deeper than 10"
	}
	n := 0
	var firstErr string
	for _, term := range strings.Fields(rec)[1:] {
		t := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		var follow string
		switch {
		case strings.HasPrefix(t, "include:"):
			n++
			follow = strings.TrimPrefix(t, "include:")
		case strings.HasPrefix(t, "redirect="):
			n++
			follow = strings.TrimPrefix(t, "redirect=")
		case t == "a" || strings.HasPrefix(t, "a:") || strings.HasPrefix(t, "a/"),
			t == "mx" || strings.HasPrefix(t, "mx:") || strings.HasPrefix(t, "mx/"),
			t == "ptr" || strings.HasPrefix(t, "ptr:"),
			strings.HasPrefix(t, "exists:"):
			n++
		}
		if follow == "" || seen[follow] {
			continue
		}
		seen[follow] = true
		sub := only(lookupTXT(ctx, r, follow), isSPF)
		if !sub.Known() || len(sub.Values) != 1 {
			if firstErr == "" {
				firstErr = "could not read the SPF record of " + follow
			}
			continue
		}
		k, err := countSPFLookups(ctx, r, sub.Values[0], seen, depth+1)
		n += k
		if firstErr == "" {
			firstErr = err
		}
	}
	return n, firstErr
}

// SPFAll is the record's catch-all qualifier: "-all", "~all", "?all", "+all",
// or "" when there is none (which defaults to neutral, i.e. allows anyone).
func SPFAll(rec string) string {
	for _, term := range strings.Fields(strings.ToLower(rec)) {
		switch term {
		case "-all", "~all", "?all", "+all":
			return term
		case "all":
			return "+all"
		}
	}
	return ""
}

// SPFAuthorises reports whether the record lets any host send: any mechanism
// other than the catch-all.
func SPFAuthorises(rec string) bool {
	for _, term := range strings.Fields(strings.ToLower(rec))[1:] {
		t := strings.TrimLeft(term, "+~?")
		if strings.HasPrefix(term, "-") || t == "all" || strings.HasPrefix(t, "exp=") {
			continue
		}
		return true
	}
	return false
}

// DMARCPolicy is a parsed DMARC record.
type DMARCPolicy struct {
	P, SP string
	PCT   int
	RUA   []string
}

// ParseDMARC reads the tags that matter here.
func ParseDMARC(rec string) DMARCPolicy {
	d := DMARCPolicy{PCT: 100}
	d.P, _ = tag(rec, "p")
	d.SP, _ = tag(rec, "sp")
	if s, ok := tag(rec, "pct"); ok {
		if n, err := strconv.Atoi(s); err == nil {
			d.PCT = n
		}
	}
	if s, ok := tag(rec, "rua"); ok {
		for _, u := range strings.Split(s, ",") {
			if u = strings.TrimSpace(u); u != "" {
				d.RUA = append(d.RUA, u)
			}
		}
	}
	d.P, d.SP = strings.ToLower(d.P), strings.ToLower(d.SP)
	return d
}

// Effective is the policy that applies to name, given where the record came
// from: a subdomain covered by its parent's record gets sp= when set.
func (d DMARCPolicy) Effective(fromParent bool) string {
	if fromParent && d.SP != "" {
		return d.SP
	}
	return d.P
}

// tag reads one k=v tag from a semicolon-separated record.
func tag(rec, key string) (string, bool) {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), key) {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}
