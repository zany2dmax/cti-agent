package domains

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity of a finding. Three levels, not the fleet's Sev1-5: those score
// vulnerabilities, and a domain record is a configuration fact.
type Severity int

const (
	Info Severity = iota
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "High"
	case Medium:
		return "Medium"
	}
	return "Info"
}

// Finding is one thing the report says about one domain.
type Finding struct {
	Domain string
	Sev    Severity
	Area   string // registrar, dns, web, tls, mail, change
	Text   string
}

// Options are the run's settings.
type Options struct {
	Now time.Time
	// Registrar is the account name, "" when the registrar was not consulted
	// (--no-registrar, or it failed - RegistrarErr then says why).
	Registrar    string
	RegistrarErr string
	// ExpectRUA, when set, must appear in every sending domain's DMARC rua=.
	// Empty until the mail team says where aggregate reports should go; then
	// the check is only that SOME rua= exists.
	ExpectRUA string
}

// Evaluate turns observations into findings.
func Evaluate(results []Result, cmp *Comparison, opt Options) []Finding {
	var out []Finding
	add := func(d string, s Severity, area, f string, a ...any) {
		out = append(out, Finding{Domain: d, Sev: s, Area: area, Text: fmt.Sprintf(f, a...)})
	}

	if cmp != nil {
		for _, e := range cmp.NotAtRegistrar {
			add(e.Name, Medium, "registrar",
				"not in the %s account: held at another registrar, lapsed, or not ours - "+
					"somebody should be able to say which", cmp.Registrar)
		}
		for _, r := range cmp.NotInInventory {
			add(r.Domain, Medium, "registrar",
				"in the %s account but not in the inventory, so nothing else in this report "+
					"checked it - add it to domains.txt (with \"send\" if it sends mail)", cmp.Registrar)
		}
		seen := map[string]bool{}
		for _, res := range results {
			reg, ok := cmp.Covered[res.Entry.Name]
			if !ok || seen[reg.Domain] {
				continue
			}
			seen[reg.Domain] = true
			evalRegistration(reg, opt.Now, add)
		}
	}

	for _, res := range results {
		d := res.Entry.Name
		if cmp != nil {
			if reg, ok := cmp.Covered[d]; ok && reg.Domain == d {
				evalDelegation(d, reg, res.NS, cmp.Registrar, add)
			}
		}
		for _, w := range res.Web {
			evalWeb(d, w, opt.Now, add)
		}
		if res.Entry.Sends {
			evalSender(d, res.Mail, opt, add)
		} else {
			evalNonSender(d, res.Mail, add)
		}
	}
	SortFindings(out)
	return out
}

type adder func(d string, s Severity, area, f string, a ...any)

func evalRegistration(r Registration, now time.Time, add adder) {
	d := r.Domain
	if r.Status != "" && r.Status != "ACTIVE" {
		add(d, High, "registrar", "registrar status is %s, not ACTIVE", r.Status)
	}
	if !r.Expires.IsZero() {
		days := int(r.Expires.Sub(now).Hours() / 24)
		switch {
		case days < 0:
			add(d, High, "registrar", "registration expired %s", r.Expires.Format("2 Jan 2006"))
		case days <= 30 && !r.AutoRenew:
			add(d, High, "registrar", "registration expires in %d days (%s) and auto-renew is OFF",
				days, r.Expires.Format("2 Jan 2006"))
		case days <= 30:
			add(d, Medium, "registrar", "registration expires in %d days (%s); auto-renew is on - "+
				"confirm the payment method will go through", days, r.Expires.Format("2 Jan 2006"))
		case days <= 60 && !r.AutoRenew:
			add(d, Medium, "registrar", "registration expires in %d days (%s) and auto-renew is OFF",
				days, r.Expires.Format("2 Jan 2006"))
		case !r.AutoRenew:
			add(d, Medium, "registrar", "auto-renew is OFF (expires %s)", r.Expires.Format("2 Jan 2006"))
		}
	} else if !r.AutoRenew {
		add(d, Medium, "registrar", "auto-renew is OFF")
	}
	if !r.Locked && r.Status == "ACTIVE" {
		add(d, High, "registrar", "transfer lock is OFF - the domain can be moved to another "+
			"registrar by anyone holding its auth code")
	}
}

func evalDelegation(d string, reg Registration, ns Lookup, registrar string, add adder) {
	switch {
	case !ns.Known():
		add(d, Info, "dns", "nameserver lookup failed (%s) - delegation not compared", ns.Err)
	case !ns.Present():
		add(d, High, "dns", "registered but DNS has no nameservers for it - the domain does not resolve")
	case len(reg.NameServers) > 0 && !sameSet(ns.Values, reg.NameServers):
		add(d, Medium, "dns", "DNS reports nameservers %s but %s has %s - one of them is stale",
			strings.Join(ns.Values, ", "), registrar, strings.Join(reg.NameServers, ", "))
	}
}

func evalWeb(d string, w Web, now time.Time, add adder) {
	h := w.Host
	where := ""
	if h != d {
		where = h + ": "
	}
	if w.Dangling {
		add(d, High, "dns", "%sCNAME points at %s, which does not resolve - whoever claims that "+
			"name serves content as us (subdomain takeover)", where, w.CNAME)
		return
	}
	if !w.Addrs.Known() {
		add(d, Medium, "dns", "%saddress lookup failed (%s) - web not checked", where, w.Addrs.Err)
		return
	}
	if !w.Addrs.Present() {
		return // not live is a state, shown in the inventory table, not a finding
	}
	if !w.Live() {
		add(d, Info, "web", "%sresolves but nothing answered on 80 or 443", where)
		return
	}
	if p := w.ParkedBy(); p != "" {
		return // parked is a state, shown in the table
	}
	switch {
	case !w.HTTPS.OK() && w.HTTP.OK():
		add(d, Medium, "tls", "%sserves a page over HTTP only - nothing usable on 443 (%s)", where,
			firstNonEmpty(w.TLS.DialErr, w.HTTPS.Err))
	case w.TLS.Checked && w.TLS.DialErr == "" && !w.TLS.Verified:
		add(d, High, "tls", "%sserves a page with a certificate browsers reject: %s", where, w.TLS.VerifyErr)
	case w.TLS.Verified:
		days := int(w.TLS.NotAfter.Sub(now).Hours() / 24)
		if days <= 14 {
			add(d, High, "tls", "%scertificate expires in %d days (%s)", where, days, w.TLS.NotAfter.Format("2 Jan"))
		} else if days <= 30 {
			add(d, Medium, "tls", "%scertificate expires in %d days (%s)", where, days, w.TLS.NotAfter.Format("2 Jan"))
		}
	}
}

func evalSender(d string, m Mail, opt Options, add adder) {
	switch {
	case !m.MX.Known():
		add(d, Medium, "mail", "MX lookup failed (%s)", m.MX.Err)
	case !m.MX.Present():
		add(d, Medium, "mail", "sends mail but has no MX - replies and bounces have nowhere to go")
	case len(m.MX.Values) == 1 && m.MX.Values[0] == ".":
		add(d, High, "mail", "marked as sending but publishes a null MX, declaring it accepts no mail")
	}

	switch {
	case !m.SPF.Known():
		add(d, Medium, "mail", "SPF lookup failed (%s) - not checked", m.SPF.Err)
	case !m.SPF.Present():
		add(d, High, "mail", "no SPF record - receivers cannot tell our mail from forgeries")
	case len(m.SPF.Values) > 1:
		add(d, High, "mail", "%d SPF records - receivers treat that as a permanent error, the same as none",
			len(m.SPF.Values))
	default:
		rec := m.SPF.Values[0]
		switch SPFAll(rec) {
		case "+all":
			add(d, High, "mail", "SPF ends +all - it authorises every host on the internet")
		case "?all", "":
			add(d, Medium, "mail", "SPF has no -all or ~all, so unlisted senders are not failed")
		}
		if m.SPFLookups > 10 {
			add(d, High, "mail", "SPF needs %d DNS lookups; over 10 is a permanent error at the receiver",
				m.SPFLookups)
		}
		if m.SPFLookupErr != "" {
			add(d, Info, "mail", "SPF lookup count is a lower bound: %s", m.SPFLookupErr)
		}
	}

	switch dk := m.DKIM; {
	case dk.Wildcard:
		add(d, Info, "mail", "the zone answers any DKIM selector (wildcard TXT), so DKIM could not be checked")
	case len(dk.Found) > 0:
	case len(dk.Revoked) > 0:
		add(d, Medium, "mail", "only revoked DKIM keys found (%s)", strings.Join(dk.Revoked, ", "))
	case len(dk.Failed) == len(dk.Tried) && len(dk.Tried) > 0:
		add(d, Medium, "mail", "every DKIM lookup failed - not checked")
	default:
		add(d, Medium, "mail", "no DKIM key at the selectors tried (%s); if the mail service uses "+
			"another, add it to DOMAINS_DKIM_SELECTORS", strings.Join(dk.Tried, ", "))
	}

	inherited := m.DMARCFrom != d
	switch {
	case !m.DMARC.Known():
		add(d, Medium, "mail", "DMARC lookup failed (%s) - not checked", m.DMARC.Err)
	case !m.DMARC.Present():
		add(d, High, "mail", "no DMARC record - nothing tells receivers to refuse mail forged as this domain")
	case len(m.DMARC.Values) > 1:
		add(d, High, "mail", "%d DMARC records - receivers ignore them all", len(m.DMARC.Values))
	default:
		p := ParseDMARC(m.DMARC.Values[0])
		eff := p.Effective(inherited)
		src := ""
		if inherited {
			src = " (inherited from " + m.DMARCFrom + ")"
		}
		switch eff {
		case "reject", "quarantine":
		case "none":
			add(d, Medium, "mail", "DMARC policy is none%s - forgeries are reported, not refused", src)
		default:
			add(d, High, "mail", "DMARC record has no valid p= tag%s", src)
		}
		if p.PCT < 100 && eff != "none" {
			add(d, Medium, "mail", "DMARC pct=%d%s - the policy applies to only part of the mail", p.PCT, src)
		}
		if len(p.RUA) == 0 {
			add(d, Medium, "mail", "DMARC has no rua=%s - nobody receives the aggregate reports that "+
				"show who is sending as this domain", src)
		} else if opt.ExpectRUA != "" && !containsFold(p.RUA, opt.ExpectRUA) {
			add(d, Medium, "mail", "DMARC rua= (%s) does not include %s", strings.Join(p.RUA, ", "), opt.ExpectRUA)
		}
	}
}

// evalNonSender checks a domain is locked down: nobody should be able to send
// as it, and if it IS sending, the inventory is wrong.
func evalNonSender(d string, m Mail, add adder) {
	switch {
	case !m.SPF.Known():
		add(d, Info, "mail", "SPF lookup failed (%s) - not checked", m.SPF.Err)
	case !m.SPF.Present():
		add(d, Medium, "mail", "does not send, but has no SPF - publish \"v=spf1 -all\"")
	case len(m.SPF.Values) > 1:
		add(d, Medium, "mail", "%d SPF records - replace with one \"v=spf1 -all\"", len(m.SPF.Values))
	case SPFAuthorises(m.SPF.Values[0]):
		add(d, Medium, "mail", "marked as not sending, but SPF authorises senders (%s) - is it sending "+
			"mail? If so, mark it \"send\"; if not, replace with \"v=spf1 -all\"", m.SPF.Values[0])
	case SPFAll(m.SPF.Values[0]) != "-all":
		add(d, Medium, "mail", "SPF should be \"v=spf1 -all\" for a domain that does not send")
	}

	if len(m.DKIM.Found) > 0 && !m.DKIM.Wildcard {
		add(d, Medium, "mail", "marked as not sending, but publishes DKIM keys (%s) - is it sending mail?",
			strings.Join(m.DKIM.Found, ", "))
	}

	inherited := m.DMARCFrom != d
	switch {
	case !m.DMARC.Known():
		add(d, Info, "mail", "DMARC lookup failed (%s) - not checked", m.DMARC.Err)
	case !m.DMARC.Present():
		add(d, Medium, "mail", "does not send, but has no DMARC - publish \"v=DMARC1; p=reject\" so "+
			"forgeries are refused")
	case len(m.DMARC.Values) == 1:
		if eff := ParseDMARC(m.DMARC.Values[0]).Effective(inherited); eff != "reject" {
			src := ""
			if inherited {
				src = " (inherited from " + m.DMARCFrom + ")"
			}
			add(d, Medium, "mail", "does not send, so DMARC should be p=reject; it is %q%s", eff, src)
		}
	default:
		add(d, Medium, "mail", "%d DMARC records - receivers ignore them all", len(m.DMARC.Values))
	}
}

// SortFindings orders worst first, then by domain, then area, so the same
// week renders the same document.
func SortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Sev != b.Sev {
			return a.Sev > b.Sev
		}
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return a.Area < b.Area
	})
}

func sameSet(a, b []string) bool {
	a, b = cleanHosts(a), cleanHosts(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(strings.ToLower(s), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return "no detail"
}
