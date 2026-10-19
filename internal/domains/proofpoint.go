package domains

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PROOFPOINT ON DEMAND, FROM DNS ALONE
//
// The organisation's mail gateway is Proofpoint on Demand (PoD), inbound and
// outbound. That makes two of domains.txt's hand-kept facts visible in public
// DNS, with no API and no credential:
//
//   - RECEIVE. A domain whose MX hosts are our PoD tenant's (mx0a-<id>.pphosted.com
//     and its siblings) has its mail accepted by Proofpoint. An MX on
//     pphosted.com with a DIFFERENT tenant id is another organisation's
//     gateway receiving our domain's mail - worth a person's attention.
//   - SEND. Outbound relays through PoD, so a domain that sends has to
//     authorise PoD in SPF (an include on pphosted.com). One that does not is
//     sending some other way, or not at all; DNS cannot tell which, so the
//     report says "unconfirmed", never "does not send".
//
// The reason this matters is acquisitions. A newly acquired company's domains
// keep their old mail system - Microsoft 365 directly, Google, another
// gateway - for weeks or months until they are moved. Those domains are
// outside the gateway's filtering, and the weekly should say so, with how long
// each has been that way. After the move, whatever still authorises the old
// system (an SPF include, a Google DKIM key) is a sender nobody is watching.
//
// The tenant id is learned: the most common PoD tenant across every domain's
// MX is "ours". PROOFPOINT_POD_TENANT pins it, for the week that guess would
// be wrong. With no domain on pphosted.com at all and no pin, the whole check
// is off - this repository is public and not everyone uses Proofpoint.

// Route is how one domain's mail flows, as DNS shows it.
type Route struct {
	// Inbound is the provider key receiving the domain's mail: "pod" (our
	// tenant), "pod-other", one of the mailboxProviders keys, "other", or
	// "none" (no MX, or a null MX).
	Inbound      string
	InboundName  string // human name of Inbound
	InboundHosts []string
	// Tenant is the PoD tenant id in the MX, when Inbound is pod/pod-other.
	Tenant string
	// SPFPoD: SPF authorises Proofpoint on Demand.
	SPFPoD bool
	// SPFOthers are other MAILBOX providers SPF authorises (not SaaS
	// senders, which legitimately sit beside PoD), excluding the inbound one.
	SPFOthers []string
	// SPFAll is every recognised mailbox provider SPF authorises, inbound
	// one included - for saying what a domain off the gateway sends through.
	SPFAll []string
	// OldDKIM are selectors found for a mailbox provider that is not where
	// the domain's mail now goes (a Google Workspace key on a PoD domain).
	OldDKIM []string
	// Known is false when MX or SPF could not be looked up this run.
	Known bool
}

// State is the route reduced to one comparable string, for the weekly
// state file's "how long has it been like this".
func (r Route) State() string {
	switch r.Inbound {
	case "pod":
		if r.SPFPoD {
			return "pod"
		}
		return "pod-in-only"
	case "pod-other":
		return "pod-other:" + r.Tenant
	case "other":
		return "other:" + strings.Join(r.InboundHosts, ",")
	default:
		return r.Inbound
	}
}

type provider struct{ key, name string }

// mailboxProviders are systems that HOST mail, matched by host suffix. A
// domain on one of these is not behind the gateway.
var mailboxProviders = []struct {
	suffix string
	provider
}{
	{".mail.protection.outlook.com", provider{"m365", "Microsoft 365 directly"}},
	{"spf.protection.outlook.com", provider{"m365", "Microsoft 365 directly"}},
	{"aspmx.l.google.com", provider{"google", "Google Workspace"}},
	{".aspmx.l.google.com", provider{"google", "Google Workspace"}},
	{"googlemail.com", provider{"google", "Google Workspace"}},
	{"smtp.google.com", provider{"google", "Google Workspace"}},
	{"_spf.google.com", provider{"google", "Google Workspace"}},
	{".ppe-hosted.com", provider{"ppe", "Proofpoint Essentials (a different Proofpoint product)"}},
	{".mimecast.com", provider{"mimecast", "Mimecast"}},
	{".barracudanetworks.com", provider{"barracuda", "Barracuda"}},
	{".iphmx.com", provider{"cisco", "Cisco Secure Email"}},
	{".secureserver.net", provider{"godaddy", "GoDaddy email"}},
	{"secureserver.net", provider{"godaddy", "GoDaddy email"}},
	{".zoho.com", provider{"zoho", "Zoho Mail"}},
	{".messagelabs.com", provider{"symantec", "Symantec/Broadcom Email Security"}},
}

// podMX matches a PoD inbound host and captures the tenant id:
// mx0a-00123456.pphosted.com, mx0b-..., mxa-00123456.gslb.pphosted.com.
var podMX = regexp.MustCompile(`^mx[0-9]*[a-z]-([0-9a-z]+)\.(?:gslb\.)?pphosted\.com$`)

// podSPF captures a tenant-specific SPF include: spf-00123456.pphosted.com.
var podSPF = regexp.MustCompile(`^spf-([0-9a-z]+)\.pphosted\.com$`)

func isPoDHost(h string) bool { return strings.HasSuffix(h, ".pphosted.com") }

func providerOf(host string) (provider, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, p := range mailboxProviders {
		if h == strings.TrimPrefix(p.suffix, ".") || strings.HasSuffix(h, p.suffix) {
			return p.provider, true
		}
	}
	return provider{}, false
}

// mxHost strips the preference from "10 mx0a-x.pphosted.com." if present.
func mxHost(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(f[len(f)-1], "."))
}

// spfTargets are the include: and redirect= domains of one SPF record.
func spfTargets(rec string) []string {
	var out []string
	for _, t := range strings.Fields(strings.ToLower(rec)) {
		t = strings.TrimLeft(t, "+~?-")
		switch {
		case strings.HasPrefix(t, "include:"):
			out = append(out, strings.TrimPrefix(t, "include:"))
		case strings.HasPrefix(t, "redirect="):
			out = append(out, strings.TrimPrefix(t, "redirect="))
		}
	}
	return out
}

// HomeTenant is our PoD tenant id: PROOFPOINT_POD_TENANT if set, else the
// tenant a STRICT MAJORITY of the inventory's PoD domains use. "" when no
// domain uses PoD, or when no tenant has a majority - then the check is off
// and the caller says why, rather than guessing: a guess flipped by an
// acquisition with more PoD domains than ours would report every one of our
// own domains as "another organisation's gateway".
func HomeTenant(results []Result) string {
	t, _ := HomeTenantWhy(results)
	return t
}

// HomeTenantWhy is HomeTenant plus every tenant seen with its domain count,
// for the log line.
func HomeTenantWhy(results []Result) (string, map[string]int) {
	if t := strings.ToLower(strings.TrimSpace(os.Getenv("PROOFPOINT_POD_TENANT"))); t != "" {
		return t, nil
	}
	count := map[string]int{}
	for _, r := range results {
		for _, v := range r.Mail.MX.Values {
			if m := podMX.FindStringSubmatch(mxHost(v)); m != nil {
				count[m[1]]++
				break // one vote per domain, not per MX host
			}
		}
	}
	total, best, n := 0, "", 0
	for t, c := range count {
		total += c
		if c > n || (c == n && t < best) {
			best, n = t, c
		}
	}
	if n*2 <= total {
		return "", count // no strict majority: pin PROOFPOINT_POD_TENANT
	}
	return best, count
}

// RouteOf works out one domain's route against our tenant.
func RouteOf(r Result, tenant string) Route {
	rt := Route{Known: r.Mail.MX.Known() && r.Mail.SPF.Known()}
	var hosts []string
	for _, v := range r.Mail.MX.Values {
		if h := mxHost(v); h != "" && h != "." {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	rt.InboundHosts = hosts

	switch {
	case len(hosts) == 0:
		rt.Inbound, rt.InboundName = "none", "no inbound mail"
	default:
		var podOurs, podOther, other int
		var first provider
		for _, h := range hosts {
			if m := podMX.FindStringSubmatch(h); m != nil {
				if m[1] == tenant {
					podOurs++
				} else {
					podOther++
					rt.Tenant = m[1]
				}
				continue
			}
			if isPoDHost(h) {
				podOurs++ // a PoD host without a tenant in its name
				continue
			}
			if p, ok := providerOf(h); ok && first.key == "" {
				first = p
			}
			other++
		}
		switch {
		case podOurs == len(hosts):
			rt.Inbound, rt.InboundName, rt.Tenant = "pod", "Proofpoint on Demand", tenant
		case podOther > 0 && other == 0:
			rt.Inbound, rt.InboundName = "pod-other", "another organisation's Proofpoint tenant"
		case first.key != "":
			rt.Inbound, rt.InboundName = first.key, first.name
		default:
			rt.Inbound, rt.InboundName = "other", "an unrecognised mail host"
		}
		if podOurs > 0 && podOurs < len(hosts) {
			rt.InboundName += " (mixed with Proofpoint)"
		}
	}

	seen := map[string]bool{}
	var targets []string
	for _, rec := range r.Mail.SPF.Values {
		targets = append(targets, spfTargets(rec)...)
	}
	targets = append(targets, r.Mail.SPFIncludes...)
	allSeen := map[string]bool{}
	for _, t := range targets {
		if p, ok := providerOf(t); ok {
			rt.SPFAll = appendOnce(rt.SPFAll, allSeen, p.name)
		}
	}
	for _, t := range targets {
		if isPoDHost(t) || t == "pphosted.com" {
			rt.SPFPoD = true
			if m := podSPF.FindStringSubmatch(t); m != nil && tenant != "" && m[1] != tenant {
				rt.SPFOthers = appendOnce(rt.SPFOthers, seen,
					"another Proofpoint tenant ("+m[1]+")")
			}
			continue
		}
		if p, ok := providerOf(t); ok && p.key != rt.Inbound {
			rt.SPFOthers = appendOnce(rt.SPFOthers, seen, p.name)
		}
	}
	// A Google Workspace key on a domain whose mail is not at Google is left
	// over from before a move. Microsoft's selector1/selector2 are NOT: with
	// PoD outbound, Microsoft 365 still signs before relaying.
	if rt.Inbound != "google" && containsFold(r.Mail.DKIM.Found, "google") {
		rt.OldDKIM = append(rt.OldDKIM, "google")
	}
	return rt
}

func appendOnce(list []string, seen map[string]bool, s string) []string {
	if seen[s] {
		return list
	}
	seen[s] = true
	return append(list, s)
}

// AssignRoutes fills every result's Route. A no-op when tenant is "" (no
// domain on PoD, nothing pinned): the check is off.
func AssignRoutes(results []Result, tenant string) {
	if tenant == "" {
		return
	}
	for i := range results {
		results[i].Route = RouteOf(results[i], tenant)
		results[i].RouteChecked = true
	}
}

// weeksSince renders how long a route has been in its state, from the state
// file's date. "" when unknown.
func weeksSince(since string, now time.Time) string {
	t, err := time.Parse("2006-01-02", since)
	if err != nil || t.After(now) {
		return ""
	}
	days := int(now.Sub(t).Hours() / 24)
	switch w := days / 7; {
	case days < 7:
		return "first seen this week"
	case w == 1:
		return "for 1 week"
	default:
		return fmt.Sprintf("for %d weeks", w)
	}
}

// EvalProofpoint turns routes into findings, Area "proofpoint". cur is this
// run's state, for how long each domain has been off the gateway.
func EvalProofpoint(results []Result, cur *State, now time.Time) []Finding {
	var out []Finding
	add := func(d string, s Severity, f string, a ...any) {
		out = append(out, Finding{Domain: d, Sev: s, Area: "proofpoint", Text: fmt.Sprintf(f, a...)})
	}
	for _, r := range results {
		if !r.RouteChecked || !r.Route.Known {
			continue
		}
		d, rt := r.Entry.Name, r.Route
		since := ""
		if cur != nil {
			since = weeksSince(cur.Domains[d].RouteSince, now)
		}
		when := ""
		if since != "" {
			when = " - " + since
		}
		switch rt.Inbound {
		case "pod":
			// On the gateway. Only what is left behind is worth a line.
		case "pod-other":
			add(d, High, "MX is on Proofpoint but tenant %s, not ours: another organisation's "+
				"gateway receives this domain's mail (%s)%s", rt.Tenant,
				strings.Join(rt.InboundHosts, ", "), when)
		case "none":
			// Receives nothing. A sender with no MX is handled below.
		default:
			if !r.Entry.Receives {
				// Inventory says it receives no mail: the stray MX is already
				// reported by the lock-down rules, once is enough.
				break
			}
			add(d, Medium, "NOT YET ON PROOFPOINT: mail is received by %s (%s), outside the "+
				"gateway's filtering%s", rt.InboundName, strings.Join(rt.InboundHosts, ", "), when)
		}
		if r.Entry.Sends && !rt.SPFPoD {
			others := "nothing that identifies the sender"
			if len(rt.SPFAll) > 0 {
				others = strings.Join(rt.SPFAll, ", ")
			}
			add(d, Medium, "sends, but SPF does not authorise Proofpoint: its outbound mail is "+
				"not going through the gateway (SPF authorises %s) - send route unconfirmed%s",
				others, when)
		}
		if rt.Inbound == "pod" && len(rt.SPFOthers) > 0 {
			var m365, rest []string
			for _, o := range rt.SPFOthers {
				if o == "Microsoft 365 directly" {
					m365 = append(m365, o)
				} else {
					rest = append(rest, o)
				}
			}
			if len(rest) > 0 {
				add(d, Medium, "on Proofpoint, but SPF still authorises %s: left over from before "+
					"the move, and anyone on that service can pass SPF as this domain - remove it "+
					"once nothing still sends that way", strings.Join(rest, ", "))
			}
			if len(m365) > 0 {
				// Commonly kept on purpose with PoD in front of Microsoft 365,
				// so a note, not a finding to fix.
				add(d, Info, "on Proofpoint, and SPF also authorises Microsoft 365 directly: "+
					"needed only if something sends from Microsoft 365 without relaying "+
					"through Proofpoint; otherwise any Microsoft 365 tenant passes SPF as "+
					"this domain")
			}
		}
		if len(rt.OldDKIM) > 0 && r.Entry.Sends {
			add(d, Medium, "a DKIM key is still published at selector %s for a mail system this "+
				"domain no longer uses - revoke it (publish p= empty) once nothing signs with it",
				strings.Join(rt.OldDKIM, ", "))
		}
	}
	SortFindings(out)
	return out
}
