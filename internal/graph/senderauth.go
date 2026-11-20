package graph

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/zany2dmax/cti-agent/internal/audit"
)

// UnauthenticatedSendersEnv lists From domains whose mail is read even when the
// receiving server did not authenticate it: "qualys.net,scanner.example". It is
// for a tenant whose inbound path hides the sender from Exchange Online (a
// gateway in front without enhanced filtering for connectors), where every
// genuine notice fails the check and is reported as a problem.
//
// It replaces FLEET_SENDER_AUTH=off, which switched the check off for EVERY
// sender: with it set, a forged From of any scanner or feed address was read,
// and a forged intel email reached a model. A list names the few domains a
// gateway really hides, and everything else is still checked. Exact domains
// only: no wildcard, no subdomain match. It is still a bypass for the domains
// on it (a forged From of a listed domain is believed), so list as few as the
// problem needs, and prefer fixing the connector.
const UnauthenticatedSendersEnv = "FLEET_UNAUTHENTICATED_SENDERS"

// legacySenderAuthEnv is the switch this list replaced. It is no longer
// honoured, and a message that would have passed because of it says so.
const legacySenderAuthEnv = "FLEET_SENDER_AUTH"

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ParseUnauthenticatedSenders splits the setting into valid domains and the
// entries it refused (a wildcard, an address, anything that is not a plain
// domain name).
func ParseUnauthenticatedSenders(v string) (domains, bad []string) {
	for _, e := range strings.Split(v, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case domainRE.MatchString(e):
			domains = append(domains, e)
		default:
			bad = append(bad, e)
		}
	}
	return domains, bad
}

var (
	warnOnce  sync.Once
	acceptedM sync.Mutex
	accepted  = map[string]bool{}
)

// VouchedFor is SenderAuthenticated, or true when the From domain is listed in
// FLEET_UNAUTHENTICATED_SENDERS. Lanes that act on a message because of who
// sent it call this. A message accepted only because its domain is listed is
// written to the audit trail, once per domain per run: the bypass is visible.
func (m Message) VouchedFor() (bool, string) {
	ok, why := m.SenderAuthenticated()
	if ok {
		auditVerdict(fromDomain(m.From), audit.Success, "the receiving server authenticated the sender")
		return true, ""
	}
	listed, bad := ParseUnauthenticatedSenders(os.Getenv(UnauthenticatedSendersEnv))
	if len(bad) > 0 {
		warnOnce.Do(func() {
			_, _ = fmt.Fprintf(os.Stderr, "%s: ignoring %q (exact domain names only, such as qualys.net)\n",
				UnauthenticatedSendersEnv, strings.Join(bad, ","))
		})
	}
	if d := fromDomain(m.From); d != "" {
		for _, l := range listed {
			if d == l {
				auditAccepted(d, why)
				return true, ""
			}
		}
	}
	auditVerdict(fromDomain(m.From), audit.Refused, why)
	if strings.EqualFold(strings.TrimSpace(os.Getenv(legacySenderAuthEnv)), "off") {
		why += "; " + legacySenderAuthEnv + "=off is no longer honoured: list the sender's domain in " +
			UnauthenticatedSendersEnv + " instead"
	}
	return false, why
}

// auditVerdict records an authentication verdict that decided whether a
// message was believed, once per sender domain and outcome per run (a mailbox
// of three hundred notices is one line, not three hundred). Success and
// refusal are both written: "who did we trust, and who did we turn away" is
// the audit question. Never the address, subject or body of the message.
func auditVerdict(domain, outcome, why string) {
	if domain == "" {
		domain = "(no domain)"
	}
	acceptedM.Lock()
	key := outcome + " " + domain
	seen := accepted[key]
	accepted[key] = true
	acceptedM.Unlock()
	if seen {
		return
	}
	audit.Emit(audit.Event{Action: "sender.authentication", Target: domain, Outcome: outcome, Detail: why})
}

func auditAccepted(domain, why string) {
	acceptedM.Lock()
	seen := accepted[domain]
	accepted[domain] = true
	acceptedM.Unlock()
	if seen {
		return
	}
	audit.Emit(audit.Event{Action: "sender.unauthenticated.accepted", Target: domain, Outcome: audit.Success,
		Detail: "read on the strength of " + UnauthenticatedSendersEnv + "; the check said: " + why})
}

// SenderAuthenticated reports whether the receiving server authenticated the
// message's From domain, and if not, why not, in words for a report line.
//
// A From address is a claim the sender makes. Code that trusts a message
// because of who it is from (a Qualys scan notice, say) must also see the
// receiving server vouch for it. Exchange Online writes that verdict in the
// Authentication-Results header it prepends:
//
//	spf=pass (sender IP is ...) smtp.mailfrom=qualys.com; dkim=pass
//	(signature was verified) header.d=qualys.com;dmarc=pass action=none
//	header.from=qualys.com;compauth=pass reason=100
//
// Either result is enough:
//   - compauth=pass, Microsoft's composite verdict on the From domain;
//   - dmarc=pass, with header.from the same domain as the From address.
//
// Only the first Authentication-Results header is read (Message holds no
// other), because the ones below it came with the message. Before this, the
// Qualys parsers trusted the From address alone (PrimeSec attack vector
// 10786562).
func (m Message) SenderAuthenticated() (bool, string) {
	ar := strings.TrimSpace(m.AuthenticationResults)
	if ar == "" {
		return false, "no Authentication-Results header from the receiving server"
	}
	from := fromDomain(m.From)
	results := map[string]string{}
	headerFrom := ""
	for _, clause := range strings.Split(ar, ";") {
		f := strings.Fields(strings.TrimSpace(clause))
		if len(f) == 0 {
			continue
		}
		method, result, ok := strings.Cut(f[0], "=")
		if !ok {
			continue
		}
		method = strings.ToLower(method)
		if _, seen := results[method]; !seen {
			results[method] = strings.ToLower(result)
		}
		if method == "dmarc" {
			for _, p := range f[1:] {
				if k, v, ok := strings.Cut(p, "="); ok && strings.EqualFold(k, "header.from") {
					headerFrom = strings.ToLower(strings.TrimSpace(v))
				}
			}
		}
	}
	if results["compauth"] == "pass" {
		return true, ""
	}
	if results["dmarc"] == "pass" && from != "" && headerFrom == from {
		return true, ""
	}
	why := []string{}
	for _, k := range []string{"dmarc", "compauth"} {
		if v, ok := results[k]; ok {
			why = append(why, k+"="+v)
		}
	}
	if len(why) == 0 {
		return false, "the receiving server recorded no DMARC or composite authentication result"
	}
	if results["dmarc"] == "pass" {
		return false, "dmarc=pass was for " + headerFrom + ", not the From domain " + from
	}
	return false, "the receiving server did not authenticate the sender (" + strings.Join(why, ", ") + ")"
}

// fromDomain is the lowercased domain of the address in "Name <addr>" or a
// bare addr, or "" if there is none.
func fromDomain(from string) string {
	s := strings.TrimSpace(from)
	if i := strings.LastIndex(s, "<"); i >= 0 {
		s = strings.TrimSuffix(strings.TrimSpace(s[i+1:]), ">")
	}
	at := strings.LastIndex(s, "@")
	if at < 0 || strings.ContainsAny(s, " <>") {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s[at+1:]))
}
