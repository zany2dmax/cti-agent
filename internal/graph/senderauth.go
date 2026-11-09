package graph

import (
	"os"
	"strings"
)

// SenderAuthEnv turns the sender check off when set to "off". It is for a
// tenant whose inbound path hides the sender from Exchange Online (a gateway
// in front without enhanced filtering for connectors): there every genuine
// notice fails, and each one is reported as a problem until this is set.
const SenderAuthEnv = "FLEET_SENDER_AUTH"

// VouchedFor is SenderAuthenticated unless FLEET_SENDER_AUTH=off. Lanes that
// act on a message because of who sent it call this.
func (m Message) VouchedFor() (bool, string) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv(SenderAuthEnv)), "off") {
		return true, ""
	}
	return m.SenderAuthenticated()
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
