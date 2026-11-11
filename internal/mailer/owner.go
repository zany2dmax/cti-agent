package mailer

import (
	"fmt"
	"strings"
)

// THE OWNER LANE'S GATE
//
// The owner lane mails one application's scanner report to that
// application's owner and watchers - people who are often outside the
// company. Its recipients are not a fleet.env list. They are the owner and
// watchers= on the application's line in app-owners.txt, and every one of
// them must also be at a domain in OWNER_ALLOW_DOMAINS.
//
// The domain list is what catches a typo. A misspelled address at a real
// domain is a report about our unfixed vulnerabilities delivered to a
// stranger; a misspelled domain is refused here.
//
// No fallback, no --to, no --cc, and --approve does not widen it: the only
// way to add a recipient is to edit two root-owned files.
//
// One standing exception, also root-owned: WAS_OWNER_CC in fleet.env, the
// security team, copied on every owner email so it sees what each owner was
// sent. Its addresses pass the same domain check as a watcher. It is a
// separate list from WAS_TO on purpose: WAS_TO is the AppSec weekly's
// audience, which is wider than the people who should see every owner's
// report.

// OwnerAllowVar is the fleet.env variable naming the permitted domains.
const OwnerAllowVar = "OWNER_ALLOW_DOMAINS"

// OwnerCcVar is the fleet.env variable naming the security team copied on
// every owner email.
const OwnerCcVar = "WAS_OWNER_CC"

// OwnerTeamCc adds the WAS_OWNER_CC addresses to an owner email's Cc.
//
// Each one must be at a domain in allowDomains, exactly like a watcher; one
// that is not is left off and returned in refused, and the email still goes
// to the owner. An address already on To or Cc is not repeated. An empty
// team leaves cc unchanged: the setting is optional, and unset means the
// email is what it was before it existed.
func OwnerTeamCc(to, cc []string, team, allowDomains string) (out, refused []string) {
	permitted := ownerPermit(allowDomains)
	seen := map[string]bool{}
	for _, a := range append(append([]string(nil), to...), cc...) {
		seen[strings.ToLower(strings.TrimSpace(a))] = true
	}
	out = append([]string(nil), cc...)
	for _, a := range SplitList(team) {
		a = strings.TrimSpace(a)
		k := strings.ToLower(a)
		if a == "" || seen[k] {
			continue
		}
		seen[k] = true
		if permitted(a) {
			out = append(out, a)
		} else {
			refused = append(refused, a)
		}
	}
	return out, refused
}

// ownerPermit is the domain check shared by watchers and WAS_OWNER_CC.
func ownerPermit(allowDomains string) func(string) bool {
	allow := map[string]bool{}
	for _, d := range SplitList(allowDomains) {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" {
			allow[d] = true
		}
	}
	return func(a string) bool {
		if !ValidAddress(a) {
			return false
		}
		at := strings.LastIndex(a, "@")
		return allow[strings.ToLower(a[at+1:])]
	}
}

// OwnerAudience is who an application's report goes to: the owner on To and
// the watchers on Cc, each checked against allowDomains. A watcher outside it
// is dropped and returned in refused, for the operator; an owner outside it
// refuses the whole send, since a report to the watchers alone reaches nobody
// accountable for the fix.
//
// allowName is what the allowlist is called in messages: the fleet.env
// variable, or where owners.db keeps it.
func OwnerAudience(owner string, watchers []string, allowDomains, allowName string) (to, cc, refused []string, err error) {
	allow := map[string]bool{}
	for _, d := range SplitList(allowDomains) {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" {
			allow[d] = true
		}
	}
	if len(allow) == 0 {
		return nil, nil, nil, fmt.Errorf("%s is empty, so the owner lane will not send. "+
			"List the domains application owners and watchers may be at (yours and each "+
			"outside developer's)", allowName)
	}
	permitted := ownerPermit(allowDomains)
	owner = strings.TrimSpace(owner)
	if !permitted(owner) {
		return nil, nil, nil, fmt.Errorf("the owner %s is not at a domain in %s, so nothing is "+
			"sent for this application. Fix the owner's address, or add its domain to %s",
			owner, allowName, allowName)
	}
	seen := map[string]bool{strings.ToLower(owner): true}
	for _, w := range watchers {
		w = strings.TrimSpace(w)
		if w == "" || seen[strings.ToLower(w)] {
			continue
		}
		seen[strings.ToLower(w)] = true
		if permitted(w) {
			cc = append(cc, w)
		} else {
			refused = append(refused, w)
		}
	}
	return []string{owner}, cc, refused, nil
}
