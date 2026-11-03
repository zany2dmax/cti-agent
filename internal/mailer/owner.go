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

// OwnerAllowVar is the fleet.env variable naming the permitted domains.
const OwnerAllowVar = "OWNER_ALLOW_DOMAINS"

// OwnerAudience is who an application's report goes to: the owner on To and
// the watchers on Cc, each checked against allowDomains. A watcher outside it
// is dropped and returned in refused, for the operator; an owner outside it
// refuses the whole send, since a report to the watchers alone reaches nobody
// accountable for the fix.
func OwnerAudience(owner string, watchers []string, allowDomains string) (to, cc, refused []string, err error) {
	allow := map[string]bool{}
	for _, d := range SplitList(allowDomains) {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" {
			allow[d] = true
		}
	}
	if len(allow) == 0 {
		return nil, nil, nil, fmt.Errorf("%s is not set, so the owner lane will not send. "+
			"List the domains application owners and watchers may be at (yours and each "+
			"outside developer's) in fleet.env", OwnerAllowVar)
	}
	permitted := func(a string) bool {
		if !ValidAddress(a) {
			return false
		}
		at := strings.LastIndex(a, "@")
		return allow[strings.ToLower(a[at+1:])]
	}
	owner = strings.TrimSpace(owner)
	if !permitted(owner) {
		return nil, nil, nil, fmt.Errorf("the owner %s is not at a domain in %s, so nothing is "+
			"sent for this application. Fix the address in app-owners.txt, or add its domain to %s",
			owner, OwnerAllowVar, OwnerAllowVar)
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
