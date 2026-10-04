package mailer

import (
	"fmt"
	"strings"
)

// Lane is one report's audience and its own allowlist.
//
// # WHY NOT REUSE CheckAllowed
//
// CheckAllowed falls back to DIGEST_TO when its allowlist is empty:
//
//	raw := allowRaw
//	if strings.TrimSpace(raw) == "" {
//	    raw = digestTo
//	}
//
// That is defensible for the one audience it was written for. Applied to a
// second audience it becomes the exact bug the second audience exists to
// prevent: an unset WAS_ALLOW_LIST would silently fall back to the
// Infrastructure digest recipients, and the application-security report -
// which names which applications have open Urgent findings and which are
// scanned
// without authentication - would go to the people who have no need for it, as
// a successful send.
//
// So a lane allowlist has no fallback. Unset means refuse, loudly, naming the
// variable to edit. A report that does not go out is an inconvenience; a
// report that goes to the wrong distribution list cannot be recalled.
//
// # WHY EACH LANE NAMES ITS OWN VARIABLES
//
// The error has to tell an operator which file and which line. "Recipients
// outside the allowlist" is useless when there are three allowlists.
type Lane struct {
	// Name is the lane, for error messages: "was", "vm", "patchtuesday".
	Name string
	// ToVar and AllowVar are the fleet.env variable names, quoted verbatim in
	// every error this type produces.
	ToVar    string
	AllowVar string

	// To and Allow are the raw values of those variables.
	To    string
	Allow string

	// Operator is FLEET_OPERATOR_EMAIL. Always permitted, because it is the
	// escalation path and a lane that cannot reach a human is a lane that
	// fails silently.
	Operator string

	// Lookup resolves $OTHER_ALLOW_TO references inside Allow. Nil means
	// references are not available, and a list containing one is refused
	// rather than silently treated as literal text.
	Lookup func(string) (string, bool)
}

// Resolve returns the recipients for this lane, or explains why it will not
// send.
//
// approved mirrors the --approve flag: a human has seen the draft and accepted
// a one-off recipient outside the list. It does NOT bypass an unset allowlist,
// because there is nothing to have reviewed - an empty list is a
// misconfiguration, not a narrow one.
func (l Lane) Resolve(approved bool) ([]string, error) {
	allowVar := orDefault(l.AllowVar, "the lane allowlist")
	toVar := orDefault(l.ToVar, "the lane recipient list")

	if strings.TrimSpace(l.Allow) == "" {
		return nil, fmt.Errorf(
			"%s is not set, so the %s lane will not send. This does NOT fall "+
				"back to another lane's recipients: that is how a report reaches "+
				"an audience nobody chose. Set %s in fleet.env",
			allowVar, l.Name, allowVar)
	}

	to := SplitList(l.To)
	if len(to) == 0 {
		return nil, fmt.Errorf(
			"%s is not set, so the %s lane has no recipients. There is no "+
				"default: a hardcoded address is a mis-send waiting to happen",
			toVar, l.Name)
	}

	lookup := l.Lookup
	if lookup == nil {
		// No resolver: references cannot be expanded, so a list containing one
		// must not be read as a literal address called "$VM_ALLOW_TO".
		lookup = func(string) (string, bool) { return "", false }
	}
	expanded, err := ExpandAllow(allowVar, l.Allow, lookup)
	if err != nil {
		return nil, err
	}
	if len(expanded) == 0 {
		return nil, fmt.Errorf(
			"%s expanded to no addresses, so the %s lane will not send",
			allowVar, l.Name)
	}

	allow := map[string]bool{}
	for _, a := range expanded {
		allow[strings.ToLower(a)] = true
	}
	if op := strings.TrimSpace(l.Operator); op != "" {
		allow[strings.ToLower(op)] = true
	}

	var bad, outside []string
	for _, r := range to {
		if !ValidAddress(r) {
			bad = append(bad, r)
			continue
		}
		if !allow[strings.ToLower(r)] {
			outside = append(outside, r)
		}
	}
	// Malformed addresses are refused even with --approve. Approving a
	// recipient you cannot read is not approval.
	if len(bad) > 0 {
		return nil, fmt.Errorf("%s contains malformed address(es): %s",
			toVar, strings.Join(bad, ", "))
	}
	if len(outside) > 0 && !approved {
		return nil, fmt.Errorf(
			"recipients outside %s: %s. Add them to %s in fleet.env for a "+
				"standing recipient, or re-run with --approve for a one-off",
			allowVar, strings.Join(outside, ", "), allowVar)
	}
	return to, nil
}

// CrossCheck reports whether this lane's recipients overlap another lane's.
//
// Not an error. Two lanes legitimately share people - an operator sits on
// both - and refusing that would be wrong. But a WAS report whose recipients
// are entirely the VM audience almost certainly means WAS_TO was copied from
// DIGEST_TO and never edited, which is the misconfiguration this whole split
// exists to catch. The caller logs it; a human decides.
func (l Lane) CrossCheck(otherName, otherTo string) string {
	mine, theirs := SplitList(l.To), SplitList(otherTo)
	if len(mine) == 0 || len(theirs) == 0 {
		return ""
	}
	set := map[string]bool{}
	for _, a := range theirs {
		set[strings.ToLower(a)] = true
	}
	n := 0
	for _, a := range mine {
		if set[strings.ToLower(a)] {
			n++
		}
	}
	if n != len(mine) {
		return ""
	}
	return fmt.Sprintf(
		"every %s recipient is also a %s recipient - check that %s was not "+
			"copied from the %s list and left unedited",
		l.Name, otherName, orDefault(l.ToVar, "the recipient list"), otherName)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
