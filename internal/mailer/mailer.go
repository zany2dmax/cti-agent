// Package mailer decides who receives a message, and what it says.
//
// This is the port of mailer.py's policy. It is a separate package from the
// command, and from internal/graph, for one reason: **the recipient gate is
// the most security-relevant decision in this codebase**, and a decision that
// can only be exercised by sending mail is a decision nobody tests.
//
// Everything here is pure. No network, no files, no environment reads. Give it
// the inputs and it returns the answer, so the allowlist can be tested against
// a table of cases rather than against a tenant.
//
// # WHY THIS MOVED FROM PYTHON
//
// mailer.py is the single outbound channel for the whole fleet and holds the
// FLEET_ALLOW_TO gate, and it was the most security-relevant code in the
// repository sitting outside gosec and govulncheck - not because Python was
// the right tool, but because that is where it started. It needs no SQLite,
// which is the only thing keeping the other lanes in Python.
//
// The behaviour is deliberately unchanged. A port that also improves things
// cannot be verified by comparing old and new output, and this is the one
// component where "it sends slightly different mail now" is discovered by
// somebody not receiving a security finding.
package mailer

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"
)

// addressRE matches what mailer.py accepted: something, an @, something with a
// dot in it, no spaces. Deliberately not RFC 5322 - this validates operator
// typing in a config file, and a full parser would accept addresses that
// Exchange then rejects anyway.
var addressRE = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// ValidAddress reports whether an address is well-formed enough to send to.
func ValidAddress(s string) bool { return addressRE.MatchString(s) }

// SplitList parses a comma-separated address list, dropping empty entries.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Truthy reads a boolean out of hand-edited configuration.
//
// fleet.env is edited by hand, so "true", "True", "1", "yes" and "on" all have
// to work. Anything unrecognised is false: a flag that turns a security
// control into a distribution list must not be enabled by a typo.
func Truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Audience is the inputs needed to work out who receives a message.
type Audience struct {
	ToOperator bool   // escalation: goes to Operator, never CC'd
	ToFlag     string // --to
	CCFlag     string // --cc
	DigestTo   string // DIGEST_TO
	DigestCC   string // DIGEST_CC
	Operator   string // FLEET_OPERATOR_EMAIL
	AllowRaw   string // FLEET_ALLOW_TO, raw

	// CCFromAllow mirrors DIGEST_CC_FROM_ALLOW_TO. Opt-in, because it changes
	// what FLEET_ALLOW_TO MEANS: from "addresses this fleet may mail" to
	// "addresses this fleet mails".
	CCFromAllow bool
}

// Resolve works out the To and Cc lists, or explains why it cannot.
//
// The order of operations is load-bearing and matches mailer.py exactly:
// derive To, derive Cc, optionally extend Cc from the raw allowlist, validate
// every address, then remove from Cc anyone already in To.
func (a Audience) Resolve() (to, cc []string, err error) {
	switch {
	case a.ToOperator && a.ToFlag != "":
		return nil, nil, fmt.Errorf("--to-operator and --to are mutually exclusive")
	case a.ToOperator && strings.TrimSpace(a.Operator) == "":
		return nil, nil, fmt.Errorf("FLEET_OPERATOR_EMAIL is not set in fleet.env - " +
			"the fleet has nowhere to escalate to")
	case a.ToOperator:
		to = SplitList(a.Operator)
	default:
		raw := a.ToFlag
		if raw == "" {
			raw = a.DigestTo
		}
		to = SplitList(raw)
	}
	if len(to) == 0 {
		return nil, nil, fmt.Errorf("no recipients - set DIGEST_TO in fleet.env or " +
			"pass --to. There is no default; the fleet will not guess who " +
			"receives security findings.")
	}

	// Escalations are never CC'd: a question addressed to one person should
	// not become a thread.
	if !a.ToOperator {
		raw := a.CCFlag
		if raw == "" {
			raw = a.DigestCC
		}
		cc = SplitList(raw)

		// Read from the RAW allowlist, not the augmented set used by the gate
		// below - that one has the operator added so the orchestrator can
		// always escalate, and silently CC-ing the operator on every digest is
		// not what enabling this asks for.
		if a.CCFromAllow {
			have := map[string]bool{}
			for _, r := range cc {
				have[strings.ToLower(r)] = true
			}
			for _, x := range SplitList(a.AllowRaw) {
				if !have[strings.ToLower(x)] {
					cc = append(cc, x)
				}
			}
		}
	}

	for _, r := range append(append([]string{}, to...), cc...) {
		if !ValidAddress(r) {
			// Single quotes, because mailer.py used f"{r!r}" and Python's
			// repr() quotes a plain string with them. %q would print double
			// quotes and the two messages would differ - which is the sort of
			// drift that makes "behaviour identical" a claim nobody can rely
			// on.
			//
			// repr() switches to double quotes for a value that itself
			// contains a single quote. Not replicated: an address with an
			// apostrophe in it is already being rejected, and matching
			// Python's quoting heuristics exactly would be a worse trade than
			// saying so here.
			return nil, nil, fmt.Errorf("'%s' is not a valid address", r)
		}
	}

	// A Cc that is already a To recipient is a duplicate delivery, and Graph
	// sends both. This matters more with the allowlist as the Cc source, since
	// DIGEST_TO is normally in FLEET_ALLOW_TO by definition.
	seen := map[string]bool{}
	for _, r := range to {
		seen[strings.ToLower(r)] = true
	}
	var deduped []string
	for _, r := range cc {
		if !seen[strings.ToLower(r)] {
			deduped = append(deduped, r)
		}
	}
	return to, deduped, nil
}

// CheckAllowed is the autonomy gate.
//
// Scheduled digests to the allowlisted distribution list are pre-approved, and
// so are escalations to the operator's own address - the orchestrator has to
// be able to ask a question without needing permission to ask it. Anything
// else needs an explicit human OK on this specific send.
//
// FLEET_ALLOW_TO defaults to DIGEST_TO rather than to everything, so an
// unconfigured deployment fails closed: the scheduled digest still works and
// any other recipient needs --approve.
//
// **The gate covers Cc as well as To.** Exempting Cc would make the allowlist
// trivially bypassable - the whole control is "this fleet cannot mail an
// address nobody approved", and a header name does not change who receives the
// findings.
func CheckAllowed(to, cc []string, allowRaw, digestTo, operator string, approved bool) error {
	raw := allowRaw
	if strings.TrimSpace(raw) == "" {
		raw = digestTo
	}
	allow := map[string]bool{}
	for _, a := range SplitList(raw) {
		allow[strings.ToLower(a)] = true
	}
	if op := strings.TrimSpace(operator); op != "" {
		allow[strings.ToLower(op)] = true
	}

	var outside []string
	for _, r := range append(append([]string{}, to...), cc...) {
		if !allow[strings.ToLower(r)] {
			outside = append(outside, r)
		}
	}
	if len(outside) > 0 && !approved {
		return fmt.Errorf("recipients outside FLEET_ALLOW_TO: %s. Add them to "+
			"FLEET_ALLOW_TO in fleet.env for a standing recipient, or post the "+
			"draft to the board tagged [APPROVE] and re-run with --approve for "+
			"a one-off.", strings.Join(outside, ", "))
	}
	return nil
}

// MaxSubject is Graph's practical limit. Longer subjects are truncated rather
// than rejected: losing the tail of a subject is a cosmetic failure, and
// refusing to send a Sev5 over it is not.
const MaxSubject = 255

// Subject builds the final subject line.
//
// Whitespace is collapsed because a subject assembled from a template can
// carry newlines, and a newline in a mail header is a header-injection
// primitive as well as a rendering bug.
func Subject(raw, boardID string, isMessage bool, now time.Time) string {
	s := raw
	if strings.TrimSpace(s) == "" {
		s = "CTI Brief " + now.Format("2006-01-02")
	}
	if isMessage && boardID != "" {
		tag := "[FLEET " + boardID + "]"
		if !strings.Contains(s, tag) {
			s = tag + " " + s
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > MaxSubject {
		s = s[:MaxSubject]
	}
	return s
}

// HighImportance reports whether a subject earns the urgent flag.
//
// Reserved for Sev5. A system that marks everything urgent has marked nothing
// urgent, so this is a prefix match and not a keyword search.
func HighImportance(subject string) bool {
	return strings.HasPrefix(subject, "[Sev5]")
}

// EscalationHTML renders a short question or alert.
//
// Deliberately plain: this is a question, not a report. The reply instructions
// matter more than the styling - an escalation nobody knows how to answer just
// stalls the fleet.
func EscalationHTML(message, boardID, replyTo string) string {
	if strings.TrimSpace(replyTo) == "" {
		replyTo = "this mailbox"
	}
	tag := "[FLEET]"
	if boardID != "" {
		tag = "[FLEET " + boardID + "]"
	}
	var paras strings.Builder
	for _, block := range strings.Split(message, "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		// Escape first, then turn the remaining newlines into breaks. The
		// other order would let a <br> in the source survive escaping.
		esc := strings.ReplaceAll(html.EscapeString(block), "\n", "<br>")
		paras.WriteString(`<p style="margin:0 0 10px 0">` + esc + `</p>`)
	}
	return `<!DOCTYPE html>
<html><body style="margin:0;padding:16px;background:#eef1f5">
<table width="100%" cellpadding="0" cellspacing="0" role="presentation">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" role="presentation"
       style="max-width:560px;background:#fff;border-radius:6px">
  <tr><td style="background:#12203a;padding:12px 18px;font:700 14px
                 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#fff">
    CTI Fleet</td></tr>
  <tr><td style="padding:16px 18px;font:400 14px/1.55 -apple-system,Segoe UI,
                 Helvetica,Arial,sans-serif;color:#1a202c">` + paras.String() + `</td></tr>
  <tr><td style="padding:12px 18px 16px 18px;border-top:1px solid #e2e8f0;
                 font:400 12px/1.6 -apple-system,Segoe UI,Helvetica,Arial,
                 sans-serif;color:#4a5568">
    <b>To answer:</b> reply to this message, keeping
    <code>` + html.EscapeString(tag) + `</code> in the subject. The orchestrator reads
    ` + html.EscapeString(replyTo) + ` on its next check-in, posts your answer to the board,
    and the waiting lane picks it up.
  </td></tr>
</table></td></tr></table></body></html>`
}
