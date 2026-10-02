// Package defender reads Microsoft Defender for Cloud attack-path
// notifications and turns them into something a person can act on.
//
// # WHAT THESE EMAILS DO AND DO NOT CONTAIN
//
// A real notification carries the risk level, the attack path name, the
// subscription GUID, a list of risk factors, a two-step "attack story", an
// attack path ID, and a link. It does NOT name the affected virtual machine,
// its resource group, its resource ID, or any CVE - not even when the attack
// path is titled "...with high severity vulnerabilities".
//
// So the email alone produces "an internet-facing VM somewhere in this
// subscription has an RCE, go look in the portal", which is the same
// unactionable shape as a ticket with no hostnames. Naming the resource takes
// an ARM call against Microsoft.Security/attackPaths, keyed on the attack path
// ID this package extracts.
package defender

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// PortalHost is the only host an unwrapped link is allowed to resolve to.
//
// An allowlist, not a blocklist, and not a "looks like Microsoft" check. The
// link arrives inside an email, and while this particular sender is Microsoft,
// nothing about the transport proves that - the mailbox accepts mail from
// anyone, and a forged Defender notification is a cheap and plausible phish
// aimed at exactly the person who reads this digest.
const PortalHost = "portal.azure.com"

// ErrNotPortal means the link did not resolve to the Azure portal. The caller
// should report this rather than hide it: a Defender notification whose link
// points somewhere else is a finding, not a parse failure.
var ErrNotPortal = errors.New("link does not resolve to the Azure portal")

// UnwrapPortalLink peels the layers off a link in a Defender notification and
// returns the portal URL, or an error.
//
// There are two wrappers in production mail:
//
//	Proofpoint:  https://urldefense.com/v3/__<INNER>__;<MAP>!!<TOK>!<TOK>$
//	Azure:       https://eur.safelink.emails.azure.net/redirect/?destination=<ENC>&p=<B64>
//
// # WHY UNWRAP AT ALL
//
// The wrapped form is over 400 characters of opaque tokens. A reader cannot
// tell where it goes, which defeats the one thing a human reviewer is good at.
// Unwrapping and then VERIFYING the destination is what makes it safe to show;
// unwrapping without verifying would be strictly worse than leaving it alone,
// because it would launder an arbitrary URL into something that looks checked.
//
// # FAIL CLOSED
//
// Every path that cannot produce a verified portal.azure.com URL returns an
// error. The caller renders the attack path ID instead and says the link was
// not what it claimed. Nothing here ever returns a URL it could not verify.
func UnwrapPortalLink(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("no link")
	}

	if inner, ok := unwrapProofpoint(s); ok {
		s = inner
	}
	if inner, ok := unwrapAzureSafelink(s); ok {
		s = inner
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("unwrapped link does not parse: %w", err)
	}
	// Hostname() strips any :port and the brackets on an IPv6 literal, and
	// comparing it whole - rather than with HasSuffix - is what stops
	// portal.azure.com.evil.example and evilportal.azure.com.
	if !strings.EqualFold(u.Hostname(), PortalHost) || u.Scheme != "https" {
		return "", fmt.Errorf("%w: %s", ErrNotPortal, u.Hostname())
	}
	return u.String(), nil
}

// unwrapProofpoint extracts the original URL from a urldefense v3 wrapper.
//
// v3 puts the URL between `__` and `__;`, with `%` rewritten to `*`. It also
// has a base64 dictionary form for other replaced characters; this handles the
// percent case and leaves anything else alone, because a half-decoded URL is
// still checked against the portal allowlist before it is used. Guessing at
// the dictionary and getting it wrong would produce a plausible-looking wrong
// URL, which is worse than not decoding.
func unwrapProofpoint(s string) (string, bool) {
	if !strings.Contains(s, "urldefense.com/") {
		return "", false
	}
	start := strings.Index(s, "__")
	if start < 0 {
		return "", false
	}
	rest := s[start+2:]
	end := strings.Index(rest, "__;")
	if end < 0 {
		return "", false
	}
	return strings.ReplaceAll(rest[:end], "*", "%"), true
}

// unwrapAzureSafelink pulls the destination out of Azure's own redirector.
func unwrapAzureSafelink(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), "safelink.emails.azure.net") {
		return "", false
	}
	dest := u.Query().Get("destination")
	if dest == "" {
		return "", false
	}
	return dest, true
}

// SubscriptionFromTracker recovers the subscription GUID from the redirector's
// `p` parameter, which base64-decodes to `m=<guid>&s=<subscription>&u=...`.
//
// A second, independent source for a value the email also states in its "Scope
// IDs" row. Worth having: when the two disagree, the email was not built the
// way this parser assumes, and that is a reason to stop trusting the rest of
// the parse rather than to pick one.
func SubscriptionFromTracker(link string) (string, bool) {
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	p := u.Query().Get("p")
	if p == "" {
		return "", false
	}
	// The tracker is standard base64 but arrives without padding often enough
	// that RawStdEncoding is the safer first attempt.
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(p, "="))
	if err != nil {
		return "", false
	}
	q, err := url.ParseQuery(string(b))
	if err != nil {
		return "", false
	}
	s := q.Get("s")
	return s, s != ""
}
