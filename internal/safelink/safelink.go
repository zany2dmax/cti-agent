// Package safelink unwraps the layers mail gateways put around links, and
// then verifies where the result actually goes.
//
// # WHY THIS IS SHARED AND NOT COPIED
//
// Two lanes needed it within a week — Defender for Cloud attack-path
// notifications and Qualys WAS scan summaries — and both arrive at a published
// address that anyone can write to. A forged notification carrying a link
// somewhere else is a cheap, plausible phish aimed precisely at whoever reads
// the resulting report.
//
// Verification logic that exists twice drifts. The copy that gets the next fix
// is whichever one the person was looking at.
//
// # UNWRAPPING WITHOUT VERIFYING WOULD BE WORSE THAN DOING NOTHING
//
// The wrapped form is 400+ characters of opaque tokens, which defeats the one
// thing a human reviewer is good at. Unwrapping makes it readable. Unwrapping
// and NOT checking the destination would launder an arbitrary URL into
// something that looks checked — so every path that cannot produce a verified
// host returns an error, and callers report that rather than hiding it.
package safelink

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrHostNotAllowed means the link did not resolve to an expected host.
//
// Worth distinguishing from a parse failure by the caller: a notification
// whose link points somewhere unexpected is a finding, not a malformed email.
var ErrHostNotAllowed = errors.New("link does not resolve to an allowed host")

// Unwrap peels known wrappers off raw and returns the URL, provided it is
// https and its host exactly matches one of allowed.
//
// Exact host match, not a suffix check. A suffix check accepts
// portal.azure.com.evil.example; a "contains" check accepts
// https://portal.azure.com@evil.example, which goes to evil.example.
func Unwrap(raw string, allowed ...string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("no link")
	}
	if len(allowed) == 0 {
		return "", errors.New("safelink.Unwrap called with no allowed hosts")
	}

	if inner, ok := unwrapProofpoint(s); ok {
		s = inner
	}
	if inner, ok := unwrapRedirector(s); ok {
		s = inner
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("unwrapped link does not parse: %w", err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%w: scheme is %q", ErrHostNotAllowed, u.Scheme)
	}
	host := u.Hostname() // strips :port, and the brackets on an IPv6 literal
	for _, a := range allowed {
		if strings.EqualFold(host, a) {
			return u.String(), nil
		}
	}
	return "", fmt.Errorf("%w: %s", ErrHostNotAllowed, host)
}

// unwrapProofpoint extracts the original URL from a urldefense v3 wrapper:
//
//	https://urldefense.com/v3/__<INNER>__;<MAP>!!<TOK>!<TOK>$
//
// v3 rewrites '%' as '*'. It also has a base64 dictionary form for other
// replaced characters, which this does not decode — a half-decoded URL is
// still checked against the allowlist before it is used, whereas guessing at
// the dictionary would produce a plausible-looking wrong URL.
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

// redirectors are vendor click-through hosts that carry the real destination
// in a query parameter.
var redirectors = []struct {
	hostSuffix string
	param      string
}{
	{"safelink.emails.azure.net", "destination"},
	{"safelinks.protection.outlook.com", "url"},
}

func unwrapRedirector(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	for _, r := range redirectors {
		if !strings.HasSuffix(host, r.hostSuffix) {
			continue
		}
		if dest := u.Query().Get(r.param); dest != "" {
			return dest, true
		}
	}
	return "", false
}
