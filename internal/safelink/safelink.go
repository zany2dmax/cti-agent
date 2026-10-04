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
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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

// b64Alphabet is urldefense's URL-safe base64 alphabet, used both to decode
// the substitution dictionary and to read run lengths.
const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// runToken matches a substitution token: "*" alone, or "**" plus one
// base64 character giving a run length.
var runToken = regexp.MustCompile(`\*(\*.)?`)

// unwrapProofpoint extracts the original URL from a urldefense v3 wrapper:
//
//	https://urldefense.com/v3/__<INNER>__;<DICT>!!<TOK>!<TOK>$
//
// # "*" DOES NOT MEAN "%"
//
// The first version of this assumed it did, and was wrong in a way that only
// showed up on the second vendor. urldefense replaces special characters in
// the URL with "*" and carries the characters themselves, in order, as
// url-safe base64 in the segment after "__;".
//
// For the Azure notification that dictionary decodes to "%%%", so substituting
// "%" produced the right answer by coincidence. For the Qualys notification it
// decodes to "#", and substituting "%" produced ".../was/%/reports/" - an
// invalid percent-escape that url.Parse then rejected. The link was dropped
// and reported as unverifiable, which is the correct failure, but it was a
// failure of this decoder rather than anything wrong with the mail.
//
// "**X" is a run: X is a base64 digit giving how many consecutive characters
// to take from the dictionary.
//
// Anything inconsistent - a dictionary that does not decode, a run that
// overruns it - returns false rather than a partial guess. A half-decoded URL
// that happens to parse is exactly the kind of plausible wrong answer the
// allowlist exists to catch, and it should never get that far.
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
	inner := rest[:end]

	seg := rest[end+3:]
	if i := strings.Index(seg, "!"); i >= 0 {
		seg = seg[:i]
	}
	if pad := len(seg) % 4; pad != 0 {
		seg += strings.Repeat("=", 4-pad)
	}
	dictBytes, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return "", false
	}
	dict := string(dictBytes)

	var b strings.Builder
	ptr := 0
	for _, loc := range splitTokens(inner) {
		if !strings.HasPrefix(loc, "*") {
			b.WriteString(loc)
			continue
		}
		n := 1
		if len(loc) == 3 { // "**X"
			n = strings.IndexByte(b64Alphabet, loc[2])
			if n < 0 {
				return "", false
			}
		}
		if ptr+n > len(dict) {
			return "", false
		}
		b.WriteString(dict[ptr : ptr+n])
		ptr += n
	}
	return b.String(), true
}

// splitTokens breaks the wrapped URL into substitution tokens and the literal
// text between them, preserving order.
func splitTokens(s string) []string {
	var out []string
	last := 0
	for _, m := range runToken.FindAllStringIndex(s, -1) {
		if m[0] > last {
			out = append(out, s[last:m[0]])
		}
		out = append(out, s[m[0]:m[1]])
		last = m[1]
	}
	if last < len(s) {
		out = append(out, s[last:])
	}
	return out
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
