package appscan

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// REDACTION OF SCANNER EVIDENCE
//
// A scanner's evidence is the HTTP it sent and received while logged in as
// the scan account: its Cookie, Set-Cookie and Authorization headers are a
// working session. Anything this fleet writes from that evidence - a probe
// dump, ticket text - goes through Redact first. (The scanner's own report,
// attached as-is, is the exception, and the ticket says so.)

var (
	secretHeaderRE = regexp.MustCompile(
		`(?im)^([ \t]*(?:cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token)[ \t]*:).*$`)
	// Qualys sends request/response headers base64-encoded in verbose output.
	b64BlockRE = regexp.MustCompile(`(?s)<(headers|contents|request|response|body)(\s[^>]*)?>\s*(?:<!\[CDATA\[)?\s*([A-Za-z0-9+/=\r\n]{16,})\s*(?:\]\]>)?\s*</(?:headers|contents|request|response|body)>`)
)

// Redact removes credential-bearing header values from text. Base64 blocks
// inside the scanner's XML that decode to text are decoded first and
// redacted in the clear, marked as decoded - a redaction that only looked at
// the encoded form would pass every cookie through untouched.
func Redact(s string) string {
	s = b64BlockRE.ReplaceAllStringFunc(s, func(m string) string {
		sub := b64BlockRE.FindStringSubmatch(m)
		raw := strings.NewReplacer("\r", "", "\n", "").Replace(sub[3])
		dec, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || !utf8.Valid(dec) || !printable(dec) {
			// Fail closed: what cannot be read cannot be checked for a
			// cookie, so it does not go out.
			return "<" + sub[1] + ">[encoded block removed by cti-agent: not readable text, " +
				"so it could not be checked for credentials]</" + sub[1] + ">"
		}
		return "<" + sub[1] + " decoded=\"cti-appreport\"><![CDATA[" +
			strings.ReplaceAll(redactHeaders(string(dec)), "]]>", "]]&gt;") + "]]></" + sub[1] + ">"
	})
	return redactHeaders(s)
}

func redactHeaders(s string) string {
	return secretHeaderRE.ReplaceAllString(s, "$1 [redacted by cti-agent]")
}

func printable(b []byte) bool {
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
