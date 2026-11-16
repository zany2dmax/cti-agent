package mailer

import (
	"html"
	"os"
	"strings"
)

// WithAttribution makes sure the credit line (FLEET_ATTRIBUTION) is on the
// email, the way mailer.py's with_attribution does.
//
// Every lane builds its own footer with emailkit.Credit, and each is meant to
// carry the credit, but cti-mailer is the one place every Go lane's email
// passes through, so it is the net under all of them: if the configured text
// is not in the body, raw or escaped, a plain credit line is added before the
// closing body tag. Unset means nothing is added. It reports whether a line
// was added, so the caller can say so.
//
// Until 16 Nov 2026 only mailer.py had this net; compare-mailers found the gap
// once it ran with an attribution set.
func WithAttribution(body string) (string, bool) {
	text := strings.TrimSpace(os.Getenv("FLEET_ATTRIBUTION"))
	if text == "" {
		return body, false
	}
	esc := html.EscapeString(text)
	if strings.Contains(body, text) || strings.Contains(body, esc) ||
		strings.Contains(body, strings.ReplaceAll(esc, "&#39;", "&#x27;")) {
		return body, false
	}
	line := `<div style="font:400 11px/1.6 Arial,sans-serif;color:#6b7280;` +
		`padding:8px 20px 14px 20px">` + esc + "</div>"
	if i := strings.LastIndex(strings.ToLower(body), "</body>"); i >= 0 {
		return body[:i] + line + body[i:], true
	}
	return body + line, true
}
