// Package attribution is the credit line at the foot of a fleet email: which
// agent fleet sent it, so a recipient who has never heard of it can tell.
//
// Configured, not hardcoded. This repository is deliberately generic - no
// organisation name, no addresses - so the wording comes from FLEET_ATTRIBUTION
// and the optional link from FLEET_REPO_URL. brief.py and cti-patchtuesday
// read the same two variables with the same rules; this is the Go copy for the
// lanes that did not have it (the AppSec emails).
//
// Unset means the caller's own plain fallback, so a fresh install advertises
// nobody. The default wording is only used when a URL was given: somebody who
// sets a repo link wants the credit, somebody who sets neither has asked for
// neither.
package attribution

import (
	"fmt"
	"html"
	"net/url"
	"os"
	"strings"
)

// Attribution is the line and its optional link.
type Attribution struct {
	Line string // FLEET_ATTRIBUTION, or a default built from the org name
	URL  string // FLEET_REPO_URL, http(s) only; empty renders as plain text
}

// Load reads the attribution from the environment. who names the caller in the
// warning about a refused URL. A zero Attribution renders nothing.
func Load(org, who string) Attribution {
	text := strings.TrimSpace(os.Getenv("FLEET_ATTRIBUTION"))
	raw := strings.TrimSpace(os.Getenv("FLEET_REPO_URL"))
	u := safeLinkURL(raw)
	if raw != "" && u == "" {
		// Not silently: a footer link that vanished because of a typo is the
		// kind of thing nobody notices for months.
		fmt.Fprintf(os.Stderr, "%s: ignoring FLEET_REPO_URL=%q - only http:// and "+
			"https:// are rendered as links\n", who, raw)
	}
	if text == "" && u == "" {
		return Attribution{}
	}
	if text == "" {
		text = fmt.Sprintf("Correlated and published by the %s Claude Code Agent Fleet", org)
	}
	return Attribution{Line: text, URL: u}
}

// safeLinkURL returns the URL only if it is safe in an href. These mails are
// rendered in Outlook: javascript:, data: and file: are at best broken and at
// worst a payload, and the value arrives from a config file.
func safeLinkURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.String()
	}
	return ""
}

// Empty reports that nothing is configured.
func (a Attribution) Empty() bool { return a.Line == "" }

// HTML renders the line escaped, linked in linkColour when there is a URL.
func (a Attribution) HTML(linkColour string) string {
	if a.Line == "" {
		return ""
	}
	if a.URL == "" {
		return html.EscapeString(a.Line)
	}
	return fmt.Sprintf(`<a href="%s" style="color:%s;text-decoration:underline">%s</a>`,
		html.EscapeString(a.URL), html.EscapeString(linkColour), html.EscapeString(a.Line))
}

// Text renders it for a plain-text reader, the URL on its own line.
func (a Attribution) Text() string {
	switch {
	case a.Line == "":
		return ""
	case a.URL == "":
		return a.Line
	}
	return a.Line + "\n" + a.URL
}
