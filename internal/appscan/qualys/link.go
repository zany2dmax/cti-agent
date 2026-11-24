package qualys

import (
	"fmt"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/safelink"
)

// ReportHosts are the only hosts a scan-report link may resolve to.
//
// An allowlist of specific pods rather than a "*.qualys.com" rule. The
// subscription lives on one pod and its hostname is stable; accepting any
// subdomain would accept one an attacker can register on a shared platform,
// and the whole point of checking the link is to not do that.
//
// Another platform is added from the operator's configuration at startup
// (UsePlatform); until it is, its links are reported as unverified, which is
// the right failure: visible, and not a silently dropped link.
var ReportHosts = []string{
	"qualysguard.qg1.apps.qualys.com",
	"qualysguard.qg2.apps.qualys.com",
	"qualysguard.qg3.apps.qualys.com",
	"qualysguard.qg4.apps.qualys.com",
	"qualysapi.qualys.com",
}

// PortalHosts are the Qualys UI hosts a link this lane BUILDS may point at -
// the only links the report renders as clickable.
//
// The qualysguard pods only. qualysapi.* is the API host: a link there opens a
// raw XML endpoint behind a basic-auth prompt, which is no use to a reader
// and trains them to type credentials into whatever prompt a link produces.
var PortalHosts = []string{
	"qualysguard.qg1.apps.qualys.com",
	"qualysguard.qg2.apps.qualys.com",
	"qualysguard.qg3.apps.qualys.com",
	"qualysguard.qg4.apps.qualys.com",
}

// UsePlatform adds the operator's own Qualys platform to ReportHosts and
// PortalHosts, so a subscription outside the four US pods (EU, CA, IN, UK and
// the rest) gets verified links instead of every one refused.
//
// Both come from the operator's configuration, never from mail: the API host
// in baseURL (qualysapi.<platform> gives qualysguard.<platform> for the UI),
// and extra, a comma- or space-separated list of further UI hosts for a
// platform that rule does not fit. The US pods stay accepted, so a box on one
// of them behaves as before. A host that is not a plain lower-case DNS name -
// a wildcard, a port, a path, a scheme - is refused, and nothing is added.
// Call it once at startup, before any link is checked.
func UsePlatform(baseURL, extra string) error {
	var add []string
	api := ""
	if u, err := neturl.Parse(strings.TrimSpace(baseURL)); err == nil && u.Scheme == "https" {
		if host := strings.ToLower(u.Hostname()); strings.HasPrefix(host, "qualysapi.") && hostRE.MatchString(host) {
			add = append(add, "qualysguard."+strings.TrimPrefix(host, "qualysapi."))
			api = host
		}
	}
	for _, h := range strings.FieldsFunc(extra, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		h = strings.ToLower(h)
		if !hostRE.MatchString(h) {
			return fmt.Errorf("portal host %q for Qualys is not a plain host name (no scheme, port, path or wildcard)", h)
		}
		add = append(add, h)
	}
	if api != "" {
		ReportHosts = appendNew(ReportHosts, api)
	}
	for _, h := range add {
		ReportHosts = appendNew(ReportHosts, h)
		PortalHosts = appendNew(PortalHosts, h)
	}
	return nil
}

// hostRE is a lower-case DNS name of at least three labels: no wildcard, no
// port, nothing a URL could smuggle in.
var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?){2,}$`)

func appendNew(list []string, h string) []string {
	for _, x := range list {
		if x == h {
			return list
		}
	}
	return append(list, h)
}

// UnwrapReportLink returns the Qualys report URL from a notification, or an
// error explaining why it could not be verified.
//
// Qualys links arrive wrapped by Proofpoint in production mail. The caller
// renders the result as plain text, never as an anchor: this message came from
// outside, and a security report that turns an externally supplied URL into a
// one-click link is a phishing delivery mechanism with the security team's
// name in the From field.
func UnwrapReportLink(raw string) (string, error) {
	return safelink.Unwrap(raw, ReportHosts...)
}

// PortalOrigin maps the API base URL to the matching Qualys UI origin.
//
// QUALYS_BASE_URL names the API host - qualysapi.qgN.apps.qualys.com - and
// the UI for the same pod is qualysguard.qgN.apps.qualys.com. Derived from
// the operator's own configuration, never from mail. Returns "" for a host
// that does not map onto one of PortalHosts, so an unexpected platform gets
// no link rather than a guessed one.
func PortalOrigin(baseURL string) string {
	u, err := neturl.Parse(strings.TrimSpace(baseURL))
	if err != nil || u.Scheme != "https" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if !strings.HasPrefix(host, "qualysapi.") {
		return ""
	}
	ui := "qualysguard." + strings.TrimPrefix(host, "qualysapi.")
	for _, h := range PortalHosts {
		if h == ui {
			return "https://" + ui
		}
	}
	return ""
}

// ScanReportURL is the UI page for one scan's results.
//
// The same page Qualys links from its own completion email -
// /was/#/reports/online-reports/email-report/scan/<scan id> - and the id in
// that link is the <id> the scan list returns, checked against a real
// notification. Built here from an integer and a constant path, so it is the
// one link the report renders as clickable. Empty origin or id, empty URL.
func ScanReportURL(origin string, scanID int) string {
	if origin == "" || scanID <= 0 {
		return ""
	}
	return origin + "/was/#/reports/online-reports/email-report/scan/" + strconv.Itoa(scanID)
}
