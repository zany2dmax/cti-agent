package qualys

import (
	"github.com/zany2dmax/cti-agent/internal/safelink"
)

// ReportHosts are the only hosts a scan-report link may resolve to.
//
// An allowlist of specific pods rather than a "*.qualys.com" rule. The
// subscription lives on one pod and its hostname is stable; accepting any
// subdomain would accept one an attacker can register on a shared platform,
// and the whole point of checking the link is to not do that.
//
// A new pod means a one-line change here and a parse problem reported in the
// meantime, which is the right failure: visible, and not a silently dropped
// link.
var ReportHosts = []string{
	"qualysguard.qg1.apps.qualys.com",
	"qualysguard.qg2.apps.qualys.com",
	"qualysguard.qg3.apps.qualys.com",
	"qualysguard.qg4.apps.qualys.com",
	"qualysapi.qualys.com",
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
