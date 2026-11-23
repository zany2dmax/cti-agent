package jira

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// RETITLING A TICKET WHEN ITS EXPOSURE IS REPORTED AGAIN.
//
// A ticket's title was written once, when it was filed, and every later
// "Exposure changed" comment left it as it was. CR-26125 was filed as
// "CVE-2026-114938 - java-17-amazon-corretto (Amazon Linux), ... - 106 hosts":
// the product came from the first scanner titles in QID order, which were
// Amazon Linux advisories with no hosts here. Three days later the comment
// said 241 hosts, Windows and Linux, and the title still said Amazon Linux
// and 106. IT read the title, has nothing in AWS, and set it aside.
//
// So when the fleet posts an exposure comment it also brings the title's
// product and host count up to date. Only those two parts: the rest (OVERDUE,
// CISA KEV, CVSS, QDS, the KEV name) is left as it is, because the follow-up
// pass that usually posts the comment does not have the digest's view of them.
//
// A PERSON'S TITLE IS LEFT ALONE. The title the fleet last wrote is kept in
// the ticket's exposure state; a ticket whose title is no longer that one was
// renamed in Jira, and is not renamed back. A ticket filed before the state
// kept a title is retitled only while its title still has the fleet's shape.

// summaryShape is the shape Summary writes:
//
//	[OVERDUE] CVE-... - <product> - <N> hosts<, flags>< - title>
//
// with the product optional. The product is the shortest text before the
// " - " that is followed by the host count.
var summaryShape = regexp.MustCompile(
	`^(\[OVERDUE\] )?(CVE-\d{4}-\d{4,}) - (?:(.+?) - )?((?:at least )?\d+ hosts?)(.*)$`)

// sourceRank orders where a product name came from: the catalog and NVD say
// what the CVE is about; a scanner title is the scanner's name for one check.
// A title-derived name must not replace one from a better source.
func sourceRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "cisa kev":
		return 3
	case "nvd":
		return 2
	case "":
		return 0
	}
	return 1 // the scanner's titles ("Qualys", or the provider's name)
}

// Retitle is the title a ticket should now carry, or "" with the reason it is
// left as it is. current is the ticket's title in Jira, prev its stored state
// (nil when there is none), f what the scanner reports now.
func Retitle(current string, prev *ExposureState, f Finding) (string, string) {
	if prev != nil && prev.Summary != "" && current != prev.Summary {
		return "", "the title was changed in Jira, so it is left as it is"
	}
	m := summaryShape.FindStringSubmatch(current)
	if m == nil {
		return "", "the title is not in the fleet's format, so it is left as it is"
	}
	overdue, cve, product, rest := m[1], m[2], m[3], m[5]

	if p := strings.TrimSpace(f.Product); p != "" {
		stored := ""
		if prev != nil {
			stored = prev.ProductSource
		}
		if sourceRank(f.ProductSource) >= sourceRank(stored) {
			product = p
		}
	}
	hosts := hostPhrase(f)

	var b strings.Builder
	b.WriteString(overdue + cve + " - ")
	if product != "" {
		b.WriteString(product + " - ")
	}
	b.WriteString(hosts + rest)
	next := truncate(strings.Join(strings.Fields(b.String()), " "), MaxSummary)
	if next == current {
		return "", "the title is already current"
	}
	return next, ""
}

// hostPhrase is the host count as Summary writes it.
func hostPhrase(f Finding) string {
	n := f.Count()
	s := strconv.Itoa(n) + " host"
	if n != 1 {
		s += "s"
	}
	if f.HostFloor() {
		s = "at least " + s
	}
	return s
}

// SetSummary replaces an issue's title. Needs the "Edit Issues" permission,
// which filing and commenting already rely on in a project the fleet works in.
func (c *Client) SetSummary(ctx context.Context, key, summary string) error {
	body := map[string]any{"fields": map[string]any{"summary": summary}}
	path := "/rest/api/2/issue/" + url.PathEscape(key)
	err := c.do(ctx, http.MethodPut, path, body, nil)
	auditJira("jira.summary.set", key, "", err)
	return err
}
