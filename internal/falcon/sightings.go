package falcon

// SIGHTINGS AND DETECTIONS
//
// Two counts advisory triage asks for, both facts rather than judgements:
//
//   - SeenOn: how many of our hosts saw this domain, IP or hash. A hit is the
//     strongest thing triage can report, and it is reported whatever a model
//     says (Phase 4).
//   - TechniqueAlerts: how many Falcon alerts named this ATT&CK technique
//     recently - "have we seen this behaviour at all".
//
// The indicator and technique come from advisory text. Each is checked for
// its exact shape here before it goes into a query, whatever the caller
// already did.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Indicator types the IOC route accepts.
const (
	IOCDomain = "domain"
	IOCIPv4   = "ipv4"
	IOCIPv6   = "ipv6"
	IOCMD5    = "md5"
	IOCSHA256 = "sha256"
)

var (
	domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	md5RE    = regexp.MustCompile(`^[a-f0-9]{32}$`)
	sha256RE = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// ClassifyIndicator returns the IOC type and canonical value, or an error
// when the value is none of them exactly.
func ClassifyIndicator(v string) (typ, value string, err error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch {
	case s == "":
		return "", "", errors.New("empty indicator")
	case sha256RE.MatchString(s):
		return IOCSHA256, s, nil
	case md5RE.MatchString(s):
		return IOCMD5, s, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil && !strings.Contains(s, ":") {
			return IOCIPv4, ip.String(), nil
		}
		return IOCIPv6, ip.String(), nil
	}
	if len(s) <= 253 && domainRE.MatchString(s) {
		return IOCDomain, s, nil
	}
	return "", "", fmt.Errorf("%q is not a domain, IP or MD5/SHA-256 hash", trimForError(v))
}

// SeenOn counts the hosts that saw one indicator. The service's own 404 is
// "none"; any other 404 is an error (the route moved), as in --check.
func (c *Client) SeenOn(ctx context.Context, indicator string) (int, error) {
	typ, val, err := ClassifyIndicator(indicator)
	if err != nil {
		return 0, err
	}
	const route = "/iocs/queries/indicators/devices/v1"
	resp, err := c.Get(ctx, route, url.Values{"type": {typ}, "value": {val}, "limit": {"100"}})
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound && emptyAnswer(he) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if n, ok := resp.Total(); ok {
		return n, nil
	}
	if hasResources(resp) {
		return countResources(resp), nil
	}
	return 0, nil
}

func countResources(r *Response) int {
	var xs []any
	if len(r.Envelope.Resources) == 0 || json.Unmarshal(r.Envelope.Resources, &xs) != nil {
		return 0
	}
	return len(xs)
}

var techniqueRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// TechniqueAlerts counts Falcon alerts since `since` whose technique is t.
// A sub-technique (T1566.001) is counted under its parent (T1566): that is
// how alerts carry it, and the caller is told which was asked.
func (c *Client) TechniqueAlerts(ctx context.Context, t string, since time.Time) (count int, asked string, err error) {
	t = strings.ToUpper(strings.TrimSpace(t))
	if !techniqueRE.MatchString(t) {
		return 0, "", fmt.Errorf("%q is not an ATT&CK technique ID", trimForError(t))
	}
	asked = strings.SplitN(t, ".", 2)[0]
	filter := "technique_id:'" + asked + "'+created_timestamp:>'" + since.UTC().Format(time.RFC3339) + "'"
	resp, err := c.Get(ctx, "/alerts/queries/alerts/v2", url.Values{"filter": {filter}, "limit": {"1"}})
	if err != nil {
		return 0, asked, err
	}
	if n, ok := resp.Total(); ok {
		return n, asked, nil
	}
	return countResources(resp), asked, nil
}

// Sensors is how many hosts carry the Falcon sensor: the denominator for
// every "on N hosts", and the edge of what Falcon can see.
//
// Only hosts seen in the last 30 days count: the host list also holds
// machines retired long ago.
func (c *Client) Sensors(ctx context.Context) (int, error) {
	since := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	resp, err := c.Get(ctx, "/devices/queries/devices/v1", url.Values{"limit": {"1"}, "filter": {"last_seen:>'" + since + "'"}})
	if err != nil {
		return 0, err
	}
	if n, ok := resp.Total(); ok {
		return n, nil
	}
	return 0, errors.New("falcon hosts: no total in the answer")
}
