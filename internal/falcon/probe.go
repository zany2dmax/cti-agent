package falcon

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Probe is one read the fleet will depend on, run with the smallest possible
// result so `--check` costs nothing and returns no data worth keeping.
type Probe struct {
	Scope string // the scope's name as the Falcon console shows it
	What  string // what the fleet uses it for
	Path  string
	Query url.Values
	// NotFoundOK: a 404 from this route can mean "no results". It counts as
	// OK only when emptyAnswer says the service itself sent it.
	NotFoundOK bool
	// DeniedHint is added when the route answers 403.
	DeniedHint string
}

// Probes are the four scopes advisory triage needs, each exercised on the
// exact route the triage will call.
var Probes = []Probe{
	{
		Scope: "Hosts: READ", What: "host names, OS and last-seen for a host ID",
		Path: "/devices/queries/devices/v1", Query: url.Values{"limit": {"1"}},
		DeniedHint: "tick Hosts: Read on the API client",
	},
	{
		Scope: "Assets: READ", What: "installed applications per host (Falcon Discover)",
		Path: "/discover/queries/applications/v1", Query: url.Values{"limit": {"1"}},
		DeniedHint: "tick Assets: Read on the API client; if it is ticked, Falcon Discover / Exposure Management is not licensed",
	},
	{
		// example.com is reserved for documentation (RFC 2606): asking which
		// hosts saw it reveals nothing and should find nothing.
		Scope: "IOC Management: READ", What: "which hosts saw a domain, IP or hash",
		Path:       "/iocs/queries/indicators/devices/v1",
		Query:      url.Values{"type": {"domain"}, "value": {"example.com"}, "limit": {"1"}},
		NotFoundOK: true,
		DeniedHint: "tick IOC Management: Read on the API client (not the older IOCs scope)",
	},
	{
		Scope: "Alerts: READ", What: "detections and their ATT&CK techniques",
		Path: "/alerts/queries/alerts/v2", Query: url.Values{"limit": {"1"}},
		DeniedHint: "tick Alerts: Read on the API client",
	},
}

// Probe outcomes.
const (
	ProbeOK     = "ok"
	ProbeDenied = "denied"
	ProbeError  = "error"
)

// ProbeResult is one line of `--check`. It carries a count at most, never
// an ID or a record.
type ProbeResult struct {
	Scope  string `json:"scope"`
	What   string `json:"what"`
	Path   string `json:"path"`
	Result string `json:"result"`
	HTTP   int    `json:"http,omitempty"`
	Total  *int   `json:"total,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// RunProbe runs one probe.
func (c *Client) RunProbe(ctx context.Context, p Probe) ProbeResult {
	r := ProbeResult{Scope: p.Scope, What: p.What, Path: p.Path}
	resp, err := c.Get(ctx, p.Path, p.Query)
	var he *HTTPError
	switch {
	case err == nil:
		r.Result, r.HTTP = ProbeOK, resp.Status
		if n, ok := resp.Total(); ok {
			r.Total = &n
		}
	case errors.As(err, &he) && he.Path == p.Path && he.Status == http.StatusNotFound && p.NotFoundOK && emptyAnswer(he):
		r.Result, r.HTTP = ProbeOK, he.Status
		r.Detail = "no hosts for the test value, as expected"
		if he.Message != "" {
			r.Detail += " (API: " + he.Message + ")"
		}
	case errors.As(err, &he) && he.Path == p.Path && he.Status == http.StatusForbidden:
		r.Result, r.HTTP, r.Detail = ProbeDenied, he.Status, he.Message
		if p.DeniedHint != "" {
			if r.Detail != "" {
				r.Detail += " - "
			}
			r.Detail += p.DeniedHint
		}
	case errors.As(err, &he):
		r.Result, r.HTTP, r.Detail = ProbeError, he.Status, he.Error()
	default:
		r.Result, r.Detail = ProbeError, err.Error()
	}
	return r
}

// emptyAnswer tells the service's "nothing matched" 404 from a 404 for a
// route that does not exist: the first comes in the API's envelope with a
// trace_id, and does not talk about the route. Anything else - a gateway's
// page, a retired route - is an ERROR, so --check cannot pass for a lookup
// that triage could never make.
func emptyAnswer(he *HTTPError) bool {
	if !he.FromAPI {
		return false
	}
	m := strings.ToLower(he.Message)
	return !strings.Contains(m, "route") && !strings.Contains(m, "endpoint") && !strings.Contains(m, "path")
}
