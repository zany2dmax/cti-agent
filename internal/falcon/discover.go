package falcon

// DISCOVER: WHAT WE RUN
//
// Falcon Discover holds one record per application per host - about 582,000
// for 2,128 hosts when this was written. Copying that every night would be
// hundreds of paged calls for data that is mostly unchanged, so triage asks
// two narrower questions instead:
//
//   - FindApps: "do we run X?" - asked when an advisory names a product. A few
//     calls, always current.
//   - NewApps: "what appeared this week that we never had before?" - the
//     systems nobody told us about. Weekly.
//
// Every product or vendor name that reaches a filter comes, eventually, from
// threat-intel text or a model's reading of it. It is hostile. Literal admits
// only a narrow character set. It refuses the quote and backslash, so a value
// cannot leave the single-quoted FQL string it is placed in, and it refuses
// FQL's operators (+ , * : ! ~ [ ] < > = |) outright, so even a parser that
// looked inside the quotes would find no clause to add and no wildcard to
// widen. Names that come back from Discover are hostile too (anyone who can
// install software names it), so everything printed is sanitised.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// appsRoute is the one Discover route this package reads.
const appsRoute = "/discover/combined/applications/v1"

// pageSize: the API documents both 100 and 1000 as the maximum; 100 is safe.
const pageSize = 100

// Literal checks a typed or extracted name for use inside an FQL quoted
// string, folding runs of whitespace. Letters, digits, space and . _ - ( ) / &
// only; 2 to 80 characters.
func Literal(s string) (string, error) {
	return literal(strings.Join(strings.Fields(s), " "))
}

// exactLiteral is Literal without the folding, for a name Discover itself
// returned: an exact match must use the stored spelling, double spaces and
// all, or it finds nothing.
func exactLiteral(s string) (string, error) {
	if s != strings.TrimSpace(s) {
		return "", fmt.Errorf("name %q has leading or trailing space", trimForError(s))
	}
	return literal(s)
}

func literal(t string) (string, error) {
	if n := len(t); n < 2 || n > 80 {
		return "", fmt.Errorf("name %q must be 2 to 80 characters", trimForError(t))
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(" ._-()/&", r):
		default:
			return "", fmt.Errorf("name %q has %q, which a lookup does not allow", trimForError(t), r)
		}
	}
	return t, nil
}

func trimForError(s string) string {
	r := []rune(s)
	if len(r) > 40 {
		r = append(r[:40], '…')
	}
	return strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return '?'
		}
		return c
	}, string(r))
}

// app is the part of a Discover record the fleet reads. Host identity is
// kept only to count distinct hosts; it is never printed or stored.
type app struct {
	Name      string `json:"name"`
	Vendor    string `json:"vendor"`
	Version   string `json:"version"`
	FirstSeen string `json:"first_seen_timestamp"`
	Host      struct {
		ID       string `json:"id"`
		Platform string `json:"platform_name"`
	} `json:"host"`
}

// AppSummary is one application, aggregated over hosts. Counts only.
type AppSummary struct {
	Vendor    string         `json:"vendor"`
	Name      string         `json:"name"`
	Hosts     int            `json:"hosts"`     // distinct hosts
	Versions  map[string]int `json:"versions"`  // version -> distinct hosts with it
	Platforms map[string]int `json:"platforms"` // Windows, Mac, Linux -> distinct hosts
	// NoHost counts records that named no host. They are not added to
	// Hosts, since they cannot be told apart.
	NoHost int `json:"no_host,omitempty"`
}

// AppSearch is FindApps' answer.
type AppSearch struct {
	Filter    string       `json:"filter"`
	Total     int          `json:"total"` // records the API matched
	Read      int          `json:"read"`  // records read before the cap
	Truncated bool         `json:"truncated"`
	Apps      []AppSummary `json:"apps"`
}

// FindOpts narrows FindApps.
type FindOpts struct {
	Vendor  string // optional, matched the same way as the name
	Exact   bool   // name (and vendor) must equal, not contain, the value
	MaxRows int    // stop reading after this many records; 0 = 2000
}

// FindApps answers "do we run this?" for one product name.
func (c *Client) FindApps(ctx context.Context, name string, o FindOpts) (*AppSearch, error) {
	n, err := Literal(name)
	if err != nil {
		return nil, err
	}
	filter := clause("name", n, o.Exact)
	if strings.TrimSpace(o.Vendor) != "" {
		v, err := Literal(o.Vendor)
		if err != nil {
			return nil, fmt.Errorf("vendor: %w", err)
		}
		filter += "+" + clause("vendor", v, o.Exact)
	}
	max := o.MaxRows
	if max <= 0 {
		max = 2000
	}
	rows, total, truncated, err := c.readApps(ctx, filter, max)
	if err != nil {
		return nil, err
	}
	return &AppSearch{Filter: filter, Total: total, Read: len(rows), Truncated: truncated, Apps: summarise(rows)}, nil
}

// clause builds one FQL comparison from a value that passed Literal.
func clause(field, v string, exact bool) string {
	if exact {
		return field + ":'" + v + "'"
	}
	return field + ":*'*" + v + "*'"
}

// readApps pages through one filter, up to max records.
func (c *Client) readApps(ctx context.Context, filter string, max int) ([]app, int, bool, error) {
	var rows []app
	total, after := 0, ""
	for {
		q := url.Values{"filter": {filter}, "limit": {strconv.Itoa(pageSize)}}
		if after != "" {
			q.Set("after", after)
		}
		resp, err := c.Get(ctx, appsRoute, q)
		if err != nil {
			return nil, 0, false, err
		}
		var page []app
		if len(resp.Envelope.Resources) > 0 {
			if err := json.Unmarshal(resp.Envelope.Resources, &page); err != nil {
				return nil, 0, false, errors.New("falcon discover: resources are not application records")
			}
		}
		rows = append(rows, page...)
		if t, ok := resp.Total(); ok {
			total = t
		}
		next := ""
		if p := resp.Envelope.Meta.Pagination; p != nil {
			next = p.After
		}
		if len(rows) >= max {
			more := total > max
			if total == 0 { // no total came back: only the cursor can say
				more = next != ""
			}
			return rows[:max], max0(total, len(rows)), more, nil
		}
		if next == "" || len(page) == 0 || next == after {
			return rows, max0(total, len(rows)), false, nil
		}
		after = next
	}
}

func max0(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// summarise groups records by vendor and name and counts distinct hosts -
// overall, per version and per platform, so a host with two versions of an
// app counts toward both.
func summarise(rows []app) []AppSummary {
	type acc struct {
		s         AppSummary
		hosts     map[string]bool
		versions  map[string]map[string]bool
		platforms map[string]map[string]bool
	}
	add := func(m map[string]map[string]bool, k, host string) {
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		m[k][host] = true
	}
	by := map[string]*acc{}
	var order []string
	for _, r := range rows {
		k := strings.ToLower(r.Vendor) + "\x00" + strings.ToLower(r.Name)
		a := by[k]
		if a == nil {
			a = &acc{s: AppSummary{Vendor: r.Vendor, Name: r.Name}, hosts: map[string]bool{},
				versions: map[string]map[string]bool{}, platforms: map[string]map[string]bool{}}
			by[k] = a
			order = append(order, k)
		}
		if r.Host.ID == "" {
			a.s.NoHost++
			continue
		}
		a.hosts[r.Host.ID] = true
		add(a.versions, orUnknown(r.Version), r.Host.ID)
		add(a.platforms, orUnknown(r.Host.Platform), r.Host.ID)
	}
	out := make([]AppSummary, 0, len(by))
	for _, k := range order {
		a := by[k]
		a.s.Hosts = len(a.hosts)
		a.s.Versions = counts(a.versions)
		a.s.Platforms = counts(a.platforms)
		out = append(out, a.s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Hosts != out[j].Hosts {
			return out[i].Hosts > out[j].Hosts
		}
		return strings.ToLower(out[i].Vendor+out[i].Name) < strings.ToLower(out[j].Vendor+out[j].Name)
	})
	return out
}

func counts(m map[string]map[string]bool) map[string]int {
	out := make(map[string]int, len(m))
	for k, hs := range m {
		out[k] = len(hs)
	}
	return out
}

func orUnknown(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}

// New-app outcomes.
const (
	NewToEstate = "new"         // no record of it before the window
	SeenBefore  = "seen-before" // already somewhere in the estate: an update or a new host
	NotChecked  = "not-checked" // no vendor, a name that cannot go in a filter, or the cap was hit
)

// NewApp is one application first seen inside the window.
type NewApp struct {
	AppSummary
	Status string `json:"status"`
}

// NewAppsReport is NewApps' answer.
type NewAppsReport struct {
	Since      time.Time `json:"since"`
	Total      int       `json:"total"` // records first seen in the window
	Read       int       `json:"read"`
	Truncated  bool      `json:"truncated"`
	New        []NewApp  `json:"new"`
	NotChecked []NewApp  `json:"not_checked"`
	SeenBefore int       `json:"seen_before"` // applications, not records
}

// NewAppsOpts caps the work.
type NewAppsOpts struct {
	MaxRows   int // records first seen in the window to read; 0 = 10000
	MaxChecks int // "was it here before?" lookups; 0 = 200
}

// NewApps lists applications first seen since `since` that the estate had
// never had before. It reads the window's records, groups them, then asks for
// each group whether any record predates the window: one limit=1 call each,
// largest groups first, up to MaxChecks.
func (c *Client) NewApps(ctx context.Context, since time.Time, o NewAppsOpts) (*NewAppsReport, error) {
	if o.MaxRows <= 0 {
		o.MaxRows = 10000
	}
	if o.MaxChecks <= 0 {
		o.MaxChecks = 200
	}
	ts := since.UTC().Format(time.RFC3339)
	rows, total, truncated, err := c.readApps(ctx, "first_seen_timestamp:>'"+ts+"'", o.MaxRows)
	if err != nil {
		return nil, err
	}
	rep := &NewAppsReport{Since: since.UTC(), Total: total, Read: len(rows), Truncated: truncated}
	checks := 0
	for _, s := range summarise(rows) {
		// No vendor: a name-only lookup would match the same name from any
		// vendor and call a look-alike "seen before", the wrong way round for
		// this report. So it is listed as not checked.
		n, nerr := exactLiteral(s.Name)
		v, verr := exactLiteral(s.Vendor)
		if nerr != nil || verr != nil || checks >= o.MaxChecks {
			rep.NotChecked = append(rep.NotChecked, NewApp{s, NotChecked})
			continue
		}
		filter := clause("name", n, true) + "+" + clause("vendor", v, true) +
			"+first_seen_timestamp:<='" + ts + "'"
		checks++
		resp, err := c.Get(ctx, appsRoute, url.Values{"filter": {filter}, "limit": {"1"}})
		if err != nil {
			return nil, err
		}
		if t, ok := resp.Total(); (ok && t > 0) || hasResources(resp) {
			rep.SeenBefore++
			continue
		}
		rep.New = append(rep.New, NewApp{s, NewToEstate})
	}
	return rep, nil
}

// hasResources: the answer carried at least one record, whatever its meta said.
func hasResources(r *Response) bool {
	var xs []json.RawMessage
	return json.Unmarshal(r.Envelope.Resources, &xs) == nil && len(xs) > 0
}
