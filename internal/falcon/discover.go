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
//   - NewApps: "what appeared today that we never had before?" - the
//     systems nobody told us about. Daily.
//
// Names are hostile either way. A name typed or taken from an advisory goes
// through Literal: a narrow character set with no quote, no backslash and
// none of FQL's operators (+ , * : ! ~ [ ] < > = |), so even a parser that
// looked inside the quotes would find no clause to add. A name Discover
// returned (anyone who can install software chooses it) goes through
// apiLiteral, which refuses only what could leave the single-quoted value or
// act as a wildcard: the quote, the backslash, * and control characters. If
// FQL rejects such a name anyway, that one app is "not checked - lookup
// rejected", never the whole run. Everything printed is sanitised.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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

// apiLiteral checks a name Discover itself returned, for an exact or
// pattern lookup inside an FQL quoted string. Such names are chosen by
// whoever packaged the software, so they are hostile too, but they carry
// ®, +, :, <>, @ and non-Latin scripts that real products use. Only what
// could leave the quoted string or act as a wildcard is refused: the quote,
// the backslash, *, and control characters. The stored spelling is kept
// exactly, double spaces and all, or an exact match finds nothing.
func apiLiteral(s string) (string, error) {
	if s == "" || s != strings.TrimSpace(s) {
		return "", errors.New("empty, or leading or trailing space")
	}
	if len(s) > 300 {
		return "", errors.New("longer than 300 bytes")
	}
	if !utf8.ValidString(s) {
		return "", errors.New("not valid UTF-8")
	}
	for _, r := range s {
		if r == '\'' || r == '\\' || r == '*' || unicode.IsControl(r) {
			return "", fmt.Errorf("has %q", r)
		}
	}
	return s, nil
}

// versionToken is a word that is only a version number: 8.0.34, v2.1,
// 14.51.36247, (1018.5.5). A bare number like 2015 or v14 is left alone:
// it is as likely to be part of the product's name.
var versionToken = regexp.MustCompile(`^\(?v?\d+(\.\d+)+` + versionSuffix + `\)?$`)

// versionSuffix is what may follow the numbers: a build or architecture tag
// from a short known list, never free text - "1.0-server" and "2.0-client"
// are different products, not two versions of one.
const versionSuffix = `([-_.]?(x64|x86|amd64|arm64|win64|win32|beta\d*|alpha\d*|rc\d*|preview\d*|\d+))*`

// versionPattern turns a name with version numbers in it into an FQL wildcard
// pattern for the same product at any version: "Microsoft .NET 8.0.34 -
// Windows Server Hosting" becomes "Microsoft .NET * - Windows Server
// Hosting". It returns "" when the name has no version in it, or when too
// little of the name would be left to mean anything.
func versionPattern(name string) string {
	words := strings.Split(name, " ")
	changed := false
	for i, w := range words {
		if versionToken.MatchString(strings.ToLower(w)) {
			words[i] = "*"
			changed = true
		}
	}
	if !changed {
		return ""
	}
	p := strings.Join(words, " ")
	if lit := strings.NewReplacer("*", "", " ", "", "-", "").Replace(p); utf8.RuneCountInString(lit) < 4 {
		return ""
	}
	return p
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
	Name         string `json:"name"`
	Vendor       string `json:"vendor"`
	Version      string `json:"version"`
	FirstSeen    string `json:"first_seen_timestamp"`
	SoftwareType string `json:"software_type"`
	IsSuspicious bool   `json:"is_suspicious"`
	Host         struct {
		ID          string `json:"id"`
		Platform    string `json:"platform_name"`
		HostType    string `json:"product_type_desc"` // Workstation, Server, Domain Controller
		Exposure    string `json:"internet_exposure"`
		Criticality string `json:"criticality"`
	} `json:"host"`
}

// AppSummary is one application, aggregated over hosts. Counts only.
type AppSummary struct {
	Vendor       string         `json:"vendor"`
	Name         string         `json:"name"`
	SoftwareType string         `json:"software_type,omitempty"` // as Discover labels it
	Hosts        int            `json:"hosts"`                   // distinct hosts
	Versions     map[string]int `json:"versions"`                // version -> distinct hosts with it
	Platforms    map[string]int `json:"platforms"`               // Windows, Mac, Linux -> distinct hosts
	HostTypes    map[string]int `json:"host_types"`              // Workstation, Server, ... -> distinct hosts
	Exposure     map[string]int `json:"internet_exposure"`       // Falcon's internet exposure -> distinct hosts
	Criticality  map[string]int `json:"criticality"`             // Falcon's host criticality -> distinct hosts
	// Suspicious counts distinct hosts where Falcon flagged this application;
	// SuspiciousNoHost the flagged records that named no host.
	Suspicious       int `json:"suspicious_hosts,omitempty"`
	SuspiciousNoHost int `json:"suspicious_no_host,omitempty"`
	// NoHost counts records that named no host. They are not added to
	// Hosts, since they cannot be told apart.
	NoHost int `json:"no_host,omitempty"`
}

// AppSearch is FindApps' answer.
type AppSearch struct {
	Filter    string       `json:"filter"`
	Total     int          `json:"total"` // records the API matched; -1 when it did not say
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
// The total is -1 when the API sent none.
func (c *Client) readApps(ctx context.Context, filter string, max int) ([]app, int, bool, error) {
	var rows []app
	total, known, after := 0, false, ""
	for {
		// facet=host_info adds the host's details (platform among them) to
		// each record; without it the host is an ID only. Host names arrive
		// with it too, and are never kept or printed.
		q := url.Values{"filter": {filter}, "limit": {strconv.Itoa(pageSize)}, "facet": {"host_info"}}
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
			total, known = t, true
		}
		next := ""
		if p := resp.Envelope.Meta.Pagination; p != nil {
			next = p.After
		}
		if len(rows) >= max {
			if !known { // only the cursor can say
				return rows[:max], -1, next != "", nil
			}
			return rows[:max], max0(total, len(rows)), total > max, nil
		}
		if next == "" || len(page) == 0 || next == after {
			if !known {
				return rows, -1, false, nil
			}
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

// summarise groups records by vendor, name and software type and counts
// distinct hosts - overall, and per version, platform, host type, exposure
// and criticality, so a host with two versions of an app counts toward both.
func summarise(rows []app) []AppSummary {
	const (
		aVersion = iota
		aPlatform
		aHostType
		aExposure
		aCriticality
		nAttrs
	)
	type acc struct {
		s          AppSummary
		hosts      map[string]bool
		suspicious map[string]bool
		attrs      [nAttrs]map[string]map[string]bool
	}
	by := map[string]*acc{}
	var order []string
	for _, r := range rows {
		// The type splits groups only when there is no vendor: there it
		// decides which lookup is safe. A vendored app is one app whatever
		// Discover labels each record.
		k := strings.ToLower(r.Vendor) + "\x00" + strings.ToLower(r.Name)
		if strings.TrimSpace(r.Vendor) == "" {
			k += "\x00" + strings.ToLower(r.SoftwareType)
		}
		a := by[k]
		if a == nil {
			a = &acc{s: AppSummary{Vendor: r.Vendor, Name: r.Name, SoftwareType: r.SoftwareType},
				hosts: map[string]bool{}, suspicious: map[string]bool{}}
			for i := range a.attrs {
				a.attrs[i] = map[string]map[string]bool{}
			}
			by[k] = a
			order = append(order, k)
		}
		if r.Host.ID == "" {
			a.s.NoHost++
			if r.IsSuspicious {
				a.s.SuspiciousNoHost++
			}
			continue
		}
		h := r.Host.ID
		a.hosts[h] = true
		if r.IsSuspicious {
			a.suspicious[h] = true
		}
		for i, v := range [nAttrs]string{r.Version, r.Host.Platform, r.Host.HostType, r.Host.Exposure, r.Host.Criticality} {
			k := orUnknown(v)
			if a.attrs[i][k] == nil {
				a.attrs[i][k] = map[string]bool{}
			}
			a.attrs[i][k][h] = true
		}
	}
	out := make([]AppSummary, 0, len(by))
	for _, k := range order {
		a := by[k]
		a.s.Hosts = len(a.hosts)
		a.s.Suspicious = len(a.suspicious)
		a.s.Versions = counts(a.attrs[aVersion])
		a.s.Platforms = counts(a.attrs[aPlatform])
		a.s.HostTypes = counts(a.attrs[aHostType])
		a.s.Exposure = counts(a.attrs[aExposure])
		a.s.Criticality = counts(a.attrs[aCriticality])
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
	NewToEstate = "new"         // no record of it, at any version, before the window
	SeenBefore  = "seen-before" // already in the estate: an update or a new host
	NotChecked  = "not-checked" // see Reason
)

// Why an application was not checked.
const (
	ReasonNoVendor = "no-vendor"       // no vendor and no software type: a name-only lookup would match look-alikes
	ReasonOverCap  = "over-cap"        // more applications than MaxChecks
	ReasonRefused  = "name-refused"    // the name or vendor holds a character a lookup cannot carry
	ReasonRejected = "lookup-rejected" // the API refused this one lookup (4xx), so it could not be checked
)

// rejected: the API itself refused one lookup - a filter it could not parse,
// say. That marks one app not checked. Anything else (no connection, a
// refused token, rate limits that did not clear, a 5xx) fails the run, since
// it says nothing about the app.
func rejected(err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) || !he.FromAPI {
		return false
	}
	switch he.Status {
	case 400, 404, 422:
		return true
	}
	return false
}

// NewApp is one application first seen inside the window.
type NewApp struct {
	AppSummary
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"` // for not-checked
}

// NewAppsReport is NewApps' answer.
type NewAppsReport struct {
	Since      time.Time      `json:"since"`
	Total      int            `json:"total"` // records first seen in the window; -1 when the API did not say
	Read       int            `json:"read"`
	Truncated  bool           `json:"truncated"`
	New        []NewApp       `json:"new"`
	NotChecked []NewApp       `json:"not_checked"`
	Reasons    map[string]int `json:"not_checked_reasons"`
	SeenBefore int            `json:"seen_before"` // applications, not records
	// SeenAsOtherVersion is the part of SeenBefore that matched only once the
	// version number was taken out of the name.
	SeenAsOtherVersion int `json:"seen_as_other_version"`
	// ByType counts the browser extensions (no vendor) that were looked up
	// by name among extensions and answered.
	ByType int `json:"checked_by_type"`
	// SuspiciousKnown lists apps already in the estate that Falcon flags as
	// suspicious: not new, but never to be hidden in a count.
	SuspiciousKnown []NewApp `json:"suspicious_known,omitempty"`
}

// NewAppsOpts caps the work.
type NewAppsOpts struct {
	MaxRows   int // records first seen in the window to read; 0 = 10000
	MaxChecks int // applications to look up; 0 = 500
	Workers   int // lookups at a time; 0 = 4
}

// NewApps lists applications first seen since `since` that the estate had
// never had before. It reads the window's records, groups them, then asks for
// each group whether any record from the same vendor predates the window:
// first by the exact name, then, if the name carries a version number, by
// the same name at any version. Largest groups first, up to MaxChecks,
// Workers at a time.
func (c *Client) NewApps(ctx context.Context, since time.Time, o NewAppsOpts) (*NewAppsReport, error) {
	if o.MaxRows <= 0 {
		o.MaxRows = 10000
	}
	if o.MaxChecks <= 0 {
		o.MaxChecks = 500
	}
	if o.Workers <= 0 {
		o.Workers = 4
	}
	ts := since.UTC().Format(time.RFC3339)
	rows, total, truncated, err := c.readApps(ctx, "first_seen_timestamp:>'"+ts+"'", o.MaxRows)
	if err != nil {
		return nil, err
	}
	rep := &NewAppsReport{Since: since.UTC(), Total: total, Read: len(rows), Truncated: truncated, Reasons: map[string]int{}}

	type job struct {
		i     int
		s     AppSummary
		n, p  string
		scope string // the clause that keeps the lookup to the same kind of thing
	}
	apps := summarise(rows)
	results := make([]NewApp, len(apps))
	otherVersion := make([]bool, len(apps))
	var jobs []job
	for i, s := range apps {
		// The lookup is kept to the same vendor. Browser extensions carry no
		// vendor, so for one of those it is kept to extensions instead, and a
		// desktop app of the same name cannot make it look known. Anything
		// else without a vendor is not checked: a name-only lookup would
		// match look-alikes.
		reason, scope := "", ""
		n, nerr := apiLiteral(s.Name)
		switch {
		case strings.TrimSpace(s.Vendor) != "":
			v, verr := apiLiteral(s.Vendor)
			if verr != nil {
				nerr = verr
			}
			scope = clause("vendor", v, true)
		case isExtensionType(s.SoftwareType):
			t, terr := apiLiteral(s.SoftwareType)
			if terr != nil {
				nerr = terr
			}
			scope = clause("software_type", t, true)
		}
		switch {
		case scope == "" && nerr == nil:
			reason = ReasonNoVendor
		case nerr != nil:
			reason = ReasonRefused
		case len(jobs) >= o.MaxChecks:
			reason = ReasonOverCap
		}
		if reason != "" {
			results[i] = NewApp{AppSummary: s, Status: NotChecked, Reason: reason}
			continue
		}
		jobs = append(jobs, job{i: i, s: s, n: n, p: versionPattern(n), scope: scope})
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	work := make(chan job)
	for w := 0; w < o.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				seen, other, err := c.seenBefore(ctx, j.n, j.scope, j.p, ts)
				if rejected(err) {
					results[j.i] = NewApp{AppSummary: j.s, Status: NotChecked, Reason: ReasonRejected}
					continue
				}
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
						cancel()
					}
					mu.Unlock()
					continue
				}
				st := NewToEstate
				if seen {
					st = SeenBefore
				}
				results[j.i] = NewApp{AppSummary: j.s, Status: st}
				otherVersion[j.i] = other
			}
		}()
	}
feed:
	for _, j := range jobs {
		select {
		case work <- j:
		case <-ctx.Done():
			break feed
		}
	}
	close(work)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	for i, r := range results {
		// Looked up by type, and the lookup answered.
		if strings.TrimSpace(r.Vendor) == "" && (r.Status == NewToEstate || r.Status == SeenBefore) {
			rep.ByType++
		}
		switch r.Status {
		case NewToEstate:
			rep.New = append(rep.New, r)
		case SeenBefore:
			rep.SeenBefore++
			if otherVersion[i] {
				rep.SeenAsOtherVersion++
			}
			if r.Suspicious > 0 || r.SuspiciousNoHost > 0 {
				rep.SuspiciousKnown = append(rep.SuspiciousKnown, r)
			}
		case NotChecked:
			rep.NotChecked = append(rep.NotChecked, r)
			rep.Reasons[r.Reason]++
		}
	}
	return rep, nil
}

// seenBefore asks whether the same vendor had this application before the
// window: by exact name, then by pattern (any version), if there is one.
func (c *Client) seenBefore(ctx context.Context, name, scope, pattern, ts string) (seen, otherVersion bool, err error) {
	ask := func(nameClause string) (bool, error) {
		filter := nameClause + "+" + scope + "+first_seen_timestamp:<='" + ts + "'"
		resp, err := c.Get(ctx, appsRoute, url.Values{"filter": {filter}, "limit": {"1"}})
		if err != nil {
			return false, err
		}
		t, ok := resp.Total()
		return (ok && t > 0) || hasResources(resp), nil
	}
	if seen, err = ask(clause("name", name, true)); err != nil || seen || pattern == "" {
		return seen, false, err
	}
	// The wildcard matches any text, so "Zoom *" would also find "Zoom
	// Rooms": a different product, which would make a new one look known.
	// So the earlier records' names are read back and only one that differs
	// from this name in its version numbers alone counts.
	// Discover keeps a record per host, so many copies of one look-alike can
	// fill a page; up to 300 records are read. Past that the app is called
	// new - the safe way to be wrong.
	filter := "name:*'" + pattern + "'+" + scope + "+first_seen_timestamp:<='" + ts + "'"
	earlier, _, _, err := c.readApps(ctx, filter, 300)
	if err != nil {
		return false, false, err
	}
	re := patternRegexp(pattern)
	for _, e := range earlier {
		if re.MatchString(e.Name) {
			return true, true, nil
		}
	}
	return false, false, nil
}

// patternRegexp is versionPattern's pattern as a strict regexp: every * must
// be a version number, everything else must match exactly.
func patternRegexp(pattern string) *regexp.Regexp {
	parts := strings.Split(pattern, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.MustCompile(`(?i)^` + strings.Join(parts, `\(?v?\d+(\.\d+)+`+versionSuffix+`\)?`) + `$`)
}

// isExtensionType: a software type that names a browser extension. Only
// those get a lookup scoped by type. "application", Discover's default, is
// on most vendor-less records, and scoping by it would be a name-only lookup
// across every app in the estate - the look-alike risk "no vendor" exists
// to avoid.
func isExtensionType(t string) bool {
	return strings.Contains(strings.ToLower(t), "extension")
}

// hasResources: the answer carried at least one record, whatever its meta said.
func hasResources(r *Response) bool {
	var xs []json.RawMessage
	return len(r.Envelope.Resources) > 0 && json.Unmarshal(r.Envelope.Resources, &xs) == nil && len(xs) > 0
}

// FieldNames reads one Discover record and returns the names of its fields,
// nested ones as host.platform_name, each with its JSON type - never a value.
// It exists to find where a field lives (the platform, at first) without
// printing anything about a host. An object with more than 40 keys is not
// opened: its keys are likely data (one per host or group), not field names.
func (c *Client) FieldNames(ctx context.Context) ([]string, error) {
	resp, err := c.Get(ctx, appsRoute, url.Values{"limit": {"1"}, "facet": {"host_info"}})
	if err != nil {
		return nil, err
	}
	var recs []map[string]any
	if len(resp.Envelope.Resources) == 0 || json.Unmarshal(resp.Envelope.Resources, &recs) != nil {
		return nil, errors.New("falcon discover: resources are not records")
	}
	if len(recs) == 0 {
		return nil, errors.New("falcon discover: no record to read the fields of")
	}
	var out []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			if prefix != "" {
				if len(t) > 40 {
					out = append(out, fmt.Sprintf("%s (object of %d keys, not opened)", prefix, len(t)))
					return
				}
				out = append(out, prefix+" (object)")
			}
			for k, x := range t {
				name := cleanKey(k)
				if prefix != "" {
					name = prefix + "." + name
				}
				walk(name, x)
			}
		case []any:
			out = append(out, fmt.Sprintf("%s (array of %d)", prefix, len(t)))
			if len(t) > 0 {
				walk(prefix+"[]", t[0])
			}
		case string:
			out = append(out, prefix+" (string)")
		case float64:
			out = append(out, prefix+" (number)")
		case bool:
			out = append(out, prefix+" (bool)")
		case nil:
			out = append(out, prefix+" (null)")
		}
	}
	walk("", recs[0])
	sort.Strings(out)
	return out, nil
}

// cleanKey makes one JSON key safe to print: control and invisible
// formatting characters (bidi overrides among them) become "?", and a key
// longer than 64 runes is cut.
func cleanKey(k string) string {
	r := []rune(k)
	if len(r) > 64 {
		r = append(r[:64], '…')
	}
	for i, c := range r {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			r[i] = '?'
		}
	}
	return string(r)
}
