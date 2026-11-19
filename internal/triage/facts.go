package triage

// THE FACT SHEET
//
// What our own tools say about one advisory, gathered by code with no model
// involved: which of the products it names we run (Falcon Discover), whether
// any of our hosts saw its indicators (Falcon IOC sightings), and whether
// Falcon has alerted on its techniques lately. The judge (Phase 4) sees this
// sheet, never raw API data, and the verifier holds every claim it makes to
// a line here.
//
// Every value that reaches a lookup came from the advisory, or from the
// reader's reading of it, so it is hostile: each lookup re-checks its own
// input (falcon.Literal, falcon.ClassifyIndicator, the technique pattern) and
// skips, with a reason, anything that fails. Caps keep one advisory with 500
// indicators from using up the API.

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/falcon"
)

// FactsSchema names the sheet's shape.
const FactsSchema = "cti-facts/1"

// Caps per advisory.
const (
	maxProductLookups   = 5
	maxIndicatorLookups = 25
	maxTechniqueLookups = 10
	maxAppsPerProduct   = 8
	maxVersionsPerApp   = 8
	alertWindow         = 30 * 24 * time.Hour
)

// FactSource is what the sheet is gathered from: *falcon.Client in use, a
// fake in tests.
type FactSource interface {
	FindApps(ctx context.Context, name string, o falcon.FindOpts) (*falcon.AppSearch, error)
	SeenOn(ctx context.Context, indicator string) (int, error)
	TechniqueAlerts(ctx context.Context, t string, since time.Time) (int, string, error)
	Sensors(ctx context.Context) (int, error)
}

// AppFact is one installed application matching a product the advisory names.
type AppFact struct {
	Vendor        string         `json:"vendor"`
	Name          string         `json:"name"`
	Hosts         int            `json:"hosts"`
	VendorMatches bool           `json:"vendor_matches"` // the advisory's vendor is in Discover's vendor
	Versions      map[string]int `json:"top_versions"`   // the most common, capped
	OtherVersions int            `json:"other_versions,omitempty"`
	// BelowFixed is about how many hosts run a version older than the
	// advisory's fixed version: a sum over versions, capped at Hosts, since a
	// host with two versions counts in both. Nil when no fixed version.
	BelowFixed      *int           `json:"hosts_below_fixed,omitempty"`
	UncomparedHosts int            `json:"hosts_version_not_comparable,omitempty"`
	HostTypes       map[string]int `json:"host_types,omitempty"`
	Exposure        map[string]int `json:"internet_exposure,omitempty"`
	SuspiciousHosts int            `json:"suspicious_hosts,omitempty"`
}

// SubjectFacts is one subject and what the inventory says about it.
type SubjectFacts struct {
	Subject
	Apps      []AppFact `json:"installed"`
	Records   int       `json:"records_matched"` // -1 when the API did not say
	Truncated bool      `json:"counts_are_lower_bounds,omitempty"`
	Skipped   string    `json:"not_looked_up,omitempty"`
	Error     string    `json:"lookup_error,omitempty"`
}

// IndicatorFact is one indicator and how many hosts saw it.
type IndicatorFact struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Hosts   int    `json:"hosts_seen_on"`
	Skipped string `json:"not_looked_up,omitempty"`
	Error   string `json:"lookup_error,omitempty"`
}

// TechniqueFact is one technique and the recent Falcon alerts on it.
type TechniqueFact struct {
	ID      string `json:"id"`
	Asked   string `json:"asked_as"` // the parent, for a sub-technique
	Source  string `json:"source"`   // "advisory" or "reader" (inferred)
	Alerts  int    `json:"alerts_30d"`
	Error   string `json:"lookup_error,omitempty"`
	Skipped string `json:"not_looked_up,omitempty"`
}

// FactSheet is everything gathered for one advisory.
type FactSheet struct {
	Schema       string          `json:"schema"`
	Gathered     time.Time       `json:"gathered"`
	Sensors      int             `json:"falcon_sensors"` // 0 when unknown
	BlindSpots   string          `json:"blind_spots,omitempty"`
	Subjects     []SubjectFacts  `json:"subjects"`
	Indicators   []IndicatorFact `json:"indicators"`
	Techniques   []TechniqueFact `json:"techniques"`
	ReaderErrors []string        `json:"reader_claims_removed,omitempty"`
	Refused      string          `json:"reader_refused,omitempty"`
}

// Gather builds the sheet. subjects may be nil (no reader run): indicators
// and the advisory's own techniques are still looked up.
func Gather(ctx context.Context, src FactSource, body string, ex Extraction, subj *Subjects, removed []SubjectViolation, now time.Time, blindSpots string) FactSheet {
	fs := FactSheet{Schema: FactsSchema, Gathered: now.UTC(), BlindSpots: oneLine(blindSpots)}
	if n, err := src.Sensors(ctx); err == nil {
		fs.Sensors = n
	}
	for _, v := range removed {
		fs.ReaderErrors = append(fs.ReaderErrors, v.String())
	}
	if subj != nil && subj.Refusal != nil {
		fs.Refused = oneLine(subj.Refusal.Reason)
	}

	// Products.
	if subj != nil {
		for i, s := range subj.Items {
			sf := SubjectFacts{Subject: s, Records: -1}
			switch {
			case s.Product == "":
				sf.Skipped = "no product named"
			case i >= maxProductLookups:
				sf.Skipped = fmt.Sprintf("over the cap of %d product lookups", maxProductLookups)
			default:
				name, err := falcon.Literal(s.Product)
				if err != nil {
					sf.Skipped = "the product name has characters a lookup does not allow"
					break
				}
				res, err := src.FindApps(ctx, name, falcon.FindOpts{})
				if err != nil {
					sf.Error = err.Error()
					break
				}
				sf.Records, sf.Truncated = res.Total, res.Truncated
				for j, a := range res.Apps {
					if j == maxAppsPerProduct {
						break
					}
					sf.Apps = append(sf.Apps, appFact(a, s.Vendor, s.FixedIn))
				}
			}
			fs.Subjects = append(fs.Subjects, sf)
		}
	}

	// Indicators: what code extracted, plus hashes and defanged URL hosts.
	for i, ind := range indicators(body, ex) {
		f := IndicatorFact{Value: ind}
		typ, val, err := falcon.ClassifyIndicator(ind)
		switch {
		case err != nil:
			f.Skipped = "not a domain, IP or hash Falcon can look up"
		case i >= maxIndicatorLookups:
			f.Type, f.Skipped = typ, fmt.Sprintf("over the cap of %d indicator lookups", maxIndicatorLookups)
		default:
			f.Type, f.Value = typ, val
			if n, err := src.SeenOn(ctx, val); err != nil {
				f.Error = err.Error()
			} else {
				f.Hosts = n
			}
		}
		fs.Indicators = append(fs.Indicators, f)
	}

	// Techniques: the advisory's own first, then the reader's inferred ones.
	since := now.Add(-alertWindow)
	seen := map[string]bool{}
	add := func(t, source string) {
		t = strings.ToUpper(t)
		if seen[t] {
			return
		}
		seen[t] = true
		f := TechniqueFact{ID: t, Source: source}
		if len(fs.Techniques) >= maxTechniqueLookups {
			f.Skipped = fmt.Sprintf("over the cap of %d technique lookups", maxTechniqueLookups)
		} else if n, asked, err := src.TechniqueAlerts(ctx, t, since); err != nil {
			f.Asked, f.Error = asked, err.Error()
		} else {
			f.Asked, f.Alerts = asked, n
		}
		fs.Techniques = append(fs.Techniques, f)
	}
	for _, t := range ex.Techniques {
		add(t, "advisory")
	}
	if subj != nil {
		for _, s := range subj.Items {
			for _, t := range s.Techniques {
				src := "advisory"
				for _, inf := range s.Inferred {
					if inf == t {
						src = "reader"
					}
				}
				add(t, src)
			}
		}
	}
	return fs
}

func appFact(a falcon.AppSummary, vendor, fixed string) AppFact {
	f := AppFact{
		Vendor: a.Vendor, Name: a.Name, Hosts: a.Hosts,
		VendorMatches: vendor != "" && strings.Contains(strings.ToLower(a.Vendor), strings.ToLower(vendor)),
		HostTypes:     known(a.HostTypes), Exposure: known(a.Exposure),
		SuspiciousHosts: a.Suspicious,
	}
	type kv struct {
		v string
		n int
	}
	var vs []kv
	for v, n := range a.Versions {
		vs = append(vs, kv{v, n})
	}
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].n != vs[j].n {
			return vs[i].n > vs[j].n
		}
		return vs[i].v < vs[j].v
	})
	f.Versions = map[string]int{}
	for i, x := range vs {
		if i < maxVersionsPerApp {
			f.Versions[x.v] = x.n
		} else {
			f.OtherVersions++
		}
	}
	if fixed != "" {
		below := 0
		for _, x := range vs {
			switch c, ok := compareVersions(x.v, fixed); {
			case !ok:
				f.UncomparedHosts += x.n
			case c < 0:
				below += x.n
			}
		}
		if below > a.Hosts {
			below = a.Hosts
		}
		f.BelowFixed = &below
	}
	return f
}

// known drops the "unknown" bucket: it tells the judge nothing.
func known(m map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range m {
		if k != "unknown" {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// compareVersions compares dotted numeric versions ("157.0.8089.0" against
// "157.0.8100"). ok is false when either has a part that is not a number,
// within the parts compared.
func compareVersions(a, b string) (int, bool) {
	pa, pb := strings.Split(strings.TrimSpace(a), "."), strings.Split(strings.TrimSpace(b), ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	part := func(p []string, i int) (int, bool) {
		if i >= len(p) {
			return 0, true
		}
		x, err := strconv.Atoi(p[i])
		return x, err == nil && x >= 0
	}
	for i := 0; i < n; i++ {
		x, okx := part(pa, i)
		y, oky := part(pb, i)
		if !okx || !oky {
			return 0, false
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

var hashRE = regexp.MustCompile(`(?i)\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b`)

// indicators is the lookup list: code's extracted indicators refanged, the
// hashes in the body, and the hosts of defanged links (hxxp://), which are
// written that way because they are indicators. Ordinary links are not
// looked up: they are references, and every host has seen microsoft.com.
func indicators(body string, ex Extraction) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.ToLower(strings.TrimSpace(s))
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, i := range ex.Indicators {
		add(Refang(i))
	}
	for _, h := range hashRE.FindAllString(body, 200) {
		add(h)
	}
	for _, l := range ex.Links {
		if !strings.HasPrefix(strings.ToLower(l), "hxxp") {
			continue
		}
		if u, err := url.Parse(Refang(l)); err == nil && u.Hostname() != "" {
			add(u.Hostname())
		}
	}
	return out
}
