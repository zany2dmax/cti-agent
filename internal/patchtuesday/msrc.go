package patchtuesday

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// MICROSOFT'S OWN RELEASE DATA
//
// The Security Update Guide publishes every month as a CVRF document at
// api.msrc.microsoft.com: public, no key, no account. It is the release
// itself rather than somebody's write-up of it, so it is the primary source
// for the counts, the severities, the zero-days and the CVE list. The two
// articles are kept as a cross-check and for what only they carry (the Adobe
// paragraph, the Edge count, Qualys's published QQL).
//
// Added in 1.3 because the box runs in Azure and the Qualys blog answers 403
// to Azure addresses, whatever the request looks like. A synopsis built from
// one news article was the result.
//
// WHAT COUNTS AS "THIS RELEASE"
//
// The month's document is much larger than the release: September 2026 held
// 2,772 entries - Azure Linux packages, Chromium fixes shipped in Edge, and
// CVEs other CNAs assigned. The release the articles describe is the
// entries that
//
//   - Microsoft itself assigned (the CNA note says "Microsoft"),
//   - were first published on Patch Tuesday, and
//   - need the customer to do something (not "Customer Action Required: No",
//     which marks fixes Microsoft applied in its own cloud).
//
// For September that is 964; BleepingComputer counted 966. The cloud-only
// fixes are counted separately and named in the email, so the difference
// between our number and a publisher's has a visible cause.

// RoleMSRC is Microsoft's security update API.
const RoleMSRC = "msrc"

// MSRCName is how the source is labelled in the email.
const MSRCName = "Microsoft Security Update Guide (API)"

// msrcMaxBytes bounds the download. September 2026 was 20 MB.
const msrcMaxBytes = 96 << 20

// MSRCID is the document ID for a month: "2026-Sep".
func MSRCID(year int, month time.Month) string {
	return fmt.Sprintf("%04d-%s", year, month.String()[:3])
}

// MSRCAPIURL is the machine-readable release document.
func MSRCAPIURL(year int, month time.Month) string {
	return "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/" + MSRCID(year, month)
}

// MSRCPageURL is the human page for the same release, which is what the email
// links to: a 20 MB JSON document is not something to click.
func MSRCPageURL(year int, month time.Month) string {
	return "https://msrc.microsoft.com/update-guide/releaseNote/" + MSRCID(year, month)
}

// Release is what the lane keeps from Microsoft's document.
type Release struct {
	ID        string
	Total     int // customer-action CVEs Microsoft assigned on the day
	Critical  int
	Important int
	Moderate  int
	Low       int
	CloudOnly int // released the same day, fixed by Microsoft, no action

	CloudCVEs []string // the CloudOnly CVEs, so --explain can name them
	CVEs      []string
	Titles    map[string]string `json:",omitempty"`
	Exploited []string          // CVEs marked Exploited:Yes
	Disclosed []string          // CVEs marked Publicly Disclosed:Yes

	Impacts map[string]map[string]int // impact -> severity -> count
	Tags    map[string]int            // product family -> count
}

// cvrf is the subset of the document that is read. Decoding into this rather
// than a generic map keeps memory near the size of what is kept.
type cvrf struct {
	DocumentTracking cvrfTracking
	Vulnerability    []cvrfVuln
}

type cvrfTracking struct {
	InitialReleaseDate string
}

type cvrfVuln struct {
	Title           cvrfText
	CVE             string
	Notes           []cvrfNote
	Threats         []cvrfThreat
	RevisionHistory []cvrfRevision
}

type cvrfText struct {
	Value string
}

type cvrfNote struct {
	Title string
	Type  int
	Value string
}

type cvrfThreat struct {
	Description cvrfText
	Type        int
}

type cvrfRevision struct {
	Date string
}

// CVRF note and threat types used here.
const (
	noteTag            = 7 // product family, e.g. "Windows Kernel"
	noteCNA            = 8 // who assigned the CVE
	noteCustomerAction = 6 // "Customer Action Required"
	threatImpact       = 0
	threatExploit      = 1
	threatSeverity     = 3
)

// FetchMSRC downloads and summarises a month's release. Like Fetch, a failure
// is reported in the Source, never as an error: the synopsis degrades.
func FetchMSRC(ctx context.Context, client *http.Client, apiURL string,
	year int, month time.Month) (Source, *Release) {

	s := Source{Name: MSRCName, Role: RoleMSRC, URL: MSRCPageURL(year, month)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		s.Err = err.Error()
		return s, nil
	}
	req.Header.Set("User-Agent", userAgent)
	// Without this the API answers XML.
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		s.Err = err.Error()
		return s, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// The document appears on the day, at about 17:00 UTC.
		s.Err = "HTTP 404 - Microsoft has not published " + MSRCID(year, month) + " yet"
		return s, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		s.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return s, nil
	}
	rel, err := ParseMSRC(io.LimitReader(resp.Body, msrcMaxBytes), year, month)
	if err != nil {
		s.Err = err.Error()
		return s, nil
	}
	s.Fetched = true
	return s, rel
}

// ParseMSRC reads a CVRF JSON document and keeps the release.
func ParseMSRC(r io.Reader, year int, month time.Month) (*Release, error) {
	var doc cvrf
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("release document truncated (over %d MB?)", msrcMaxBytes>>20)
		}
		return nil, fmt.Errorf("release document is not CVRF JSON: %w", err)
	}

	day := PatchTuesday(year, month).Format("2006-01-02")
	if t := strings.TrimSpace(doc.DocumentTracking.InitialReleaseDate); len(t) >= 10 {
		day = t[:10]
	}

	rel := &Release{ID: MSRCID(year, month), Titles: map[string]string{},
		Impacts: map[string]map[string]int{}, Tags: map[string]int{}}
	seen := map[string]bool{}
	for _, v := range doc.Vulnerability {
		cve := strings.ToUpper(strings.TrimSpace(v.CVE))
		if cve == "" || seen[cve] {
			continue
		}
		var cna, tag, action string
		for _, n := range v.Notes {
			switch {
			case n.Type == noteCNA && cna == "":
				cna = strings.TrimSpace(n.Value)
			case n.Type == noteTag && tag == "":
				tag = strings.TrimSpace(n.Value)
			case n.Type == noteCustomerAction && strings.EqualFold(n.Title, "Customer Action Required"):
				action = strings.TrimSpace(n.Value)
			}
		}
		if !strings.EqualFold(cna, "Microsoft") || firstPublished(v) != day {
			continue
		}
		seen[cve] = true
		if strings.EqualFold(action, "No") {
			rel.CloudOnly++
			rel.CloudCVEs = append(rel.CloudCVEs, cve)
			continue
		}

		rel.Total++
		rel.CVEs = append(rel.CVEs, cve)
		rel.Titles[cve] = strings.TrimSpace(v.Title.Value)
		if tag != "" {
			rel.Tags[tag]++
		}
		sev, impact := "", ""
		for _, t := range v.Threats {
			val := strings.TrimSpace(t.Description.Value)
			switch t.Type {
			case threatSeverity:
				if severityRank(val) > severityRank(sev) {
					sev = val
				}
			case threatImpact:
				if impact == "" {
					impact = val
				}
			case threatExploit:
				if strings.Contains(val, "Exploited:Yes") && !contains(rel.Exploited, cve) {
					rel.Exploited = append(rel.Exploited, cve)
				}
				if strings.Contains(val, "Publicly Disclosed:Yes") && !contains(rel.Disclosed, cve) {
					rel.Disclosed = append(rel.Disclosed, cve)
				}
			}
		}
		switch sev {
		case "Critical":
			rel.Critical++
		case "Important":
			rel.Important++
		case "Moderate":
			rel.Moderate++
		case "Low":
			rel.Low++
		}
		if impact == "" {
			impact = "Other"
		}
		if rel.Impacts[impact] == nil {
			rel.Impacts[impact] = map[string]int{}
		}
		if sev == "" {
			sev = "Unrated"
		}
		rel.Impacts[impact][sev]++
	}
	if rel.Total == 0 && rel.CloudOnly == 0 {
		// A document with entries but none of them recognisable is a format
		// change, not a quiet month. Say so rather than report zero.
		return nil, fmt.Errorf("no Microsoft CVEs first published on %s in %d entries - "+
			"the document format may have changed", day, len(doc.Vulnerability))
	}
	sort.Strings(rel.CVEs)
	sort.Strings(rel.CloudCVEs)
	sort.Strings(rel.Exploited)
	sort.Strings(rel.Disclosed)
	return rel, nil
}

// firstPublished is the date of the earliest revision, "2006-01-02". The
// list is not in order in the document.
func firstPublished(v cvrfVuln) string {
	first := ""
	for _, r := range v.RevisionHistory {
		if d := strings.TrimSpace(r.Date); len(d) >= 10 && (first == "" || d[:10] < first) {
			first = d[:10]
		}
	}
	return first
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 4
	case "Important":
		return 3
	case "Moderate":
		return 2
	case "Low":
		return 1
	}
	return 0
}

// ZeroDaySentence states Microsoft's own exploited and disclosed flags.
func (r *Release) ZeroDaySentence() string {
	list := func(cves []string) string {
		const shown = 8
		parts := make([]string, 0, len(cves))
		for i, c := range cves {
			if i == shown {
				parts = append(parts, fmt.Sprintf("and %d more", len(cves)-shown))
				break
			}
			if t := r.Titles[c]; t != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", c, t))
			} else {
				parts = append(parts, c)
			}
		}
		return strings.Join(parts, "; ")
	}
	var b strings.Builder
	switch n := len(r.Exploited); n {
	case 0:
		b.WriteString("Microsoft marks none of this month's vulnerabilities as exploited in the wild.")
	case 1:
		fmt.Fprintf(&b, "Microsoft marks 1 vulnerability as exploited in the wild: %s.", list(r.Exploited))
	default:
		fmt.Fprintf(&b, "Microsoft marks %d vulnerabilities as exploited in the wild: %s.", n, list(r.Exploited))
	}
	switch n := len(r.Disclosed); n {
	case 0:
		b.WriteString(" None are marked publicly disclosed.")
	case 1:
		fmt.Fprintf(&b, " 1 is marked publicly disclosed: %s.", list(r.Disclosed))
	default:
		fmt.Fprintf(&b, " %d are marked publicly disclosed: %s.", n, list(r.Disclosed))
	}
	return b.String()
}

// Categories turns the impact counts into the by-category table.
func (r *Release) Categories() []Category {
	out := make([]Category, 0, len(r.Impacts))
	for impact, bySev := range r.Impacts {
		total := 0
		var parts []string
		for _, sev := range []string{"Critical", "Important", "Moderate", "Low", "Unrated"} {
			if n := bySev[sev]; n > 0 {
				total += n
				parts = append(parts, fmt.Sprintf("%s: %d", sev, n))
			}
		}
		out = append(out, Category{Name: impact + " Vulnerabilities", Quantity: total,
			Severities: strings.Join(parts, ", ")})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Quantity != out[j].Quantity {
			return out[i].Quantity > out[j].Quantity
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// TopProducts is the product families with the most fixes, most first.
func (r *Release) TopProducts(n int) []string {
	names := make([]string, 0, len(r.Tags))
	for t := range r.Tags {
		names = append(names, t)
	}
	sort.Slice(names, func(i, j int) bool {
		if r.Tags[names[i]] != r.Tags[names[j]] {
			return r.Tags[names[i]] > r.Tags[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > n {
		names = names[:n]
	}
	return names
}
