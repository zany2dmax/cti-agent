// Package enrich takes the CVEs the agent found and adds what decides
// whether anyone should care:
//
//   - NVD 2.0    - CVSS base score, severity, description, CPE products
//   - FIRST EPSS - probability of exploitation in the next 30 days
//   - CISA KEV   - known exploited, the remediation due date, ransomware use
//
// Then it bands each finding Sev5-Sev1 by combining exploitability in the
// wild with presence in our environment. Presence comes only from the
// vulnerability lookup provider; this package never decides it.
//
// It replaced the Python enrich.py lane, and writes the same enriched file:
// the same keys, in the same order, with the same rationale text. The golden
// files in testdata were produced by that Python, and the tests hold this
// package to them.
package enrich

import (
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Options says what to enrich.
type Options struct {
	Report  string   // the agent's markdown report, or
	CVEs    []string // an explicit list (the scout lane)
	SkipNVD bool     // EPSS and KEV only

	Today time.Time
	Now   time.Time
	Logf  func(string, ...any)

	// FirstSeen reports when the findings database first stored each CVE,
	// read before the upsert or every CVE looks old. ok is false when there
	// is no database yet; err when it could not be read. Either way novelty
	// is undetermined, never guessed.
	FirstSeen func() (seen map[string]string, ok bool, err error)
}

// Run enriches the findings and returns the enriched file's content.
func Run(o Options, src Sources) (*Result, error) {
	var findings map[string]*Finding
	meta, subjects := Meta{}, []Subject{}
	if o.Report != "" {
		var err error
		if findings, err = ParseReport(o.Report); err != nil {
			return nil, err
		}
		meta = ParseMeta(o.Report)
		subjects = ParseSubjects(o.Report)
		o.Logf("parsed %d CVEs from %s", len(findings), filepath.Base(o.Report))
	} else {
		findings = map[string]*Finding{}
		for _, c := range o.CVEs {
			c = strings.TrimSpace(c)
			if !IsCVE(c) {
				continue
			}
			id := strings.ToUpper(c)
			findings[id] = &Finding{CVE: id, Status: "UNKNOWN", Provider: "scout"}
		}
		o.Logf("scoring %d CVEs from --cves", len(findings))
	}
	if len(findings) == 0 {
		o.Logf("no CVEs to enrich - writing an empty result so the digest still runs")
	}

	cves := make([]string, 0, len(findings))
	for c := range findings {
		cves = append(cves, c)
	}
	sort.Strings(cves)

	degraded := []string{}
	nvd := map[string]NVDEntry{}
	if !o.SkipNVD {
		nvd = src.NVD(cves)
		anyScore := false
		for _, v := range nvd {
			if v.CVSS != nil && numberValue(*v.CVSS) != 0 {
				anyScore = true
				break
			}
		}
		if !anyScore && len(cves) > 0 {
			degraded = append(degraded, "NVD")
		}
	}
	epss := map[string]EPSSEntry{}
	if len(cves) > 0 {
		epss = src.EPSS(cves)
		if len(epss) == 0 {
			degraded = append(degraded, "EPSS")
		}
	}
	kev := src.KEV()
	if len(kev) == 0 {
		degraded = append(degraded, "KEV catalog")
	}

	for _, cve := range cves {
		f := findings[cve]
		if e, ok := nvd[cve]; ok {
			f.NVD = &e
		}
		if e, ok := epss[cve]; ok {
			f.EPSS = &e
		}
		if e, ok := kev[cve]; ok {
			f.KEV, f.KEVFlag = &e, 1
		} else if f.NVD != nil && f.NVD.KEVNVD {
			// NVD's flag is the fallback when the catalog fetch failed.
			f.KEVFlag = 1
		}
		f.Priority, f.Rationale, f.KEVDaysLeft = prioritize(f.score(), o.Today)
		f.Product, f.ProductSource = f.product()
	}

	nov := markNovelty(findings, o)

	rows := make([]*Finding, 0, len(findings))
	for _, c := range cves {
		rows = append(rows, findings[c])
	}
	sort.SliceStable(rows, func(i, j int) bool { return less(rows[i], rows[j]) })

	counts := Counts{}
	for _, f := range rows {
		counts[f.Priority]++
	}
	for _, f := range rows {
		if f.IsNew != nil && *f.IsNew {
			nov.NewCVEs = append(nov.NewCVEs, f.CVE)
		}
	}
	return &Result{
		Generated:     o.Now.UTC().Format("2006-01-02T15:04:05-07:00"),
		SourceMeta:    meta,
		Counts:        counts,
		Total:         len(rows),
		Degraded:      degraded,
		KEVDeadlines:  kevSummary(rows),
		EmailSubjects: subjects,
		Novelty:       nov,
		Findings:      rows,
		kev:           kev,
	}, nil
}

// markNovelty flags each finding as new or seen before. A daily digest
// should lead with what changed since yesterday; the lookback is a window,
// so a CVE still being discussed reappears every run.
func markNovelty(findings map[string]*Finding, o Options) Novelty {
	nov := Novelty{NewCVEs: []string{}}
	var seen map[string]string
	ok := false
	if o.FirstSeen != nil {
		var err error
		seen, ok, err = o.FirstSeen()
		if err != nil {
			o.Logf("novelty check skipped (%v)", err)
			ok = false
		}
	}
	if !ok {
		nov.Undetermined = len(findings)
		return nov
	}
	for cve, f := range findings {
		if first, found := seen[cve]; found {
			no := false
			f.IsNew, f.FirstSeen = &no, &first
			nov.SeenBefore++
		} else {
			yes := true
			f.IsNew = &yes
			nov.New++
		}
	}
	return nov
}

var sevRank = map[string]int{"Sev5": 0, "Sev4": 1, "Sev3": 2, "Sev2": 3, "Sev1": 4}

// less orders findings for triage: band, then host count, then how overdue
// a present KEV deadline is, then EPSS, then the CVE.
//
// Host count comes before lateness on purpose. An earlier cut put
// overdue-ness first, which pushed a 40-host finding below a 4-host one:
// blast radius is the risk, and a deadline is an obligation about that risk.
func less(a, b *Finding) bool {
	if sevRank[a.Priority] != sevRank[b.Priority] {
		return sevRank[a.Priority] < sevRank[b.Priority]
	}
	if a.HostCount != b.HostCount {
		return a.HostCount > b.HostCount
	}
	if oa, ob := overdue(a), overdue(b); oa != ob {
		return oa > ob
	}
	ea, eb := 0.0, 0.0
	if a.EPSS != nil {
		ea = a.EPSS.EPSS
	}
	if b.EPSS != nil {
		eb = b.EPSS.EPSS
	}
	if ea != eb {
		return ea > eb
	}
	return a.CVE < b.CVE
}

func overdue(f *Finding) int {
	if f.KEVDaysLeft == nil || f.Status != "PRESENT" || f.HostCount <= 0 || *f.KEVDaysLeft >= 0 {
		return 0
	}
	return -*f.KEVDaysLeft
}

// SaveProducts remembers each CVE's product name, for fleet tickets whose
// CVE is not in today's mail: every KEV entry (most fleet tickets are KEV),
// plus each finding's own answer. Merged, never pruned, and written only when
// something changed.
func SaveProducts(path string, res *Result, now time.Time) error {
	known := map[string]string{}
	if !loadCache(path, 36500*24*time.Hour, now, &known) || known == nil {
		known = map[string]string{}
	}
	changed := false
	set := func(cve, name string) {
		if old, ok := known[cve]; !ok || old != name {
			known[cve] = name
			changed = true
		}
	}
	for cve, v := range res.kev {
		if name := ProductName(deref(v.Vendor), deref(v.Product)); name != "" {
			set(cve, name)
		}
	}
	for _, f := range res.Findings {
		if f.Product != "" {
			set(f.CVE, f.Product)
		}
	}
	if !changed {
		return nil
	}
	return saveCache(path, known, now)
}
