// cti-patchtuesday builds the monthly Microsoft Patch Tuesday synopsis.
//
// It reads the Qualys and BleepingComputer wrap-ups, correlates the CVEs
// against Qualys Host Detection to find what actually landed here, and writes
// the email. It does not send: mailer.py is the single outbound channel, and
// run-patchtuesday hands this output to it.
//
//	cti-patchtuesday                      the most recent release
//	cti-patchtuesday --month 2026-08      replay a past month (testing)
//	cti-patchtuesday --dry-run            print the text version, write nothing
//	cti-patchtuesday --out d.html --text-out d.txt
//	cti-patchtuesday --subject-only       just the subject line
//	cti-patchtuesday --url-qualys URL --url-bleeping URL
//	cti-patchtuesday --provider none      skip Qualys (source parsing only)
//
// Exit 0 when the synopsis was produced, even from one source: a partial
// synopsis clearly labelled is more useful than silence. Exit 1 only when it
// could not produce anything at all.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/kev"
	"github.com/zany2dmax/cti-agent/internal/patchtuesday"
	"github.com/zany2dmax/cti-agent/internal/vulnlookup/qualys"
)

func main() {
	month := flag.String("month", "",
		"YYYY-MM to report on; default is the most recent release. Use this to "+
			"replay a past month and check the lane against an email you already sent")
	out := flag.String("out", "", "write the HTML here")
	textOut := flag.String("text-out", "", "write the plain-text version here")
	jsonOut := flag.String("json", "", "write the structured digest here, for inspection")
	dryRun := flag.Bool("dry-run", false, "print the text version to stdout, write nothing")
	subjectOnly := flag.Bool("subject-only", false, "print the subject line and exit")
	urlQualys := flag.String("url-qualys", "", "override the Qualys review URL")
	urlBleeping := flag.String("url-bleeping", "", "override the BleepingComputer URL")
	provider := flag.String("provider", "", "'none' to skip Qualys entirely")
	timeout := flag.Duration("timeout", 45*time.Second, "per-request HTTP timeout")
	enriched := flag.String("enriched", "",
		"path to enriched JSON for the Sev5-Sev1 bands; default is the newest "+
			"in $FLEET_HOME/state. Without it the severity column is omitted")
	maxRows := flag.Int("max-rows", 0,
		"cap the present-CVE table (default 25). The full list is always in --json")
	explain := flag.String("explain", "",
		"print every place a CVE was found on the source pages, and whether "+
			"anything ties it to a Microsoft product, then exit")
	flag.Parse()

	now := time.Now()
	var year int
	var mon time.Month
	if *month != "" {
		y, m, err := patchtuesday.ParseMonth(*month)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: %v\n", err)
			os.Exit(1)
		}
		year, mon = y, m
	} else {
		year, mon = patchtuesday.TargetMonth(now)
	}

	// Refuse to summarise a release that has not happened. Without this a run
	// early in the month produces a confidently empty email, which reads as a
	// quiet month rather than as a mistake.
	if !patchtuesday.Released(year, mon, now) {
		fmt.Fprintf(os.Stderr,
			"cti-patchtuesday: %s Patch Tuesday is %s, which is in the future. "+
				"Nothing to summarise yet.\n",
			patchtuesday.MonthLabel(year, mon),
			patchtuesday.PatchTuesday(year, mon).Format("2006-01-02"))
		os.Exit(1)
	}

	org := os.Getenv("FLEET_ORG")
	if org == "" {
		org = "Security"
	}

	d := &patchtuesday.Digest{Year: year, Month: mon}
	if *subjectOnly {
		r := &patchtuesday.Report{Digest: d, Org: org}
		fmt.Println(r.Subject())
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: *timeout}

	qURL := *urlQualys
	if qURL == "" {
		qURL = patchtuesday.QualysURL(year, mon)
	}
	qs := patchtuesday.Fetch(ctx, client, "Qualys security update review", qURL)
	qs.Role = patchtuesday.RoleQualysBlog
	d.Sources = append(d.Sources, qs)

	bURL := *urlBleeping
	if bURL == "" {
		bURL = discoverBleeping(ctx, client, year, mon)
	}
	bs := patchtuesday.Fetch(ctx, client, "BleepingComputer Patch Tuesday", bURL)
	bs.Role = patchtuesday.RoleBleeping
	d.Sources = append(d.Sources, bs)

	patchtuesday.Parse(d)

	anyFetched := false
	for _, s := range d.Sources {
		if s.Fetched {
			anyFetched = true
		}
		if s.Err != "" {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: %s unavailable (%s): %s\n",
				s.Name, s.Err, s.URL)
		}
	}
	if !anyFetched {
		fmt.Fprintln(os.Stderr,
			"cti-patchtuesday: neither source could be read - not sending a synopsis "+
				"built from nothing. Check outbound 443 to blog.qualys.com and "+
				"www.bleepingcomputer.com, then retry with --url-qualys / --url-bleeping "+
				"if the URL pattern has changed.")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "cti-patchtuesday: %s - %d CVE(s) in the sources, "+
		"%d QID(s) published in the review\n",
		patchtuesday.MonthLabel(year, mon), len(d.CVEs), len(d.PublishedQIDs()))
	for _, c := range d.ExcludedCVEs {
		fmt.Fprintf(os.Stderr,
			"cti-patchtuesday:   scoped out %s - every sighting names %q, none "+
				"names a Microsoft product\n", c, d.ExcludedWhy[c])
	}
	if note := d.CVECountNote(); note != "" {
		fmt.Fprintf(os.Stderr, "cti-patchtuesday:   %s\n", note)
	}
	if *explain != "" {
		fmt.Print(d.Explain(*explain))
		return
	}
	// Provenance. The August replay reported a total of 400 while the Qualys
	// post said 421, and nothing in the output said which page each figure had
	// come from, so the discrepancy could only be investigated by reading code.
	for _, k := range []string{"total", "critical", "important", "zero_days", "products", "qql"} {
		if v := d.From[k]; v != "" {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday:   %-10s <- %s\n", k, v)
		}
	}

	report := &patchtuesday.Report{Digest: d, Org: org, MaxRows: *maxRows}
	var detections map[int]patchtuesday.DetectionLike

	if strings.EqualFold(*provider, "none") {
		reason := "--provider none was passed, so Qualys was not queried"
		fmt.Fprintln(os.Stderr, "cti-patchtuesday: "+reason)
		report.Exposure = patchtuesday.Unmeasured(reason)
	} else {
		var err error
		detections, err = correlate(ctx, d, report)
		if err != nil {
			// The synopsis still goes out. Losing our own exposure numbers is
			// a real loss, so it is stated, not swallowed - and it is recorded
			// as "not measured" rather than left as a zero-value Exposure,
			// which the email would otherwise have rendered as a finding about
			// the KnowledgeBase.
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: Qualys correlation failed: %v\n", err)
			report.Exposure = patchtuesday.Unmeasured(err.Error())
			d.Sources = append(d.Sources, patchtuesday.Source{
				Name: "Qualys Host Detection (exposure)",
				Role: patchtuesday.RoleExposure, URL: "-",
				Err: err.Error(),
			})
		}
	}
	report.ChooseQQL(report.Exposure.DetectedQIDs(detections))

	// Severity bands, if the enrich lane has produced any. Silence here is
	// acceptable and is reported; a column of "?" was not.
	if len(report.Highlights) > 0 {
		path := *enriched
		if path == "" {
			path = newestEnriched()
		}
		switch {
		case path == "":
			fmt.Fprintln(os.Stderr,
				"cti-patchtuesday: no enriched JSON found ($FLEET_HOME/state/enriched-*.json); "+
					"the severity column will be omitted rather than left blank")
		default:
			n, err := enrichHighlights(report.Highlights, path)
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"cti-patchtuesday: could not read %s (%v); severity column omitted\n",
					path, err)
			} else {
				fmt.Fprintf(os.Stderr,
					"cti-patchtuesday: severity bands for %d of %d present CVE(s) from %s\n",
					n, len(report.Highlights), filepath.Base(path))
			}
		}
	}

	if *jsonOut != "" {
		// #nosec G304 -- *jsonOut is an operator-supplied --json path; 0o600
		// because the structured digest carries the same host names as the
		// email.
		f, err := os.OpenFile(*jsonOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err == nil {
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			_ = enc.Encode(map[string]any{
				"month": patchtuesday.MonthLabel(year, mon), "digest": d,
				"exposure": report.Exposure, "qql": report.QQL,
				"qql_source": report.QQLSource, "subject": report.Subject(),
			})
			_ = f.Close()
		}
	}

	if *dryRun {
		fmt.Print(report.Text())
		return
	}
	wrote := false
	// 0600: this names vulnerable machines, same as every other report here.
	if *out != "" {
		// #nosec G304 -- *out is an operator-supplied --out path.
		if err := os.WriteFile(*out, []byte(report.HTML()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "cti-patchtuesday: wrote %s\n", *out)
		wrote = true
	}
	if *textOut != "" {
		// #nosec G304 -- *textOut is an operator-supplied --text-out path.
		if err := os.WriteFile(*textOut, []byte(report.Text()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: %v\n", err)
			os.Exit(1)
		}
		wrote = true
	}
	if !wrote {
		fmt.Print(report.Text())
	}
}

// discoverBleeping finds the article URL. The slug embeds the flaw count
// ("...fixes-966-flaws-2-zero-days"), which is unknowable in advance, so the
// candidate is tried first and the tag listing is the fallback.
func discoverBleeping(ctx context.Context, c *http.Client, year int, mon time.Month) string {
	for _, u := range patchtuesday.BleepingURLCandidates(year, mon) {
		if s := patchtuesday.Fetch(ctx, c, "probe", u); s.Fetched {
			return u
		}
	}
	listing := patchtuesday.Fetch(ctx, c, "probe", patchtuesday.BleepingListing)
	if listing.Fetched {
		if u := patchtuesday.FindBleepingArticle(listing.RawHTML, year, mon); u != "" {
			return u
		}
	}
	// Return the canonical guess anyway: the fetch will fail and say so, which
	// is more useful than an empty URL in the error.
	return patchtuesday.BleepingURLCandidates(year, mon)[0]
}

// correlate maps the release's CVEs to QIDs and asks Qualys what is present.
func correlate(ctx context.Context, d *patchtuesday.Digest,
	r *patchtuesday.Report) (map[int]patchtuesday.DetectionLike, error) {

	// Scanner settings only. This command never touches a mailbox.
	cfg, err := config.LoadVulnLookup()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	published := d.PublishedQIDs()
	if len(d.CVEs) == 0 && len(published) == 0 {
		return nil, fmt.Errorf("no CVEs and no published QIDs in the sources to correlate")
	}

	q := qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword,
		cfg.QualysKBCachePath, cfg.QualysKBMaxAge)

	// A KnowledgeBase that will not load is no longer fatal. The review's own
	// QID list is an independent route to a number, and on the morning after a
	// release it is usually the better one - so losing the mapping degrades the
	// correlation rather than cancelling it.
	kbStale := false
	kb, err := q.LoadOrBuildKBCache(ctx, cfg.QualysKBCachePath)
	if err != nil {
		if len(published) == 0 {
			return nil, fmt.Errorf("KnowledgeBase cache: %w", err)
		}
		fmt.Fprintf(os.Stderr,
			"cti-patchtuesday: KnowledgeBase cache unavailable (%v); correlating on "+
				"the %d QID(s) Qualys published in this month's review instead\n",
			err, len(published))
		kb, kbStale = map[string][]int{}, true
	}
	cveToQIDs := map[string][]int{}
	var allQIDs []int
	for _, cve := range d.CVEs {
		if qids := kb[strings.ToUpper(cve)]; len(qids) > 0 {
			cveToQIDs[strings.ToUpper(cve)] = qids
			allQIDs = append(allQIDs, qids...)
		}
	}
	// Union, not fallback. The two routes overlap but neither contains the
	// other: the mapping covers CVEs Qualys did not put in the QQL, and the
	// QQL covers detections the mapping has not caught up with.
	kbQIDs := len(dedupe(allQIDs))
	allQIDs = append(allQIDs, published...)

	det := map[int]patchtuesday.DetectionLike{}
	// One batched call rather than one per CVE. A Patch Tuesday can carry
	// hundreds of CVEs and thousands of QIDs; per-CVE lookups would take hours
	// and hammer the API.
	if len(allQIDs) == 0 {
		// Attempted, and honestly empty: Summarise records that we looked.
		r.Exposure = patchtuesday.Summarise(d.CVEs, cveToQIDs, published, det, kbStale)
		return det, nil
	}
	for _, chunk := range chunkInts(allQIDs, 300) {
		sums, err := q.HostDetections(ctx, chunk)
		if err != nil {
			return det, fmt.Errorf("host detections: %w", err)
		}
		for qid, s := range sums {
			det[qid] = patchtuesday.DetectionLike{
				QID: s.QID, HostCount: s.HostCount,
				Hosts: s.Hosts, HostsTruncated: s.HostsTruncated,
			}
		}
	}

	r.Exposure = patchtuesday.Summarise(d.CVEs, cveToQIDs, published, det, kbStale)
	r.Highlights = buildHighlights(r.Exposure, cveToQIDs, det)
	fmt.Fprintf(os.Stderr,
		"cti-patchtuesday: queried %d QID(s) (%d from the KnowledgeBase mapping, "+
			"%d published in the review); %d detection(s) on %d host(s)\n",
		len(r.Exposure.QIDs), kbQIDs, len(published),
		r.Exposure.Detections, r.Exposure.Hosts)
	return det, nil
}

func buildHighlights(e patchtuesday.Exposure, cveToQIDs map[string][]int,
	det map[int]patchtuesday.DetectionLike) []patchtuesday.Highlight {

	var out []patchtuesday.Highlight
	for _, cve := range e.PresentCVEs {
		h := patchtuesday.Highlight{CVE: cve}
		hosts := map[string]bool{}
		largest := 0
		for _, q := range cveToQIDs[cve] {
			d, ok := det[q]
			if !ok || d.HostCount == 0 {
				continue
			}
			h.QIDs = append(h.QIDs, q)
			if d.HostsTruncated || len(d.Hosts) < d.HostCount {
				h.HostsAreFloor = true
			}
			if d.HostCount > largest {
				largest = d.HostCount
			}
			for _, x := range d.Hosts {
				if x = strings.TrimSpace(strings.ToLower(x)); x != "" {
					hosts[x] = true
				}
			}
		}
		h.Hosts = len(hosts)
		// A single QID's own count is proven, so never report fewer machines
		// than that - which is possible only when the host lists were cut off.
		if largest > h.Hosts {
			h.Hosts = largest
			h.HostsAreFloor = true
		}
		out = append(out, h)
	}
	return out
}

// enrich fills in the severity band and the reasons behind it from the enrich
// lane's output, and reports how many rows it could fill.
//
// Without this the Sev column was structurally empty - nothing in this command
// ever set it - so every row printed "?" in a column that could not hold a
// value. Either the band is real or the column is not shown.
func enrichHighlights(hs []patchtuesday.Highlight, path string) (int, error) {
	e, err := kev.Load(path)
	if err != nil {
		return 0, err
	}
	byCVE := make(map[string]kev.Finding, len(e.Findings))
	for _, f := range e.Findings {
		byCVE[strings.ToUpper(strings.TrimSpace(f.CVE))] = f
	}
	n := 0
	for i := range hs {
		f, ok := byCVE[strings.ToUpper(hs[i].CVE)]
		if !ok {
			continue
		}
		hs[i].Sev = f.Priority
		hs[i].KEV = f.KEV == 1
		hs[i].EPSS = f.EPSS
		hs[i].CVSS = f.CVSS
		hs[i].Rationale = f.Rationale
		if f.Priority != "" {
			n++
		}
	}
	return n, nil
}

// newestEnriched finds the most recent enriched-*.json, the same way cti-kev
// does. Returns "" when there is none, which is not an error: a fresh install
// has no enrichment yet and the report simply omits the column.
func newestEnriched() string {
	home := os.Getenv("FLEET_HOME")
	if home == "" {
		return ""
	}
	dir := filepath.Join(home, "state")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best := ""
	for _, ent := range entries {
		n := ent.Name()
		if strings.HasPrefix(n, "enriched-") && strings.HasSuffix(n, ".json") && n > best {
			best = n
		}
	}
	if best == "" {
		return ""
	}
	return filepath.Join(dir, best)
}

func dedupe(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func chunkInts(in []int, n int) [][]int {
	uniq := dedupe(in)
	var out [][]int
	for i := 0; i < len(uniq); i += n {
		j := i + n
		if j > len(uniq) {
			j = len(uniq)
		}
		out = append(out, uniq[i:j])
	}
	return out
}
