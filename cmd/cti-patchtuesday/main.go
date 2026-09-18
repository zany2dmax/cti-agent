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
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
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
	d.Sources = append(d.Sources,
		patchtuesday.Fetch(ctx, client, "Qualys security update review", qURL))

	bURL := *urlBleeping
	if bURL == "" {
		bURL = discoverBleeping(ctx, client, year, mon)
	}
	d.Sources = append(d.Sources,
		patchtuesday.Fetch(ctx, client, "BleepingComputer Patch Tuesday", bURL))

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
	fmt.Fprintf(os.Stderr, "cti-patchtuesday: %s - %d CVE(s) in the sources\n",
		patchtuesday.MonthLabel(year, mon), len(d.CVEs))

	report := &patchtuesday.Report{Digest: d, Org: org}
	var detections map[int]patchtuesday.DetectionLike

	if strings.EqualFold(*provider, "none") {
		fmt.Fprintln(os.Stderr,
			"cti-patchtuesday: --provider none, skipping Qualys. Exposure will read "+
				"as unmeasurable, which is accurate for this run.")
	} else {
		var err error
		detections, err = correlate(ctx, d, report)
		if err != nil {
			// The synopsis still goes out. Losing our own exposure numbers is
			// a real loss, so it is stated, not swallowed.
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: Qualys correlation failed: %v\n", err)
			d.Sources = append(d.Sources, patchtuesday.Source{
				Name: "Qualys Host Detection (exposure)", URL: "-",
				Err: err.Error(),
			})
		}
	}
	report.ChooseQQL(report.Exposure.DetectedQIDs(detections))

	if *jsonOut != "" {
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
		if err := os.WriteFile(*out, []byte(report.HTML()), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "cti-patchtuesday: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "cti-patchtuesday: wrote %s\n", *out)
		wrote = true
	}
	if *textOut != "" {
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

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if len(d.CVEs) == 0 {
		return nil, fmt.Errorf("no CVEs found in the sources to correlate")
	}

	q := qualys.New(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword,
		cfg.QualysKBCachePath, cfg.QualysKBMaxAge)

	kb, err := q.LoadOrBuildKBCache(ctx, cfg.QualysKBCachePath)
	if err != nil {
		return nil, fmt.Errorf("KnowledgeBase cache: %w", err)
	}
	cveToQIDs := map[string][]int{}
	var allQIDs []int
	for _, cve := range d.CVEs {
		if qids := kb[strings.ToUpper(cve)]; len(qids) > 0 {
			cveToQIDs[strings.ToUpper(cve)] = qids
			allQIDs = append(allQIDs, qids...)
		}
	}

	det := map[int]patchtuesday.DetectionLike{}
	// One batched call rather than one per CVE. A Patch Tuesday can carry
	// hundreds of CVEs and thousands of QIDs; per-CVE lookups would take hours
	// and hammer the API.
	for _, chunk := range chunkInts(allQIDs, 300) {
		sums, err := q.HostDetections(ctx, chunk)
		if err != nil {
			return det, fmt.Errorf("host detections: %w", err)
		}
		for qid, s := range sums {
			det[qid] = patchtuesday.DetectionLike{
				QID: s.QID, HostCount: s.HostCount, Hosts: s.Hosts,
			}
		}
	}

	r.Exposure = patchtuesday.Summarise(d.CVEs, cveToQIDs, det, false)
	r.Highlights = buildHighlights(r.Exposure, cveToQIDs, det)
	return det, nil
}

func buildHighlights(e patchtuesday.Exposure, cveToQIDs map[string][]int,
	det map[int]patchtuesday.DetectionLike) []patchtuesday.Highlight {

	var out []patchtuesday.Highlight
	for _, cve := range e.PresentCVEs {
		h := patchtuesday.Highlight{CVE: cve}
		hosts := map[string]bool{}
		for _, q := range cveToQIDs[cve] {
			d, ok := det[q]
			if !ok || d.HostCount == 0 {
				continue
			}
			h.QIDs = append(h.QIDs, q)
			for _, x := range d.Hosts {
				hosts[strings.ToLower(x)] = true
			}
		}
		h.Hosts = len(hosts)
		out = append(out, h)
	}
	return out
}

func chunkInts(in []int, n int) [][]int {
	seen := map[int]bool{}
	var uniq []int
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			uniq = append(uniq, v)
		}
	}
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
