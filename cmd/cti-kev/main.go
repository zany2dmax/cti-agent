// cti-kev reports CISA KEV remediation deadlines for vulnerabilities the
// scanner actually found in the environment.
//
//	cti-kev                         latest enriched file, markdown
//	cti-kev --enriched <path>       a specific file
//	cti-kev --horizon 30            widen the "due soon" window
//	cti-kev --hosts                 include sample hostnames
//	cti-kev --json                  machine-readable
//	cti-kev --quiet                 print nothing when nothing is due
//
// Exit status is 0 even when findings are overdue: being late on a patch is
// not a failure of this program, and a non-zero exit would mark the calling
// unit failed and send an alert about a working report. Use --fail-if-overdue
// when you want the exit code to carry the finding, such as in CI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/kev"
)

func main() {
	enriched := flag.String("enriched", "",
		"path to enriched JSON; default is the newest in $FLEET_HOME/state")
	horizon := flag.Int("horizon", 14, "\"due soon\" window in days")
	showHosts := flag.Bool("hosts", false,
		"include sample hostnames; the output then names vulnerable machines")
	asJSON := flag.Bool("json", false, "machine-readable output")
	quiet := flag.Bool("quiet", false,
		"print nothing when nothing is overdue or due within the horizon")
	failIfOverdue := flag.Bool("fail-if-overdue", false,
		"exit 2 when something is overdue (for CI, not for systemd)")
	flag.Parse()

	path := *enriched
	if path == "" {
		p, err := newestEnriched()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cti-kev: %v\n", err)
			os.Exit(1)
		}
		path = p
	}

	e, err := kev.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cti-kev: %v\n", err)
		os.Exit(1)
	}

	r := kev.Analyze(e, time.Now().UTC(), *horizon)

	// A degraded KEV fetch means the deadline data may be incomplete. Saying
	// so matters more than the numbers: a short overdue list from a failed
	// catalog download looks exactly like good news.
	for _, d := range e.Degraded {
		if strings.Contains(strings.ToLower(d), "kev") {
			fmt.Fprintf(os.Stderr,
				"cti-kev: WARNING - the enrich run reported %q degraded, so "+
					"deadlines may be missing entirely\n", d)
		}
	}

	if *asJSON {
		out := map[string]any{
			"source":              path,
			"enriched_generated":  e.Generated,
			"now":                 r.Now.Format(time.RFC3339),
			"horizon_days":        r.Horizon,
			"overdue":             len(r.Overdue),
			"due_soon":            len(r.DueSoon),
			"later":               len(r.Later),
			"worst_overdue_days":  r.WorstOverdueDays(),
			"ransomware_present":  r.RansomwareCount(),
			"not_detected_here":   r.NotHere,
			"coverage_unverified": r.Unverified,
			"overdue_cves":        cves(r.Overdue),
			"due_soon_cves":       cves(r.DueSoon),
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else if !(*quiet && r.Clean()) {
		fmt.Print(r.Markdown(*showHosts))
		fmt.Printf("\n_Source: %s (enriched %s)_\n", filepath.Base(path), e.Generated)
	}

	if *failIfOverdue && len(r.Overdue) > 0 {
		os.Exit(2)
	}
}

func cves(rows []kev.Dated) []string {
	out := make([]string, 0, len(rows))
	for _, d := range rows {
		out = append(out, d.CVE)
	}
	return out
}

// newestEnriched picks the most recent enriched-*.json by filename rather than
// mtime. The names carry an ISO date, so lexical order is chronological, and a
// file touched by a backup or a relabel does not become "newest".
func newestEnriched() (string, error) {
	home := os.Getenv("FLEET_HOME")
	if home == "" {
		return "", fmt.Errorf("FLEET_HOME is not set and --enriched was not given")
	}
	dir := filepath.Join(home, "state")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "enriched-") && strings.HasSuffix(n, ".json") {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no enriched-*.json in %s - run the digest first", dir)
	}
	sort.Strings(names)
	return filepath.Join(dir, names[len(names)-1]), nil
}
