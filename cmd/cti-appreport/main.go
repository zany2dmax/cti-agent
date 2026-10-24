// cti-appreport fetches the DAST scanner's own report for each application,
// zipped, for cti-jira to attach to the application's ticket.
//
//	cti-appreport --list-ids                                # app ids from the last weekly run; no API
//	cti-appreport --check                                   # credentials + rate-limit headers
//	cti-appreport --app-id 1234 --dump-request              # the request body, nothing sent
//	cti-appreport --app-id 1234 --out-dir /tmp/r            # one report: create, poll, download, delete
//	cti-appreport --probe-findings 1234 > probe.xml         # verbose finding fields, redacted
//	cti-appreport --tickets T.json --only-ref P.json --out-dir D   # the weekly run
//
// # ONE INTERFACE, ANY SCANNER
//
// The scanner is chosen by APPSCAN_REPORT_PROVIDER (default qualys-was) and
// reached only through appscan.ReportFetcher. Supporting Invicti or Wiz is a
// package implementing that interface and one case in reportProvider below;
// cti-jira and the runner do not change.
//
// # IT DOES NOT WRITE TO JIRA
//
// Same split as cti-appscan: this talks to the scanner and writes files;
// cti-jira --appscan-reports reads them. A report fetched here reaches a
// ticket only if reports.json lists it.
//
// # IT SPENDS THE SHARED QUALYS API BUDGET
//
// Each report is about five calls. The client reads Qualys's rate-limit
// headers on every response (internal/qualysrl): it waits out a short
// refusal, gives way when only QUALYS_RL_RESERVE calls are left, and the
// weekly run asks only for the applications whose ticket will be filed or
// commented (--only-ref), never for unchanged ones.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/appscan/qualys"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() { os.Exit(run()) }

func logf(format string, a ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "[appreport] "+format+"\n", a...)
}

func die(format string, a ...any) int {
	logf("error  : "+format, a...)
	return exitErr
}

// Optional extras a provider may offer for testing. Not part of
// appscan.ReportFetcher: a scanner without them still attaches reports.
type checker interface {
	Check(ctx context.Context) (int, error)
}

type prober interface {
	ProbeFindings(ctx context.Context, appID string, n int) ([]byte, error)
}

type requestDumper interface {
	ReportRequestBody(req appscan.ReportRequest, name string) string
	SetReportTemplate(t string)
}

func run() int {
	check := flag.Bool("check", false,
		"make one cheap authenticated call, print the scanner's rate-limit position, and exit")
	appID := flag.String("app-id", "", "fetch the report for this one web application id (a test)")
	appName := flag.String("app-name", "", "with --app-id: the name used in messages and the report title")
	tickets := flag.String("tickets", "",
		"fetch a report for every application in this cti-appscan --tickets-out file that "+
			"has findings and was not skipped")
	onlyRef := flag.String("only-ref", "",
		"with --tickets: a cti-jira --ref-out preview; fetch only the applications whose "+
			"ticket would be filed or commented (would-create, would-comment)")
	outDir := flag.String("out-dir", "",
		"write each report (<label>.zip) and reports.json here, 0600; created 0700 if missing")
	maxReports := flag.Int("max-reports", 30,
		"fetch at most this many reports in one run; the rest are listed as not fetched")
	keep := flag.Bool("keep", false, "leave each report in the scanner instead of deleting it (debugging)")
	timeout := flag.Duration("timeout", 10*time.Minute, "give up on one report after this long")
	dump := flag.Bool("dump-request", false, "with --app-id: print the request that creates the report, send nothing")
	requestFile := flag.String("request-file", "",
		"send this create-report body instead of the built-in one ({{APP_ID}} and {{NAME}} "+
			"are filled in) - for correcting a field name while probing, without a rebuild")
	probe := flag.String("probe-findings", "",
		"print the scanner's verbose finding search for this web application id (3 open "+
			"vulnerabilities), with Cookie, Set-Cookie and Authorization redacted, and exit")
	listIDs := flag.Bool("list-ids", false,
		"print the web application id, name and findings of every application in the newest "+
			"$FLEET_HOME/state/appscan-tickets-<date>.json (or the --tickets file), and exit; "+
			"reads the file only - no scanner calls, no credentials")
	flag.Parse()

	fleetenv.Load()
	if *listIDs {
		return doListIDs(*tickets)
	}
	// The scanner's settings only: no mailbox, no Jira.
	cfg, err := config.LoadVulnLookup()
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}

	fetcher, err := reportProvider(cfg)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	if *requestFile != "" {
		d, ok := fetcher.(requestDumper)
		if !ok {
			return die("--request-file: the %s provider does not take a request body", fetcher.Name())
		}
		// #nosec G304 G703 -- an operator-supplied test file
		b, err := os.ReadFile(*requestFile)
		if err != nil {
			return die("--request-file: %s", safelog.Line(err.Error()))
		}
		d.SetReportTemplate(string(b))
	}
	defer func() {
		if rr, ok := fetcher.(appscan.RateReporter); ok {
			logf("api    : %s", safelog.Line(rr.RateStatus()))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	switch {
	case *dump:
		if *appID == "" {
			return die("--dump-request needs --app-id")
		}
		d, ok := fetcher.(requestDumper)
		if !ok {
			return die("the %s provider has no request body to show", fetcher.Name())
		}
		fmt.Println(d.ReportRequestBody(appscan.ReportRequest{AppID: *appID, App: *appName},
			"cti-agent "+*appName+" "+time.Now().UTC().Format("2006-01-02")))
		return exitOK

	case *check:
		c, ok := fetcher.(checker)
		if !ok {
			return die("the %s provider has no --check", fetcher.Name())
		}
		n, err := c.Check(ctx)
		if err != nil {
			return die("%s", safelog.Line(err.Error()))
		}
		fmt.Printf("%s: credentials work; %d web application(s) defined\n", fetcher.Name(), n)
		if rr, ok := fetcher.(appscan.RateReporter); ok {
			fmt.Printf("api budget: %s\n", rr.RateStatus())
		}
		return exitOK

	case *probe != "":
		p, ok := fetcher.(prober)
		if !ok {
			return die("the %s provider has no --probe-findings", fetcher.Name())
		}
		body, err := p.ProbeFindings(ctx, *probe, 3)
		if err != nil {
			return die("%s", safelog.Line(err.Error()))
		}
		logf("note   : redacted, but still evidence from our own application - keep the output 0600 and off tickets")
		fmt.Println(appscan.Redact(string(body)))
		return exitOK

	case *appID != "":
		if *outDir == "" {
			return die("--app-id needs --out-dir")
		}
		key := "id:" + strings.TrimSpace(*appID)
		name := *appName
		if name == "" {
			name = "web app " + *appID
		}
		m, failed := fetchAll(ctx, fetcher, *outDir, []target{{key: key, id: *appID, name: name}},
			1, *keep, *timeout)
		if failed > 0 {
			return die("the report was not fetched: %s", safelog.Line(m.Failed[key]))
		}
		r := m.Reports[key]
		fmt.Printf("%s: %d bytes in %s/%s (scanner report id %s%s)\n", name, r.Bytes, *outDir, r.File,
			r.RemoteID, map[bool]string{true: ", left in the scanner", false: ", deleted from the scanner"}[r.Kept])
		return exitOK

	case *tickets != "":
		if *outDir == "" {
			return die("--tickets needs --out-dir")
		}
		targets, err := ticketTargets(*tickets, *onlyRef)
		if err != nil {
			return die("%s", safelog.Line(err.Error()))
		}
		logf("plan   : %d application(s) need a report", len(targets))
		_, failed := fetchAll(ctx, fetcher, *outDir, targets, *maxReports, *keep, *timeout)
		if failed > 0 {
			// Not fatal: each ticket still carries every finding, and says
			// nothing about an attachment that is not there.
			logf("warn   : %d report(s) not fetched - those tickets go out without one", failed)
		}
		return exitOK
	}
	flag.Usage()
	return exitErr
}

// reportProvider is the one place a scanner is chosen. To add one: implement
// appscan.ReportFetcher in its own package and add a case here.
func reportProvider(cfg config.Config) (appscan.ReportFetcher, error) {
	name := strings.ToLower(strings.TrimSpace(os.Getenv("APPSCAN_REPORT_PROVIDER")))
	switch name {
	case "", "qualys-was", "qualys":
		if cfg.QualysBaseURL == "" || cfg.QualysUsername == "" || cfg.QualysPassword == "" {
			return nil, errors.New("QUALYS_BASE_URL, QUALYS_USERNAME and QUALYS_PASSWORD must be set " +
				"for the qualys-was report provider")
		}
		return qualys.NewAPI(cfg.QualysBaseURL, cfg.QualysUsername, cfg.QualysPassword), nil
	}
	return nil, fmt.Errorf("APPSCAN_REPORT_PROVIDER=%q is not a report provider this build knows "+
		"(known: qualys-was). A new scanner implements appscan.ReportFetcher and is added in "+
		"cmd/cti-appreport reportProvider", name)
}

type target struct{ key, id, name string }

// ticketTargets is the applications that need a report this week.
func ticketTargets(ticketsPath, refPath string) ([]target, error) {
	// #nosec G304 G703 -- the runner's own --tickets-out file
	b, err := os.ReadFile(ticketsPath)
	if err != nil {
		return nil, err
	}
	var tf appscan.TicketsFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return nil, fmt.Errorf("%s is not a cti-appscan tickets file: %w", ticketsPath, err)
	}
	var want map[string]bool
	if refPath != "" {
		// #nosec G304 G703 -- the runner's own cti-jira --ref-out file
		rb, err := os.ReadFile(refPath)
		if err != nil {
			return nil, err
		}
		var refs struct {
			Apps map[string]struct {
				Action string `json:"action"`
			} `json:"apps"`
		}
		if err := json.Unmarshal(rb, &refs); err != nil {
			return nil, fmt.Errorf("%s is not a cti-jira --ref-out file: %w", refPath, err)
		}
		want = map[string]bool{}
		for k, r := range refs.Apps {
			if r.Action == "would-create" || r.Action == "would-comment" {
				want[k] = true
			}
		}
	}
	var out []target
	for _, t := range tf.Tickets {
		if t.Skip != "" || len(t.Findings) == 0 || strings.TrimSpace(t.AppID) == "" {
			continue
		}
		if want != nil && !want[t.Key] {
			continue
		}
		out = append(out, target{key: t.Key, id: t.AppID, name: t.App})
	}
	return out, nil
}

// fetchAll fetches each target's report in turn and writes the manifest. It
// stops early - listing the rest as not fetched - once the scanner's budget
// is reserved for the other lanes.
func fetchAll(ctx context.Context, f appscan.ReportFetcher, dir string, targets []target,
	max int, keep bool, timeout time.Duration) (appscan.ReportsManifest, int) {

	m := appscan.ReportsManifest{Generated: time.Now().UTC(), Provider: f.Name(),
		Reports: map[string]appscan.Report{}, Failed: map[string]string{}}
	// #nosec G703 -- the operator's --out-dir
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		// MkdirAll leaves an existing directory's mode alone.
		err = os.Chmod(dir, 0o700) // #nosec G302 G703 -- a directory, owner-only
	}
	if err != nil {
		for _, t := range targets {
			m.Failed[t.key] = "could not create the reports directory"
		}
		logf("error  : %s", safelog.Line(err.Error()))
		return m, len(targets)
	}
	stop := ""
	for i, t := range targets {
		name := safelog.Line(t.name)
		switch {
		case stop != "":
			m.Failed[t.key] = stop
			continue
		case i >= max:
			m.Failed[t.key] = fmt.Sprintf("over --max-reports %d", max)
			continue
		}
		start := time.Now()
		r, err := f.AppReport(ctx, appscan.ReportRequest{AppID: t.id, App: t.name, Keep: keep, Timeout: timeout})
		if err == nil {
			r, err = appscan.WriteReport(dir, t.key, r)
		}
		if err != nil {
			m.Failed[t.key] = err.Error()
			logf("warn   : %s: no report - %s", name, safelog.Line(err.Error()))
			if errors.Is(err, qualysrl.ErrBudget) || ctx.Err() != nil {
				stop = "not attempted: " + err.Error()
			}
			continue
		}
		m.Reports[t.key] = r
		logf("report : %s: %d KB in %s", name, r.Bytes>>10, time.Since(start).Round(time.Second))
	}
	if err := appscan.WriteManifest(dir, m); err != nil {
		logf("error  : writing %s: %s", appscan.ManifestName, safelog.Line(err.Error()))
	}
	return m, len(m.Failed)
}

// ticketsFileRE is the weekly run's tickets file - not its -ref-, -plan- or
// -preview- siblings.
var ticketsFileRE = regexp.MustCompile(`^appscan-tickets-\d{4}-\d{2}-\d{2}\.json$`)

// newestTicketsFile is the most recent weekly tickets file in the state
// directory. The date is in the name, so the newest name is the newest run.
func newestTicketsFile(stateDir string) (string, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && ticketsFileRE.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no appscan-tickets-<date>.json in %s - has run-appscan run since "+
			"application tickets were added? (sudo cti-agent run-appscan --dry-run writes one)", stateDir)
	}
	sort.Strings(names)
	return filepath.Join(stateDir, names[len(names)-1]), nil
}

// doListIDs prints the ids to try --app-id with. From the weekly run's own
// file, so it costs no API calls and needs no credentials.
func doListIDs(path string) int {
	if path == "" {
		home := os.Getenv("FLEET_HOME")
		if home == "" {
			return die("FLEET_HOME is not set - run it as `sudo cti-agent cti-appreport --list-ids`, " +
				"or name the file with --tickets")
		}
		var err error
		if path, err = newestTicketsFile(filepath.Join(home, "state")); err != nil {
			return die("%s", safelog.Line(err.Error()))
		}
	}
	// #nosec G304 G703 -- the runner's own tickets file, or one the operator named
	b, err := os.ReadFile(path)
	if err != nil {
		return die("%s", safelog.Line(err.Error()))
	}
	var tf appscan.TicketsFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return die("%s is not a cti-appscan tickets file: %s", safelog.Line(path), safelog.Line(err.Error()))
	}
	fmt.Print(listIDs(tf, path))
	return exitOK
}

func listIDs(tf appscan.TicketsFile, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From %s (written %s)\n\n", filepath.Base(path), tf.Generated.UTC().Format("2006-01-02 15:04 UTC"))
	ts := append([]appscan.AppTicket(nil), tf.Tickets...)
	sort.SliceStable(ts, func(i, j int) bool { return strings.ToLower(ts[i].App) < strings.ToLower(ts[j].App) })
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "APP ID\tTO FIX\tPOTENTIAL\tREPORT?\tAPPLICATION")
	ready := 0
	for _, t := range ts {
		confirmed, potential := appscan.Split(t.Findings)
		id := strings.TrimSpace(t.AppID)
		state := "yes"
		switch {
		case id == "":
			id, state = "-", "no id"
		case t.Skip != "":
			state = "skipped this week"
		case len(t.Findings) == 0:
			state = "nothing to attach"
		default:
			ready++
		}
		_, _ = fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\n", safelog.Line(id), len(confirmed), len(potential),
			state, safelog.Line(t.App))
	}
	_ = w.Flush()
	fmt.Fprintf(&b, "\n%d of %d application(s) would get a report. Try one with:\n"+
		"  sudo cti-agent cti-appreport --app-id <APP ID> --dump-request\n", ready, len(ts))
	return b.String()
}
