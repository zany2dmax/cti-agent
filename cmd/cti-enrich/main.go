// cti-enrich is the @enrich lane: it takes the CVEs the agent found (or an
// explicit list) and adds NVD's CVSS and products, FIRST's EPSS and the CISA
// KEV catalog, then bands each finding Sev5-Sev1 (internal/enrich).
//
//	cti-enrich --report raw-2026-11-22.md --out enriched.json
//	cti-enrich --cves CVE-2026-1234,CVE-2026-5678 --out enriched.json
//	cti-enrich --report raw.md --out enriched.json --no-db     # no upsert
//
// It writes the enriched file cti-brief, cti-jira, cti-kev and the weekly
// read, and products.json beside it. Then it upserts the findings into the
// fleet's memory database through fleet-db, which owns the SQLite: this
// binary has no SQL in it. Before that it asks fleet-db when each CVE was
// first stored, so the digest can say what is new since the last run.
//
// It replaced the Python enrich.py, flag for flag and file for file.
//
// # SETTINGS
//
// FLEET_HOME (state/nvd-cache.json, state/kev-cache.json, state/memory.db),
// FLEET_CODE (where fleet-db is), NVD_API_KEY (a systemd credential: ten
// times NVD's rate limit), FLEET_USER_AGENT and GRAPH_MAILBOX (the agent the
// feeds see).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/enrich"
	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/safelog"
)

func main() {
	fleetenv.Load()
	os.Exit(run(os.Args[1:], os.Stderr, func(state string, logf func(string, ...any)) enrich.Sources {
		return enrich.NewLive(state, fleetenv.Secret("NVD_API_KEY"), logf)
	}, time.Now))
}

const usage = "usage: cti-enrich (--report FILE | --cves LIST) --out FILE [--no-db] [--skip-nvd]"

func run(args []string, errOut io.Writer, sources func(string, func(string, ...any)) enrich.Sources, now func() time.Time) int {
	logf := func(format string, a ...any) {
		_, _ = fmt.Fprintln(errOut, "[enrich] "+safelog.LineMax(fmt.Sprintf(format, a...), 2000))
	}
	fs := flag.NewFlagSet("cti-enrich", flag.ContinueOnError)
	fs.SetOutput(errOut)
	report := fs.String("report", "", "markdown report from cti-agent")
	cves := fs.String("cves", "", "comma-separated CVE list (scout lane)")
	out := fs.String("out", "", "output JSON path")
	noDB := fs.Bool("no-db", false, "skip the upsert into the memory database")
	skipNVD := fs.Bool("skip-nvd", false, "EPSS and KEV only (fast)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || (*report == "") == (*cves == "") || *out == "" {
		_, _ = fmt.Fprintln(errOut, usage)
		return 2
	}

	home := fleetHome()
	state := filepath.Join(home, "state")
	t := now()
	o := enrich.Options{Report: *report, SkipNVD: *skipNVD, Today: t.UTC(), Now: t, Logf: logf,
		FirstSeen: func() (map[string]string, bool, error) { return firstSeen(state) }}
	if *cves != "" {
		o.CVEs = strings.Split(*cves, ",")
	}
	res, err := enrich.Run(o, sources(state, logf))
	if err != nil {
		logf("error: %v", err)
		return 1
	}
	if n := res.Novelty.Undetermined; n > 0 {
		logf("novelty: unknown for %d finding(s) - no findings database yet, so the first run cannot distinguish new from old", n)
	} else {
		logf("novelty: %d new, %d seen before", res.Novelty.New, res.Novelty.SeenBefore)
	}

	abs, err := filepath.Abs(*out)
	if err != nil {
		logf("error: --out: %v", err)
		return 1
	}
	products := filepath.Join(filepath.Dir(abs), enrich.ProductsFile)
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		logf("error: --out: %v", err)
		return 1
	}
	if err := enrich.SaveProducts(products, res, t); err != nil {
		// A missing product map costs a name in FLEET TICKETS, nothing else.
		logf("WARNING: could not update %s (%v)", products, err)
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		logf("error: %v", err)
		return 1
	}
	if err := writeFile(abs, b); err != nil {
		logf("error: --out: %v", err)
		return 1
	}
	var counts []string
	for _, p := range enrich.SevOrder {
		counts = append(counts, fmt.Sprintf("%s=%d", p, res.Counts[p]))
	}
	line := fmt.Sprintf("wrote %s  %s", *out, strings.Join(counts, " "))
	if len(res.Degraded) > 0 {
		line += "  DEGRADED: " + strings.Join(res.Degraded, ", ")
	}
	logf("%s", line)

	if !*noDB && len(res.Findings) > 0 {
		upsert(res.Findings, home, logf)
	}
	return 0
}

func fleetHome() string {
	if h := os.Getenv("FLEET_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "fleet")
}

// writeFile replaces path atomically, 0600 like the rest of the fleet's
// output, so a reader never sees half a file.
func writeFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// fleetDBCandidates is where fleet-db might be, most specific first:
// FLEET_CODE's bin/ on both layouts, FLEET_HOME's on the single-directory
// one, and beside this binary, since both are installed in bin/.
func fleetDBCandidates(home string) []string {
	var out []string
	if code := os.Getenv("FLEET_CODE"); code != "" {
		out = append(out, filepath.Join(code, "bin", "fleet-db"))
	}
	out = append(out, filepath.Join(home, "bin", "fleet-db"))
	if exe, err := os.Executable(); err == nil {
		out = append(out, filepath.Join(filepath.Dir(exe), "fleet-db"))
	}
	seen := map[string]bool{}
	var uniq []string
	for _, p := range out {
		if !seen[p] {
			seen[p] = true
			uniq = append(uniq, p)
		}
	}
	return uniq
}

func findFleetDB(home string) string {
	for _, p := range fleetDBCandidates(home) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// fleetDB runs fleet-db with fixed arguments. Its output is for this
// program, never a heartbeat's model, so it is not cleaned.
func fleetDB(path string, stdin io.Reader, stdout io.Writer, args ...string) error {
	// #nosec G204 -- path is a root-owned fleet-db found in the fleet's own
	// bin/ directories; the arguments are constants from this file.
	cmd := exec.Command(path, args...)
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CHECKIN_BEAT_ID=") {
			env = append(env, kv)
		}
	}
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, stdin, stdout, os.Stderr
	return cmd.Run()
}

// firstSeen asks fleet-db when it first stored each CVE. No memory.db yet
// is ok=false: the first run cannot tell new from old, and says so.
func firstSeen(state string) (map[string]string, bool, error) {
	if _, err := os.Stat(filepath.Join(state, "memory.db")); err != nil {
		return nil, false, nil
	}
	db := findFleetDB(filepath.Dir(state))
	if db == "" {
		return nil, false, errors.New("fleet-db not found")
	}
	var buf strings.Builder
	if err := fleetDB(db, nil, &buf, "findings"); err != nil {
		return nil, false, fmt.Errorf("fleet-db findings: %w", err)
	}
	var rows []struct {
		CVE       string  `json:"cve"`
		FirstSeen *string `json:"first_seen"`
	}
	if err := json.Unmarshal([]byte(buf.String()), &rows); err != nil {
		return nil, false, fmt.Errorf("fleet-db findings: %w", err)
	}
	seen := make(map[string]string, len(rows))
	for _, r := range rows {
		v := ""
		if r.FirstSeen != nil {
			v = *r.FirstSeen
		}
		seen[r.CVE] = v
	}
	return seen, true, nil
}

// upsert writes the findings to memory.db through fleet-db. Not finding it
// is loud: without the upsert there is no history, so nothing can tell a new
// CVE from one reported every day this week.
func upsert(rows []*enrich.Finding, home string, logf func(string, ...any)) {
	db := findFleetDB(home)
	if db == "" {
		logf("WARNING: fleet-db not found - findings were NOT written to memory.db, so 'new since last run' "+
			"cannot be computed. Looked in: %s", strings.Join(fleetDBCandidates(home), ", "))
		return
	}
	b, err := json.Marshal(rows)
	if err != nil {
		logf("db upsert failed (%v) - JSON is still on disk", err)
		return
	}
	err = fleetDB(db, strings.NewReader(string(b)), io.Discard, "finding", "upsert")
	var ee *exec.ExitError
	switch {
	case err == nil:
		logf("upserted %d findings to memory.db", len(rows))
	case errors.As(err, &ee) && ee.ExitCode() == 3:
		// Every valid row was written; fleet-db named each skipped one on
		// its stderr, which is ours.
		logf("upserted findings to memory.db, but fleet-db SKIPPED some rows (each is named above); " +
			"the rest are written - JSON is still on disk")
	case errors.As(err, &ee):
		logf("db upsert failed (exit %d) - JSON is still on disk", ee.ExitCode())
	default:
		logf("db upsert failed (%v) - JSON is still on disk", err)
	}
}
