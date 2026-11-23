// cti-scout is the @scout lane: it polls vendor advisories and industry
// feeds for CVE IDs, sets aside the ones the fleet has already seen, and
// hands the new ones back to be run through the same lookup path as the
// mailbox's CVEs.
//
//	cti-scout --out /var/lib/cti-agent/state/scout-latest.json --days 3
//	cti-scout --out scout.json --feeds feeds.txt --print-new   # CVEs for cti-enrich --cves
//	cti-scout --out scout.json --no-db                         # read and record nothing
//
// It finds candidates. It never decides exposure: only the vulnerability
// lookup does that.
//
// The fleet's memory database is read and written through fleet-db, which
// owns the SQLite (`fleet-db scout known` and `fleet-db scout record`): this
// binary has no SQL in it. It replaced the Python scout.py flag for flag;
// the output file, the log lines and the rows it records are the same, and
// testdata/golden.json.gz holds what the Python wrote for the tests to
// compare.
//
// # SETTINGS
//
// FLEET_HOME (state/memory.db), FLEET_FEEDS (the feed list), FLEET_CODE
// (where fleet-db is), FLEET_USER_AGENT and GRAPH_MAILBOX (the agent the
// feeds see).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/fleetenv"
	"github.com/zany2dmax/cti-agent/internal/httpx"
	"github.com/zany2dmax/cti-agent/internal/pyjson"
	"github.com/zany2dmax/cti-agent/internal/safelog"
	"github.com/zany2dmax/cti-agent/internal/useragent"
)

// Product is the User-Agent token; GRAPH_MAILBOX is added as the contact.
const Product = "cti-agent-scout/1.0"

const maxFeedBytes = 10 * 1024 * 1024

const usage = "usage: cti-scout --out FILE [--feeds FILE] [--days N] [--print-new] [--no-db]"

// deps is what a run reaches outside itself, so the tests can stand in.
type deps struct {
	fetch func(url string, logf func(string, ...any)) []byte
	db    func(home string) (store, error) // nil store: no memory.db
	now   func() time.Time
}

// store is the memory database as cti-scout uses it.
type store interface {
	known() ([]string, error)
	record(rows []any) error
}

func main() {
	fleetenv.Load()
	client := httpx.New(30 * time.Second)
	ua := useragent.String(Product)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, deps{
		fetch: func(url string, logf func(string, ...any)) []byte { return fetch(client, ua, url, logf) },
		db:    openStore,
		now:   time.Now,
	}))
}

func fleetHome() string {
	if h := os.Getenv("FLEET_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "fleet")
}

type source struct {
	feed, title, link string
	published         *string
}

func run(args []string, stdout, stderr io.Writer, d deps) int {
	logf := func(format string, a ...any) {
		_, _ = fmt.Fprintln(stderr, "[scout] "+safelog.LineMax(fmt.Sprintf(format, a...), 4000))
	}
	home := fleetHome()
	defFeeds := os.Getenv("FLEET_FEEDS")
	if defFeeds == "" {
		defFeeds = filepath.Join(home, "lanes", "feeds.txt")
	}
	fs := flag.NewFlagSet("cti-scout", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "output JSON path (required)")
	feedsPath := fs.String("feeds", defFeeds, "the feed list")
	days := fs.Int("days", 3, "ignore entries older than this")
	printNew := fs.Bool("print-new", false, "print new CVEs comma-separated on stdout")
	noDB := fs.Bool("no-db", false, "do not read or write the memory database")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || *out == "" {
		_, _ = fmt.Fprintln(stderr, usage)
		return 2
	}

	// #nosec G703 -- the feed list is the operator's own --feeds or
	// FLEET_FEEDS; reading the file they name is the point.
	raw, err := os.ReadFile(*feedsPath)
	if err != nil {
		logf("no feed list at %s", *feedsPath)
		return 1
	}
	feeds := feedLines(string(raw))
	logf("polling %d feeds, window %dd", len(feeds), *days)

	var db store
	seen := map[string]bool{}
	if !*noDB {
		if db, err = d.db(home); err != nil {
			logf("error: %v", err)
			return 1
		}
		if db != nil {
			known, err := db.known()
			if err != nil {
				logf("error: %v", err)
				return 1
			}
			for _, c := range known {
				seen[strings.ToUpper(c)] = true
			}
			logf("%d CVEs already known", len(seen))
		}
	}

	cutoff := d.now().UTC().Add(-time.Duration(*days) * 24 * time.Hour)
	hits := map[string][]source{}
	var order []string // the order CVEs were first seen, as the Python's dict
	var failed []string
	ok := 0
	for _, url := range feeds {
		body := d.fetch(url, logf)
		if body == nil {
			failed = append(failed, url)
			continue
		}
		items := parseFeed(body, url, logf)
		if len(items) == 0 {
			failed = append(failed, url)
			continue
		}
		ok++
		for _, it := range items {
			if it.Published != nil {
				if pub := parseDate(*it.Published); pub != nil && pub.utc().Before(cutoff) {
					continue
				}
			}
			once := map[string]bool{}
			for _, c := range findCVEs(it.Text) {
				c = strings.ToUpper(c)
				if once[c] {
					continue
				}
				once[c] = true
				if _, ok := hits[c]; !ok {
					order = append(order, c)
				}
				hits[c] = append(hits[c], source{url, it.Title, it.Link, it.Published})
			}
		}
	}

	all := append([]string(nil), order...)
	sort.Strings(all)
	newCVEs := []string{}
	for _, c := range all {
		if !seen[c] {
			newCVEs = append(newCVEs, c)
		}
	}
	logf("%d/%d feeds ok, %d failed, %d CVEs mentioned, %d new", ok, len(feeds), len(failed), len(hits), len(newCVEs))
	if len(failed) > 0 {
		hosts := make([]string, len(failed))
		for i, f := range failed {
			if hosts[i] = netloc(f); hosts[i] == "" {
				hosts[i] = f
			}
		}
		logf("failed feeds (a silently dead feed is a blind spot): %s", strings.Join(hosts, ", "))
	}

	if db != nil {
		// Every CVE mentioned, new or not, with up to three of its sources:
		// that record is what makes it not new on the next run.
		var rows []any
		for _, c := range order {
			srcs := hits[c]
			for _, s := range srcs[:min(len(srcs), 3)] {
				o := pyjson.NewObject()
				o.Set("cve", c)
				o.Set("feed", s.feed)
				o.Set("title", s.title)
				o.Set("link", s.link)
				o.Set("published", strPtr(s.published))
				rows = append(rows, o)
			}
		}
		if err := db.record(rows); err != nil {
			logf("db record failed: %v", err)
		}
	}

	res := pyjson.NewObject()
	res.Set("generated", d.now().UTC().Format("2006-01-02T15:04:05+00:00"))
	res.Set("feeds_polled", len(feeds))
	res.Set("feeds_ok", ok)
	res.Set("feeds_failed", strList(failed))
	res.Set("window_days", *days)
	res.Set("new_cves", strList(newCVEs))
	res.Set("all_mentioned", strList(all))
	detail := []any{}
	for _, c := range newCVEs {
		srcs := []any{}
		for _, s := range hits[c] {
			o := pyjson.NewObject()
			o.Set("feed", s.feed)
			o.Set("title", s.title)
			o.Set("link", s.link)
			o.Set("published", strPtr(s.published))
			srcs = append(srcs, o)
		}
		rec := pyjson.NewObject()
		rec.Set("cve", c)
		rec.Set("sources", srcs)
		detail = append(detail, rec)
	}
	res.Set("detail", detail)
	if err := writeFile(*out, []byte(pyjson.Dumps(res, pyjson.Options{EnsureASCII: true, Indent: 2}))); err != nil {
		logf("error: could not write %s: %v", *out, err)
		return 1
	}
	logf("wrote %s", *out)
	if *printNew {
		_, _ = fmt.Fprintln(stdout, strings.Join(newCVEs, ","))
	}
	return 0
}

func strPtr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func strList(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// feedLines is the feed list: one URL a line, stripped; blank lines and
// lines starting with # (in the first column) are skipped.
func feedLines(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	var out []string
	for _, l := range strings.SplitAfter(raw, "\n") {
		if s := pyStrip(l); s != "" && !strings.HasPrefix(l, "#") {
			out = append(out, s)
		}
	}
	return out
}

// netloc is urlparse(u).netloc: the host part of scheme://host/path.
func netloc(u string) string {
	i := strings.Index(u, ":")
	if i <= 0 || !strings.HasPrefix(u[i+1:], "//") {
		return ""
	}
	for j, c := range u[:i] {
		alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !alpha && (j == 0 || !strings.ContainsRune("0123456789+-.", c)) {
			return ""
		}
	}
	rest := u[i+3:]
	if k := strings.IndexAny(rest, "/?#"); k >= 0 {
		rest = rest[:k]
	}
	return rest
}

// fetch reads one feed, https only: feeds.txt is an operator's file, and a
// plain http:// feed could be altered in transit into advisory text. httpx
// refuses a redirect off https too. Every failure is logged and is nil.
func fetch(client *http.Client, ua, url string, logf func(string, ...any)) []byte {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		logf("FEED FAIL %s :: not an https URL (plain http feeds are refused)", url)
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logf("FEED FAIL %s :: %v", url, err)
		return nil
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml, */*")
	resp, err := client.Do(req)
	if err != nil {
		logf("FEED FAIL %s :: %v", url, err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		logf("FEED FAIL %s :: HTTP Error %d: %s", url, resp.StatusCode, http.StatusText(resp.StatusCode))
		return nil
	}
	// A feed is a few hundred KB; a hostile or broken server could stream
	// without end. One byte over the cap means refuse it.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		logf("FEED FAIL %s :: %v", url, err)
		return nil
	}
	if len(body) > maxFeedBytes {
		logf("FEED FAIL %s :: larger than %d MB", url, maxFeedBytes/1024/1024)
		return nil
	}
	return body
}

// writeFile replaces path atomically, 0600 like the rest of the fleet's
// output, creating its directory.
func writeFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".scout-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ---- the memory database, through fleet-db ----

type fleetDB struct{ path string }

// openStore is nil when there is no memory.db: the lane never creates it
// (fleet-db would, on connecting), so a first run counts every CVE as new
// and records nothing, as the Python lane did.
func openStore(home string) (store, error) {
	if _, err := os.Stat(filepath.Join(home, "state", "memory.db")); err != nil {
		return nil, nil
	}
	for _, p := range fleetDBCandidates(home) {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return fleetDB{p}, nil
		}
	}
	return nil, errors.New("memory.db is there but fleet-db is not found")
}

// fleetDBCandidates is where fleet-db might be, most specific first:
// FLEET_CODE's bin/, FLEET_HOME's, and beside this binary.
func fleetDBCandidates(home string) []string {
	var out []string
	if code := os.Getenv("FLEET_CODE"); code != "" {
		out = append(out, filepath.Join(code, "bin", "fleet-db"))
	}
	out = append(out, filepath.Join(home, "bin", "fleet-db"))
	if exe, err := os.Executable(); err == nil {
		out = append(out, filepath.Join(filepath.Dir(exe), "fleet-db"))
	}
	return out
}

func (f fleetDB) cmd(stdin io.Reader, stdout io.Writer, args ...string) error {
	// #nosec G204 -- path is a root-owned fleet-db found in the fleet's own
	// bin/ directories; the arguments are constants from this file.
	c := exec.Command(f.path, args...)
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		// Not a heartbeat's output: fleet-db must not clean it for a model.
		if !strings.HasPrefix(kv, "CHECKIN_BEAT_ID=") {
			env = append(env, kv)
		}
	}
	c.Env, c.Stdin, c.Stdout, c.Stderr = env, stdin, stdout, os.Stderr
	return c.Run()
}

func (f fleetDB) known() ([]string, error) {
	var b strings.Builder
	if err := f.cmd(nil, &b, "scout", "known"); err != nil {
		return nil, fmt.Errorf("fleet-db scout known: %w", err)
	}
	return strings.Fields(b.String()), nil
}

func (f fleetDB) record(rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	in := strings.NewReader(pyjson.Dumps(rows, pyjson.Options{}))
	if err := f.cmd(in, io.Discard, "scout", "record"); err != nil {
		return fmt.Errorf("fleet-db scout record: %w", err)
	}
	return nil
}
