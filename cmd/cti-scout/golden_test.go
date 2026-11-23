package main

// testdata/golden.json.gz is what the Python scout.py did with the same
// input: how it read 49 dates, which of 17 bodies it took for HTML, the items
// it read from each feed and what it logged, and five whole runs (the output
// file, standard output and error, and the rows recorded). The Go port must
// do the same. Where the Python's message came from expat ("malformed XML ::
// no element found: line 1, column 65") only the prefix is compared: Go's
// parser words its errors its own way.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/pyjson"
)

type goldenFeed struct {
	Raw   string `json:"raw"`
	Items []struct {
		Title     string  `json:"title"`
		Link      string  `json:"link"`
		Published *string `json:"published"`
		Text      string  `json:"text"`
	} `json:"items"`
	Log string `json:"log"`
}

type goldenRun struct {
	Name   string   `json:"name"`
	Argv   []string `json:"argv"`
	RC     int      `json:"rc"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
	Result string   `json:"result"`
	Rows   [][]any  `json:"rows"`
}

type golden struct {
	FeedList string                `json:"feedlist"`
	Unescape map[string]string     `json:"unescape"`
	CVEs     map[string][]string   `json:"cves"`
	Dates    map[string]*string    `json:"dates"`
	HTML     map[string]bool       `json:"html"`
	Feeds    map[string]goldenFeed `json:"feeds"`
	Runs     []goldenRun           `json:"runs"`
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "golden.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.NewDecoder(zr).Decode(&g); err != nil {
		t.Fatal(err)
	}
	return g
}

// latin1 turns the golden's text back into the bytes the Python was given.
func latin1(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r))
	}
	return b
}

var expatMsg = regexp.MustCompile(`(malformed XML :: ).*`)

func normLog(s string) string { return expatMsg.ReplaceAllString(s, "${1}*") }

func TestMain(m *testing.M) {
	// The golden was made with TZ=UTC: a date without a zone is local time.
	time.Local = time.UTC
	os.Exit(m.Run())
}

func TestUnescapeAndCVEsMatchPython(t *testing.T) {
	g := loadGolden(t)
	if len(g.Unescape) < 30 || len(g.CVEs) < 20 {
		t.Fatalf("golden has %d escapes, %d CVE strings", len(g.Unescape), len(g.CVEs))
	}
	for in, want := range g.Unescape {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q, Python %q", in, got, want)
		}
	}
	for in, want := range g.CVEs {
		got := findCVEs(in)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("findCVEs(%q) = %q, Python %q", in, got, want)
		}
	}
}

func TestDatesMatchPython(t *testing.T) {
	g := loadGolden(t)
	if len(g.Dates) < 40 {
		t.Fatalf("golden has %d dates", len(g.Dates))
	}
	for in, want := range g.Dates {
		got := parseDate(in)
		switch {
		case want == nil && got != nil:
			t.Errorf("parseDate(%q) = %s, Python read nothing", in, got.isoformat())
		case want != nil && got == nil:
			t.Errorf("parseDate(%q) = nothing, Python read %s", in, *want)
		case want != nil && got.isoformat() != *want:
			t.Errorf("parseDate(%q) = %s, Python read %s", in, got.isoformat(), *want)
		}
	}
}

func TestFeedsMatchPython(t *testing.T) {
	g := loadGolden(t)
	for name, f := range g.Feeds {
		raw := latin1(f.Raw)
		if got := looksLikeHTML(raw); got != g.HTML[name] {
			t.Errorf("%s: looksLikeHTML = %v, Python %v", name, got, g.HTML[name])
		}
		var log strings.Builder
		items := parseFeed(raw, "https://example.com/"+name, func(format string, a ...any) {
			log.WriteString("[scout] " + sprintf(format, a...) + "\n")
		})
		if normLog(log.String()) != normLog(f.Log) {
			t.Errorf("%s: logged\n%q\nPython logged\n%q", name, log.String(), f.Log)
		}
		if len(items) != len(f.Items) {
			t.Errorf("%s: %d items, Python %d", name, len(items), len(f.Items))
			continue
		}
		for i, w := range f.Items {
			got := items[i]
			if got.Title != w.Title || got.Link != w.Link || got.Text != w.Text || !samePtr(got.Published, w.Published) {
				t.Errorf("%s item %d:\n got  %q %q %v %q\n want %q %q %v %q", name, i,
					got.Title, got.Link, deref(got.Published), got.Text, w.Title, w.Link, deref(w.Published), w.Text)
			}
		}
	}
}

func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

func samePtr(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

func deref(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// fakeStore is scout_items and the findings CVEs, as fleet-db keeps them.
type fakeStore struct {
	seen []string
	rows [][]any
}

func (f *fakeStore) known() ([]string, error) {
	out := append([]string(nil), f.seen...)
	for _, r := range f.rows {
		out = append(out, r[0].(string))
	}
	return out, nil
}

func (f *fakeStore) record(rows []any) error {
	var in []map[string]any
	if err := json.Unmarshal([]byte(pyjson.Dumps(rows, pyjson.Options{})), &in); err != nil {
		return err
	}
	for _, r := range in {
		dup := false
		for _, have := range f.rows {
			if have[0] == r["cve"] && have[1] == r["feed"] {
				dup = true
			}
		}
		if !dup {
			f.rows = append(f.rows, []any{r["cve"], r["feed"], r["title"], r["link"], r["published"], float64(0), "2026-11-22T12:00:00+00:00"})
		}
	}
	return nil
}

func TestRunsMatchPython(t *testing.T) {
	g := loadGolden(t)
	bodies := map[string][]byte{}
	for name, f := range g.Feeds {
		bodies["https://example.com/"+name] = latin1(f.Raw)
	}
	// The database each Python run started with.
	start := map[string]func() *fakeStore{
		"with-db": func() *fakeStore {
			return &fakeStore{seen: []string{"cve-2026-1234"},
				rows: [][]any{{"CVE-2026-1300", "https://example.com/atom", "old", "", nil, float64(0), "then"}}}
		},
		"no-findings-table": func() *fakeStore { return &fakeStore{} },
	}
	start["no-db-flag"] = start["with-db"]
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	for _, r := range g.Runs {
		t.Run(r.Name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("FLEET_HOME", home)
			feeds := filepath.Join(home, "feeds.txt")
			if err := os.WriteFile(feeds, []byte(g.FeedList), 0o600); err != nil {
				t.Fatal(err)
			}
			var db *fakeStore
			if mk := start[r.Name]; mk != nil {
				db = mk()
			}
			out := filepath.Join(home, "out", "scout.json")
			var stdout, stderr bytes.Buffer
			args := append([]string{"--out", out, "--feeds", feeds}, r.Argv...)
			rc := run(args, &stdout, &stderr, deps{
				fetch: func(url string, logf func(string, ...any)) []byte {
					if !strings.HasPrefix(url, "https://") {
						logf("FEED FAIL %s :: not an https URL (plain http feeds are refused)", url)
						return nil
					}
					return bodies[url]
				},
				db: func(string) (store, error) {
					if db == nil {
						return nil, nil
					}
					return db, nil
				},
				now: func() time.Time { return now },
			})
			if rc != r.RC {
				t.Errorf("exit %d, Python %d", rc, r.RC)
			}
			if stdout.String() != r.Stdout {
				t.Errorf("stdout %q, Python %q", stdout.String(), r.Stdout)
			}
			gotErr := normLog(strings.ReplaceAll(stderr.String(), home, "@H"))
			if gotErr != normLog(r.Stderr) {
				t.Errorf("stderr:\n%s\nPython:\n%s", gotErr, r.Stderr)
			}
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			// The file, byte for byte but for the time it was made.
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got["generated"] != "2026-11-22T12:00:00+00:00" {
				t.Errorf("generated = %v", got["generated"])
			}
			gen := regexp.MustCompile(`\n  "generated": "[^"]*",`)
			if s := gen.ReplaceAllString(string(data), ""); s != r.Result {
				t.Errorf("output:\n%s\nPython:\n%s", s, r.Result)
			}
			if r.Rows != nil {
				rows := db.rows
				sort.Slice(rows, func(i, j int) bool {
					if rows[i][0] != rows[j][0] {
						return rows[i][0].(string) < rows[j][0].(string)
					}
					return rows[i][1].(string) < rows[j][1].(string)
				})
				a, _ := json.Marshal(rows)
				b, _ := json.Marshal(r.Rows)
				if string(a) != string(b) {
					t.Errorf("rows:\n%s\nPython:\n%s", a, b)
				}
			}
		})
	}
}
