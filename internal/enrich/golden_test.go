package enrich

// The golden files in testdata were written by the Python enrich.py this
// package replaced, run on the same inputs (testdata/sources.json and the two
// reports). These tests hold the port to them: the same findings, keys,
// bands, rationale text, products, novelty and counts.
//
// One deliberate difference, corrected in golden-rich.json by hand: the
// Python split the subjects table on escaped pipes too, so it wrote the
// subject "Advisory: Log4j | again" as "Advisory: Log4j \". See
// TestASubjectKeepsItsPipes.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixtures struct {
	Today          string               `json:"today"`
	NVD            map[string]NVDEntry  `json:"nvd"`
	EPSS           map[string]EPSSEntry `json:"epss"`
	KEV            map[string]KEVEntry  `json:"kev"`
	FirstSeen      map[string]string    `json:"first_seen"`
	ProductsBefore map[string]string    `json:"products_before"`
}

func loadFixtures(t *testing.T) fixtures {
	t.Helper()
	var f fixtures
	readJSON(t, "testdata/sources.json", &f)
	return f
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if raw, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// stub answers as the Python harness's stubs did: the whole NVD cache, EPSS
// for the CVEs asked about, the whole KEV catalog.
type stub struct {
	nvd  map[string]NVDEntry
	epss map[string]EPSSEntry
	kev  map[string]KEVEntry
}

func (s stub) NVD([]string) map[string]NVDEntry {
	out := map[string]NVDEntry{}
	for k, v := range s.nvd {
		out[k] = v
	}
	return out
}

func (s stub) EPSS(cves []string) map[string]EPSSEntry {
	out := map[string]EPSSEntry{}
	for _, c := range cves {
		if e, ok := s.epss[c]; ok {
			out[c] = e
		}
	}
	return out
}

func (s stub) KEV() map[string]KEVEntry {
	out := map[string]KEVEntry{}
	for k, v := range s.kev {
		out[k] = v
	}
	return out
}

func day(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// generic decodes JSON with every number as a float64, for comparing two
// files by meaning: 10 and 10.0 are the same score.
func generic(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// keyOrder lists each finding's keys in the order they were written.
func keyOrder(t *testing.T, b []byte) [][]string {
	t.Helper()
	var top struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for _, f := range top.Findings {
		dec := json.NewDecoder(bytes.NewReader(f))
		var keys []string
		depth := 0
		for {
			tok, err := dec.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			switch v := tok.(type) {
			case json.Delim:
				if v == '{' || v == '[' {
					depth++
				} else {
					depth--
				}
			case string:
				if depth == 1 && dec.More() || depth == 1 {
					// A key is followed by its value; read it and skip it.
					keys = append(keys, v)
					var skip json.RawMessage
					if err := dec.Decode(&skip); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		out = append(out, keys)
	}
	return out
}

func diff(t *testing.T, name string, got, want any) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	g, _ := json.MarshalIndent(got, "", " ")
	w, _ := json.MarshalIndent(want, "", " ")
	gl, wl := strings.Split(string(g), "\n"), strings.Split(string(w), "\n")
	for i := 0; i < len(gl) || i < len(wl); i++ {
		var a, b string
		if i < len(gl) {
			a = gl[i]
		}
		if i < len(wl) {
			b = wl[i]
		}
		if a != b {
			lo := max(0, i-6)
			t.Fatalf("%s differs from the Python's output at line %d:\n got: %s\nwant: %s\ncontext (want):\n%s",
				name, i+1, a, b, strings.Join(wl[lo:min(len(wl), i+3)], "\n"))
		}
	}
	t.Fatalf("%s differs", name)
}

func TestRunMatchesThePython(t *testing.T) {
	fx := loadFixtures(t)
	full := stub{fx.NVD, fx.EPSS, fx.KEV}
	none := stub{map[string]NVDEntry{}, map[string]EPSSEntry{}, map[string]KEVEntry{}}
	empty, _ := filepath.Abs(filepath.Join(t.TempDir(), "empty.md"))
	if err := os.WriteFile(empty, []byte("# nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := func(m map[string]string) func() (map[string]string, bool, error) {
		return func() (map[string]string, bool, error) { return m, true, nil }
	}
	cases := []struct {
		name     string
		o        Options
		src      Sources
		before   map[string]string
		products bool // the Python wrote a products file
	}{
		{"rich", Options{Report: "testdata/report-rich.md", FirstSeen: seen(fx.FirstSeen)}, full, fx.ProductsBefore, true},
		{"degraded", Options{Report: "testdata/report-legacy.md"}, none, nil, false},
		{"cves", Options{CVEs: strings.Split("CVE-2021-44228, cve-2026-9110,bogus,CVE-2026-0826,CVE-2026-0826", ","),
			SkipNVD: true, FirstSeen: seen(map[string]string{})}, full, nil, true},
		{"empty", Options{Report: empty}, full, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var logs []string
			c.o.Today, c.o.Now = day(fx.Today), day(fx.Today)
			c.o.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
			res, err := Run(c.o, c.src)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.MarshalIndent(res, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			wantRaw, err := os.ReadFile("testdata/golden-" + c.name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			g := generic(t, got).(map[string]any)
			if g["generated"] != "2026-11-22T00:00:00+00:00" {
				t.Errorf("generated = %v", g["generated"])
			}
			delete(g, "generated")
			diff(t, c.name, g, generic(t, wantRaw))
			if !reflect.DeepEqual(keyOrder(t, got), keyOrder(t, wantRaw)) {
				t.Errorf("finding keys are in a different order:\n got %v\nwant %v", keyOrder(t, got), keyOrder(t, wantRaw))
			}

			dir := t.TempDir()
			path := filepath.Join(dir, ProductsFile)
			if c.before != nil {
				if err := saveCache(path, c.before, day("2026-01-01")); err != nil {
					t.Fatal(err)
				}
			}
			if err := SaveProducts(path, res, c.o.Now); err != nil {
				t.Fatal(err)
			}
			_, statErr := os.Stat(path)
			if !c.products {
				if statErr == nil {
					t.Fatal("wrote a products file the Python did not")
				}
				return
			}
			var gotP, wantP map[string]string
			if !loadCache(path, time.Hour, c.o.Now, &gotP) {
				t.Fatal("products file unreadable or not refreshed")
			}
			readJSON(t, "testdata/golden-"+c.name+"-products.json", &wantP)
			diff(t, c.name+" products", gotP, wantP)
		})
	}
}

func TestPrioritizeMatchesThePython(t *testing.T) {
	var cases []struct {
		In   map[string]any `json:"in"`
		P    string         `json:"p"`
		Why  string         `json:"why"`
		Days *int           `json:"days"`
	}
	readJSON(t, "testdata/golden-prioritize.json.gz", &cases)
	if len(cases) < 4000 {
		t.Fatalf("only %d cases", len(cases))
	}
	today := day("2026-11-22")
	for i, c := range cases {
		s := scoreInput{Status: c.In["status"].(string)}
		s.HostCount = int(numberValue(c.In["host_count"].(json.Number)))
		s.KEV = numberValue(c.In["kev"].(json.Number)) != 0
		if v, ok := c.In["epss"].(json.Number); ok {
			s.EPSS = numberValue(v)
		}
		if v, ok := c.In["cvss"].(json.Number); ok {
			s.CVSS = v
		}
		if v, ok := c.In["kev_due"].(string); ok {
			s.KEVDue = &v
		}
		if v, ok := c.In["ransomware"].(string); ok {
			s.Ransomware = &v
		}
		p, why, days := prioritize(s, today)
		if p != c.P || why != c.Why || !reflect.DeepEqual(days, c.Days) {
			t.Fatalf("case %d %v:\n got %s %q %v\nwant %s %q %v", i, c.In, p, why, ptr(days), c.P, c.Why, ptr(c.Days))
		}
	}
}

func ptr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func TestTitlesMatchThePython(t *testing.T) {
	var want map[string]string
	readJSON(t, "testdata/golden-titles.json", &want)
	for title, w := range want {
		if got := ProductFromTitle(title); got != w {
			t.Errorf("ProductFromTitle(%q) = %q, want %q", title, got, w)
		}
	}
}

func TestProductsMatchThePython(t *testing.T) {
	var cases []struct {
		In  map[string]any `json:"in"`
		Out [2]string      `json:"out"`
	}
	readJSON(t, "testdata/golden-products.json", &cases)
	str := func(v any) string { s, _ := v.(string); return s }
	for _, c := range cases {
		var cpe [][]string
		if list, ok := c.In["cpe_products"].([]any); ok {
			for _, p := range list {
				var pair []string
				if xs, ok := p.([]any); ok {
					for _, x := range xs {
						pair = append(pair, str(x))
					}
				}
				cpe = append(cpe, pair)
			}
		}
		var titles []string
		if list, ok := c.In["detection_titles"].([]any); ok {
			for _, x := range list {
				titles = append(titles, str(x))
			}
		}
		name, source := ProductFor(str(c.In["kev_vendor"]), str(c.In["kev_product"]), cpe, titles, str(c.In["provider"]))
		if name != c.Out[0] || source != c.Out[1] {
			t.Errorf("%v: got (%q, %q), want (%q, %q)", c.In, name, source, c.Out[0], c.Out[1])
		}
	}
}
