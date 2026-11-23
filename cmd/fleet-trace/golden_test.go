package main

// testdata/golden.json.gz was written by the Python fleet-trace this
// replaced: tee over stream-json with every event shape the CLI writes and
// many it should not (minimal and full, CRLF, bad UTF-8, a --max-mb cut),
// unwrap on good and bad replies, show and list over a directory of
// traces, prune, init and every usage error. The Go must produce the same
// output, the same trace lines and the same exit codes.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var goldenNow = time.Date(2026, 11, 22, 6, 0, 0, 0, time.UTC)

type golden struct {
	Tee []struct {
		Name, Keep, Stdin, Stdout, Stderr string
		RC                                int
		Plain                             *string
		Trace                             []any
		TraceLen                          int `json:"trace_len"`
		TraceLast                         any `json:"trace_last"`
	}
	Unwrap []struct {
		Name                  string
		Trace                 bool
		Stdin, Stdout, Stderr string
		RC                    int
		Result                *string
		Lines                 []any
	}
	Show, List []struct {
		Argv           []string
		RC             int
		Stdout, Stderr string
		Empty          bool
	}
	Prune []struct {
		RC     int
		Stdout string
		Left   []string
	}
	Usage []struct {
		Argv           []string
		RC             int
		Stdout, Stderr string
	}
	Init []struct {
		RC     int
		Stdout string
		Mode   string
	}
}

func loadGolden(t *testing.T) golden {
	t.Helper()
	raw, err := os.ReadFile("testdata/golden.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if raw, err = io.ReadAll(zr); err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g
}

func latin1(s string) []byte {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = append(b, byte(r))
	}
	return b
}

func newApp(home string, stdin []byte) (*app, *bytes.Buffer, *bytes.Buffer) {
	var o, e bytes.Buffer
	return &app{traceDir: filepath.Join(home, "state", "traces"), stdin: bytes.NewReader(stdin), stdout: &o, stderr: &e,
		now: func() time.Time { return goldenNow }}, &o, &e
}

// traceLines reads a trace as the golden has it: parsed, the header's
// start time masked.
func traceLines(t *testing.T, path string) []any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []any
	for _, l := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var v any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("trace line is not JSON: %q", l)
		}
		if m, ok := v.(map[string]any); ok && m["type"] == "fleet_trace" && m["started"] != nil {
			m["started"] = "<time>"
		}
		out = append(out, v)
	}
	return out
}

func same(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, _ := json.MarshalIndent(got, "", " ")
		w, _ := json.MarshalIndent(want, "", " ")
		t.Fatalf("%s:\n got %s\nwant %s", what, g, w)
	}
}

func TestTeeMatchesThePython(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Tee {
		t.Run(c.Name+"/"+c.Keep, func(t *testing.T) {
			home := t.TempDir()
			tr := filepath.Join(home, "state", "traces")
			if err := os.MkdirAll(tr, 0o700); err != nil {
				t.Fatal(err)
			}
			out, plain := filepath.Join(tr, "checkin-20261122T060000.jsonl"), filepath.Join(home, "plain.txt")
			args := []string{"tee", "--out", out, "--plain", plain, "--keep", c.Keep}
			switch c.Name {
			case "truncated":
				out, plain = filepath.Join(home, "t.jsonl"), filepath.Join(home, "p.txt")
				args = []string{"tee", "--out", out, "--plain", plain, "--max-mb", "1"}
			case "cannot-create":
				out, plain = filepath.Join(home, "t.jsonl"), filepath.Join(home, "no", "p")
				if err := os.WriteFile(out, []byte("old\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				args = []string{"tee", "--out", out, "--plain", plain}
			}
			if c.Name != "cannot-create" {
				if err := os.WriteFile(plain, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			a, o, e := newApp(home, latin1(c.Stdin))
			rc := a.run(args)
			stdout := strings.ReplaceAll(o.String(), home, "@H")
			stderr := strings.ReplaceAll(e.String(), home, "@H")
			if rc != c.RC || stdout != c.Stdout || stderr != c.Stderr {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nwant:\n%s\nstderr: %q want %q", rc, c.RC, stdout, c.Stdout, stderr, c.Stderr)
			}
			if c.Plain != nil {
				got, _ := os.ReadFile(plain)
				if string(got) != *c.Plain {
					t.Fatalf("plain:\n%q\nwant:\n%q", got, *c.Plain)
				}
			}
			switch c.Name {
			case "truncated":
				lines := traceLines(t, out)
				if len(lines) != c.TraceLen {
					t.Fatalf("%d trace lines, want %d (the cut is in a different place)", len(lines), c.TraceLen)
				}
				same(t, "last line", lines[len(lines)-1], c.TraceLast)
			case "cannot-create":
				got, _ := os.ReadFile(out)
				if string(got) != c.Trace[0] {
					t.Fatalf("an existing --out was written to: %q", got)
				}
			default:
				same(t, "trace", traceLines(t, out), c.Trace)
			}
		})
	}
}

func TestUnwrapMatchesThePython(t *testing.T) {
	g := loadGolden(t)
	for _, c := range g.Unwrap {
		name := c.Name
		if c.Trace {
			name += "/trace"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			res, trp := filepath.Join(home, "answer.txt"), filepath.Join(home, "supplier-20261122T070000.jsonl")
			args := []string{"unwrap", "--result", res}
			if c.Trace {
				args = append(args, "--trace", trp)
			}
			a, o, e := newApp(home, []byte(c.Stdin))
			rc := a.run(args)
			if c.Trace && c.Name == "ok" {
				a2, _, _ := newApp(home, []byte(c.Stdin))
				a2.run([]string{"unwrap", "--result", res + "2", "--trace", trp})
			}
			stderr := strings.ReplaceAll(e.String(), home, "@H")
			if rc != c.RC || o.String() != c.Stdout || stderr != c.Stderr {
				t.Fatalf("exit %d %q %q, want %d %q %q", rc, o.String(), stderr, c.RC, c.Stdout, c.Stderr)
			}
			got, err := os.ReadFile(res)
			if (c.Result == nil) != (err != nil) || (c.Result != nil && string(got) != *c.Result) {
				t.Fatalf("result %q %v, want %v", got, err, c.Result)
			}
			same(t, "trace", traceLines(t, trp), c.Lines)
		})
	}
}

// The directory the Python's show and list read, rebuilt the same way.
func showDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	tr := filepath.Join(home, "state", "traces")
	if err := os.MkdirAll(tr, 0o700); err != nil {
		t.Fatal(err)
	}
	g := loadGolden(t)
	var rich, results string
	for _, c := range g.Tee {
		if c.Name == "rich" && c.Keep == "full" {
			rich = string(latin1(c.Stdin))
		}
		if c.Name == "results" && c.Keep == "full" {
			results = strings.ReplaceAll(string(latin1(c.Stdin)), "\r\n", "\n")
		}
	}
	put := func(n, body string) {
		if err := os.WriteFile(filepath.Join(tr, n), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("checkin-20261120T060000.jsonl", rich)
	put("checkin-20261121T060000.jsonl", results)
	put("supplier-20261121T070000.jsonl", `{"type": "fleet_trace", "unit": "supplier"}`+"\n"+
		`{"type": "result", "total_cost_usd": 0.5, "num_turns": 1}`+"\n"+
		`{"type": "result", "total_cost_usd": 0.25, "num_turns": 2, "is_error": true, "permission_denials": [{}]}`+"\n")
	put("supplier-20261121T070000-2.jsonl", `{"type": "result", "total_cost_usd": 7, "num_turns": true}`+"\n")
	put("checkin-20261122T060000.jsonl", `{"type": "fleet_trace"}`+"\ngarbage\n")
	put("other.jsonl", `{"type": "result"}`+"\n")
	if err := os.Mkdir(filepath.Join(tr, "checkin-20261123T060000.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tr, "checkin-20261120T060000.jsonl"), filepath.Join(tr, "checkin-20261124T060000.jsonl")); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestShowAndListMatchThePython(t *testing.T) {
	g := loadGolden(t)
	for _, c := range append(append([]struct {
		Argv           []string
		RC             int
		Stdout, Stderr string
		Empty          bool
	}{}, g.Show...), g.List...) {
		t.Run(strings.Join(c.Argv, " "), func(t *testing.T) {
			home := t.TempDir()
			if !c.Empty {
				home = showDir(t)
			}
			args := make([]string, len(c.Argv))
			for i, x := range c.Argv {
				args[i] = strings.ReplaceAll(x, "@H", home)
			}
			a, o, e := newApp(home, nil)
			rc := a.run(args)
			stdout := strings.ReplaceAll(o.String(), home, "@H")
			stderr := strings.ReplaceAll(e.String(), home, "@H")
			if rc != c.RC || stdout != c.Stdout {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nwant:\n%s", rc, c.RC, stdout, c.Stdout)
			}
			if strings.Contains(c.Stderr, "Traceback") {
				// Python crashed on a malformed event; Go stops at the same
				// place with a message.
				if !strings.Contains(stderr, "is not an event this program can show") {
					t.Fatalf("stderr %q", stderr)
				}
			} else if stderr != c.Stderr {
				t.Fatalf("stderr %q, want %q", stderr, c.Stderr)
			}
		})
	}
}

func TestPruneInitAndUsageMatchThePython(t *testing.T) {
	g := loadGolden(t)
	// The Python pruned in the show/list directory, beside its recent traces.
	home := showDir(t)
	tr := filepath.Join(home, "state", "traces")
	for n, age := range map[string]int{"checkin-20261101T060000.jsonl": 40, "supplier-20261102T060000.jsonl": 31, "checkin-20261119T060000.jsonl": 3} {
		p := filepath.Join(tr, n)
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		when := goldenNow.Add(-time.Duration(age) * 24 * time.Hour)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatal(err)
		}
	}
	a, o, _ := newApp(home, nil)
	if rc := a.run([]string{"prune", "--days", "30"}); rc != g.Prune[0].RC || o.String() != g.Prune[0].Stdout {
		t.Fatalf("prune: %d %q", rc, o.String())
	}
	entries, _ := os.ReadDir(tr)
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	same(t, "left after prune", left, g.Prune[0].Left)

	home2 := t.TempDir()
	a, o, _ = newApp(home2, nil)
	if rc := a.run([]string{"init"}); rc != g.Init[0].RC || strings.ReplaceAll(o.String(), home2, "@H") != g.Init[0].Stdout {
		t.Fatalf("init: %d %q", rc, o.String())
	}
	if st, _ := os.Stat(filepath.Join(home2, "state", "traces")); st.Mode().Perm() != 0o700 {
		t.Errorf("trace directory mode %v", st.Mode().Perm())
	}

	for _, c := range g.Usage {
		a, o, e := newApp("/nonexistent-home", nil)
		rc := a.run(c.Argv)
		if rc != c.RC || o.String() != c.Stdout || e.String() != c.Stderr {
			t.Errorf("%v: exit %d %q %q\nwant %d %q %q", c.Argv, rc, o.String(), e.String(), c.RC, c.Stdout, c.Stderr)
		}
	}
}
