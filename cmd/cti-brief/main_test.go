package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/brief"
)

// The command-line runs the Python brief.py made (internal/brief/testdata):
// the same files beside the enriched one, the same arguments, the same exit
// code, output files and log lines.
func TestTheCommandMatchesThePython(t *testing.T) {
	raw, err := os.ReadFile("../../internal/brief/testdata/golden-cli.json.gz")
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
	var g struct {
		Cases []struct {
			Name    string            `json:"name"`
			Files   map[string]any    `json:"files"`
			Argv    []string          `json:"argv"`
			Env     map[string]string `json:"env"`
			RC      int               `json:"rc"`
			Stdout  string            `json:"stdout"`
			Stderr  string            `json:"stderr"`
			Outputs map[string]string `json:"outputs"`
		} `json:"cases"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 22, 6, 0, 5, 0, time.UTC)
	for _, c := range g.Cases {
		t.Run(c.Name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range c.Files {
				p := filepath.Join(dir, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				b, ok := content.(string)
				if !ok {
					j, err := json.Marshal(content)
					if err != nil {
						t.Fatal(err)
					}
					b = string(j)
				}
				if err := os.WriteFile(p, []byte(b), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := make([]string, len(c.Argv))
			for i, a := range c.Argv {
				args[i] = strings.ReplaceAll(a, "@T", dir)
			}
			env := brief.Env{Org: "Security"}
			if v, ok := c.Env["FLEET_ORG"]; ok {
				env.Org = v
			}
			var stdout, stderr bytes.Buffer
			env.Warn = func(s string) { stderr.WriteString(s + "\n") }
			rc := run(args, env, c.Env["TRIAGE_ENABLED"], now, &stdout, &stderr)
			if rc != c.RC {
				t.Fatalf("exit %d, want %d\n%s", rc, c.RC, stderr.String())
			}
			if got := strings.ReplaceAll(stdout.String(), dir, "@T"); got != c.Stdout {
				t.Errorf("stdout %q, want %q", got, c.Stdout)
			}
			if got := strings.ReplaceAll(stderr.String(), dir, "@T"); got != c.Stderr {
				t.Errorf("stderr %q, want %q", got, c.Stderr)
			}
			for rel, want := range c.Outputs {
				b, err := os.ReadFile(filepath.Join(dir, rel))
				if err != nil {
					t.Fatal(err)
				}
				if got := strings.ReplaceAll(string(b), dir, "@T"); got != want {
					i := 0
					for i < len(got) && i < len(want) && got[i] == want[i] {
						i++
					}
					t.Fatalf("%s differs at byte %d:\n got %q\nwant %q", rel, i, got[max(0, i-80):min(len(got), i+80)], want[max(0, i-80):min(len(want), i+80)])
				}
				if st, _ := os.Stat(filepath.Join(dir, rel)); st.Mode().Perm() != 0o600 {
					t.Errorf("%s mode %v, want 0600", rel, st.Mode().Perm())
				}
			}
		})
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"--daily", "--weekly", "--enriched", "x"}, {"--enriched", "x", "extra"}, {"--bogus"}} {
		var o, e bytes.Buffer
		if rc := run(args, brief.Env{}, "", time.Now(), &o, &e); rc != 2 {
			t.Errorf("%v: exit %d", args, rc)
		}
	}
	var o, e bytes.Buffer
	if rc := run([]string{"--enriched", filepath.Join(t.TempDir(), "none.json"), "--out", "x"}, brief.Env{}, "", time.Now(), &o, &e); rc != 1 {
		t.Errorf("a missing enriched file: exit %d", rc)
	}
}
