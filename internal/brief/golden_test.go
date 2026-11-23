package brief

// The golden files in testdata were written by the Python brief.py this
// package replaced (subject, HTML and text, daily and weekly, for 22
// digests; and 9 command-line runs). These tests hold the port to them byte
// for byte.
//
// One deliberate difference, corrected in golden-render.json.gz by hand: the
// Python put the counts and KEV deadline numbers into the HTML unescaped. Go
// escapes them (internal/renderguard requires it). For a real number that
// changes nothing; only the "hostile" case, whose worst_overdue_days is
// markup, differs.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

var goldenNow = time.Date(2026, 11, 22, 6, 0, 5, 0, time.UTC)

func readGolden(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
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
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		t.Fatal(err)
	}
}

func envOf(m map[string]any, warn func(string)) Env {
	e := Env{Org: "Security", Warn: warn}
	if v, ok := m["FLEET_ORG"].(string); ok {
		e.Org = v
	}
	e.Attribution, _ = m["FLEET_ATTRIBUTION"].(string)
	e.RepoURL, _ = m["FLEET_REPO_URL"].(string)
	return e
}

// firstDiff says where two long strings part, with some context.
func firstDiff(t *testing.T, what, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	lo := max(0, i-120)
	t.Fatalf("%s differs from the Python's at byte %d:\n got: %q\nwant: %q", what, i,
		got[lo:min(len(got), i+120)], want[lo:min(len(want), i+120)])
}

func TestRenderMatchesThePython(t *testing.T) {
	var g struct {
		Cases []struct {
			Name string         `json:"name"`
			Env  map[string]any `json:"env"`
			Data map[string]any `json:"data"`
			Out  map[string]struct {
				Subject, HTML, Text, Stderr string
			} `json:"out"`
		} `json:"cases"`
	}
	readGolden(t, "testdata/golden-render.json.gz", &g)
	if len(g.Cases) < 20 {
		t.Fatalf("only %d cases", len(g.Cases))
	}
	for _, c := range g.Cases {
		for _, kind := range []string{"daily", "weekly"} {
			want := c.Out[kind]
			t.Run(c.Name+"/"+kind, func(t *testing.T) {
				var warned strings.Builder
				env := envOf(c.Env, func(s string) { warned.WriteString(s + "\n") })
				firstDiff(t, "subject", Subject(c.Data, kind, goldenNow), want.Subject)
				firstDiff(t, "html", Render(c.Data, kind, goldenNow, env), want.HTML)
				firstDiff(t, "text", RenderText(c.Data, kind, goldenNow, env), want.Text)
				firstDiff(t, "stderr", warned.String(), want.Stderr)
			})
		}
	}
}
