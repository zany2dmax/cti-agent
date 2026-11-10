package sanitize

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type tcase struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	Output  string `json:"output"`
	Changed int    `json:"changed"`
}

func TestSharedCases(t *testing.T) {
	b, err := os.ReadFile("testdata/sanitize-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []tcase
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		out, ev := Text(c.Input)
		if out != c.Output || len(ev) != c.Changed {
			t.Errorf("%s: got %q with %d changed line(s), want %q with %d", c.Name, out, len(ev), c.Output, c.Changed)
		}
	}
}

func TestTheWholeOutputIsCapped(t *testing.T) {
	in := strings.Repeat("0123456789\n", MaxTotal/10)
	out, ev := Text(in)
	if len(out) > MaxTotal+80 || !strings.Contains(out, "[output cut:") || len(ev) == 0 {
		t.Errorf("len %d, events %d, tail %q", len(out), len(ev), out[len(out)-60:])
	}
}

func TestRunCleansOnlyInsideABeat(t *testing.T) {
	t.Setenv("CHECKIN_BEAT_ID", "")
	called := false
	if code := Run("x", func() int { called = true; return 3 }); code != 3 || !called {
		t.Fatalf("outside a beat Run must just call fn: %d %v", code, called)
	}
	if ForBeat() {
		t.Error("ForBeat is true without a beat id")
	}
	t.Setenv("CHECKIN_BEAT_ID", "beat-1")
	if !ForBeat() {
		t.Error("ForBeat is false inside a beat")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	real := os.Stdout
	os.Stdout = f
	code := Run("x", func() int { _, _ = os.Stdout.WriteString("a\x1b[31mb\nc\n"); return 0 })
	os.Stdout = real
	_ = f.Close()
	got, _ := os.ReadFile(f.Name())
	if code != 0 || string(got) != "a[31mb\nc\n" {
		t.Errorf("code %d, output %q", code, got)
	}
}
