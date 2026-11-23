package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/sanitize"
)

type logged struct {
	source string
	events []sanitize.Event
}

func filter(t *testing.T, args []string, in string) (out, errOut string, code int, got logged) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(in), &o, &e, func(s string, ev []sanitize.Event) {
		got = logged{s, ev}
	})
	return o.String(), e.String(), code, got
}

// The shared cases internal/sanitize is tested against, run through the
// command end to end: what the wrappers pipe in is what the beat reads.
func TestTheFilterCleansByTheSharedCases(t *testing.T) {
	b, err := os.ReadFile("../../internal/sanitize/testdata/sanitize-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, Input, Output string
		Changed             int
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 10 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			out, errOut, code, got := filter(t, []string{"--source", "test"}, c.Input)
			if code != 0 || out != c.Output {
				t.Fatalf("code %d, out %q, want %q", code, out, c.Output)
			}
			if errOut != "" {
				t.Fatalf("wrote to stderr, which goes to the model: %q", errOut)
			}
			if len(got.events) != c.Changed {
				t.Fatalf("logged %d changed line(s), want %d", len(got.events), c.Changed)
			}
		})
	}
}

// A run of invalid bytes becomes one replacement character, as the Python
// filter did. JSON cannot carry invalid UTF-8, so this case is not shared.
func TestInvalidBytesBecomeOneReplacementCharacter(t *testing.T) {
	out, _, code, _ := filter(t, nil, "a\xff\xfe\xfdb\n")
	if code != 0 || out != "a\uFFFDb\n" {
		t.Fatalf("code %d, out %q", code, out)
	}
}

func TestTheSourceNameCannotForgeALogLine(t *testing.T) {
	cases := map[string]string{
		"fleet-board":                  "fleet-board",
		"x\ny: line 1 stripped":        "xyline1stripped",
		"$(rm -rf /)":                  "rm-rf",
		"":                             "unknown",
		"\u0000\u001b":                 "unknown",
		strings.Repeat("a", 60):        strings.Repeat("a", 40),
		"caf\u00e9.db_1":               "caf.db_1",
		"\u202eevil":                   "evil",
		"fleet-journal --source other": "fleet-journal--sourceother",
	}
	for in, want := range cases {
		_, _, _, got := filter(t, []string{"--source", in}, "\x1b\n")
		if got.source != want {
			t.Errorf("source %q logged as %q, want %q", in, got.source, want)
		}
	}
}

func TestAnythingButOneSourceIsAUsageError(t *testing.T) {
	for _, args := range [][]string{{"--source"}, {"--help"}, {"--source", "a", "b"}, {"-s", "a"}} {
		out, errOut, code, _ := filter(t, args, "text\n")
		if code != 2 || out != "" || !strings.Contains(errOut, "usage: cti-sanitize") {
			t.Errorf("%v: code %d, out %q, err %q", args, code, out, errOut)
		}
	}
	if _, _, code, got := filter(t, nil, "\x1b\n"); code != 0 || got.source != "unknown" {
		t.Errorf("no arguments: code %d, source %q", code, got.source)
	}
}

// Past maxInput the rest of stdin is read and dropped, so the producer is
// never blocked, and the output still says it was cut.
func TestHugeInputIsDrainedAndCut(t *testing.T) {
	in := strings.Repeat(strings.Repeat("x", 100)+"\n", (maxInput/101)+1000)
	r := strings.NewReader(in)
	var o bytes.Buffer
	code := run(nil, r, &o, &bytes.Buffer{}, func(string, []sanitize.Event) {})
	if code != 0 || r.Len() != 0 {
		t.Fatalf("code %d, %d bytes left unread", code, r.Len())
	}
	if o.Len() > sanitize.MaxTotal+100 || !strings.Contains(o.String(), "[output cut: more than") {
		t.Fatalf("output %d bytes, no cut notice", o.Len())
	}
}
