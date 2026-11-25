package main

// testdata/golden.json.gz was written by the Python checkin-bash-guard this
// replaced: its exit code and message for several hundred calls (every
// granted command with good and bad arguments, every syntax character in
// and out of each kind of quote, odd hook input) and for nine sequences of
// calls in one beat against the per-beat counter. The Go guard must give the
// same answer to every one.
//
// One deliberate change since: the ten cases that call cti-mailer, cti-jira,
// cti-appreport, cti-domains or cti-vmscan expect a refusal ("not a command a
// beat may run") since 2026-11-25, when the credential checks moved to their
// own unit (run-credcheck) and off the beat's grant. Every other case is the
// Python's answer, unchanged. The same day the cases that call
// cti-patchtuesday or cti-mailbox (their --dry-run previews, dropped from the
// grant for the secrets they put in the beat's unit) were changed the same
// way, refusals only.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The Python ran from the repository, so its own directory was a granted one
// alongside /opt/cti-agent/bin; the corpus uses only the latter.
const goldenArgv0 = "/nonexistent/fleet-kit/fleet/bin/checkin-bash-guard"

type call struct {
	Stdin  string            `json:"stdin"`
	Cmd    string            `json:"cmd"`
	Env    map[string]string `json:"env"`
	RC     int               `json:"rc"`
	Stderr string            `json:"stderr"`
}

func loadGolden(t *testing.T) (cases []call, seqs []struct {
	Name   string            `json:"name"`
	Env    map[string]string `json:"env"`
	Calls  []call            `json:"calls"`
	Counts any               `json:"counts"`
}) {
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
	var g struct {
		Cases []call `json:"cases"`
		Seqs  []struct {
			Name   string            `json:"name"`
			Env    map[string]string `json:"env"`
			Calls  []call            `json:"calls"`
			Counts any               `json:"counts"`
		} `json:"seqs"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	return g.Cases, g.Seqs
}

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestEveryVerdictMatchesThePython(t *testing.T) {
	cases, _ := loadGolden(t)
	if len(cases) < 250 {
		t.Fatalf("only %d cases", len(cases))
	}
	for i, c := range cases {
		var e bytes.Buffer
		stdin := []byte(c.Stdin)
		if c.Stdin == "\u00ff" {
			stdin = []byte{0xff}
		}
		rc := run(bytes.NewReader(stdin), &e, envFunc(c.Env), goldenArgv0)
		if rc != c.RC || e.String() != c.Stderr {
			t.Errorf("case %d %q:\n got %d %q\nwant %d %q", i, c.Stdin, rc, e.String(), c.RC, c.Stderr)
		}
	}
}

func TestTheCounterMatchesThePython(t *testing.T) {
	_, seqs := loadGolden(t)
	for _, s := range seqs {
		t.Run(s.Name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "state", "checkin-counts")
			prep := map[string]string{"corrupt-list": `[1]`, "bad-number": `{"bash": "x", "tripped": "no"}`,
				"bad-json": `{`, "tripped-not-list": `{"bash": 20, "tripped": "x"}`}
			beats := map[string]string{"corrupt-list": "b5", "bad-number": "b6", "bad-json": "b7", "tripped-not-list": "b8"}
			if body, ok := prep[s.Name]; ok {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, beats[s.Name]+".json"), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			// As the harness did: the case's settings, then FLEET_HOME.
			env := map[string]string{}
			for k, v := range s.Env {
				env[k] = v
			}
			env["FLEET_HOME"] = home
			for i, c := range s.Calls {
				payload, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": c.Cmd}})
				var e bytes.Buffer
				rc := run(bytes.NewReader(payload), &e, envFunc(env), goldenArgv0)
				if rc != c.RC || e.String() != c.Stderr {
					t.Fatalf("call %d %q:\n got %d %q\nwant %d %q", i, c.Cmd, rc, e.String(), c.RC, c.Stderr)
				}
			}
			beat := s.Env["CHECKIN_BEAT_ID"]
			if beat == "" {
				beat = "x"
			}
			raw, err := os.ReadFile(filepath.Join(dir, beat+".json"))
			if s.Counts == nil {
				if err == nil {
					t.Fatalf("wrote a counter file the Python did not: %s", raw)
				}
				return
			}
			if m, ok := s.Counts.(map[string]any); ok && m["unparsed"] != nil {
				unparsed := m["unparsed"]
				if string(raw) != unparsed {
					t.Fatalf("counter file %q, want it left as %q", raw, unparsed)
				}
				return
			}
			var got any
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(s.Counts)
			if string(g) != string(w) {
				t.Fatalf("counts %s, want %s", g, w)
			}
		})
	}
}

// A beat id with nowhere to count is refused, not waved through.
func TestABeatWithNoHomeIsRefused(t *testing.T) {
	payload := `{"tool_name": "Bash", "tool_input": {"command": "/opt/cti-agent/bin/fleet-board read"}}`
	var e bytes.Buffer
	rc := run(bytes.NewReader([]byte(payload)), &e, envFunc(map[string]string{"CHECKIN_BEAT_ID": "b1"}), goldenArgv0)
	if rc != 2 || e.String() != "checkin-bash-guard: the beat's counter is not configured\n" {
		t.Fatalf("%d %q", rc, e.String())
	}
}
