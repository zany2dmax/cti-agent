package checkin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const guard = "/opt/cti-agent/bin/checkin-bash-guard"

func TestTheGuardMustBeWiredWithHooksOn(t *testing.T) {
	good := `{"disableAllHooks": false, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "` + guard + `"}]}]}}`
	if !GuardWired([]byte(good), guard) {
		t.Fatal("the installed settings were refused")
	}
	for name, s := range map[string]string{
		"hooks off":               strings.Replace(good, "false", "true", 1),
		"no disableAllHooks":      strings.Replace(good, `"disableAllHooks": false, `, "", 1),
		"0 is not false":          strings.Replace(good, "false", "0", 1),
		"another path":            strings.Replace(good, guard, guard+"x", 1),
		"not the Bash matcher":    strings.Replace(good, `"Bash"`, `"Edit"`, 1),
		"not a command hook":      strings.Replace(good, `"command", "command"`, `"prompt", "command"`, 1),
		"not JSON":                "{",
		"not an object":           "[]",
		"hooks the wrong shape":   `{"disableAllHooks": false, "hooks": []}`,
		"PreToolUse wrong shapes": `{"disableAllHooks": false, "hooks": {"PreToolUse": ["x", {"matcher": "Bash", "hooks": "x"}]}}`,
	} {
		if GuardWired([]byte(s), guard) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheSteeringAuditNamesEveryRiskyKey(t *testing.T) {
	d := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(d, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	settings := w("settings.json", `{"env": {"A": "1"}, "hooks": {}, "statusLine": "x", "apiKeyHelper": 0, "mcpServers": false}`)
	state := w("claude.json", `{"projects": {"/b": {"mcpServers": {"x": 1}}, "/a": {"allowedTools": ["Bash"]}, "/c": "x"}}`)
	broken := w("broken.json", `{`)
	list := w("list.json", `[1]`)
	link := filepath.Join(d, "link.json")
	if err := os.Symlink(settings, link); err != nil {
		t.Fatal(err)
	}
	got := SteeringProblems([]string{settings, state, broken, list, link, filepath.Join(d, "missing.json")})
	want := []string{
		settings + ": env is set",
		settings + ": statusLine is set",
		state + ": projects[/b].mcpServers is set",
		state + ": projects[/a].allowedTools is set",
		broken + ": cannot be read as JSON (JSONDecodeError)",
		list + ": not a JSON object",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if p := SteeringProblems([]string{w("clean.json", `{"theme": "dark"}`)}); len(p) != 0 {
		t.Errorf("a clean file: %v", p)
	}
}

func TestTrippedListsTheLimitsTheGuardEnforced(t *testing.T) {
	d := t.TempDir()
	for body, want := range map[string]string{
		`{"tripped": ["bash", 3, "board_write"]}`: "limit reached for bash, board_write",
		`{"tripped": []}`:                         "",
		`{"bash": 2}`:                             "",
		`{"tripped": null}`:                       "",
	} {
		p := filepath.Join(d, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := Tripped(p); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", body, got, err, want)
		}
	}
	// Unreadable is an error, which the runner reports as an anomaly.
	for _, body := range []string{`{`, `[1]`, `{"tripped": "bash"}`} {
		p := filepath.Join(d, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Tripped(p); err == nil {
			t.Errorf("%s: no error", body)
		}
	}
	if _, err := Tripped(filepath.Join(d, "missing.json")); err == nil {
		t.Error("a missing file: no error")
	}
}
