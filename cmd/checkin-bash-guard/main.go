// checkin-bash-guard refuses shell syntax on a heartbeat's Bash calls.
//
// Claude Code runs this before every Bash call the heartbeat makes (a
// PreToolUse hook in $FLEET_CODE/checkin-settings.json). The beat's grant is a
// list of prefix rules such as `$FLEET_CODE/bin/fleet-timers:*`. Those name
// the command, not the shell around it: if a prefix rule ever matched
// `fleet-timers > state/budget.json`, every grant would be an arbitrary file
// write as the service account, and `cmd $(other)` would run something that
// was never granted. Whether Claude Code's matcher already refuses each of
// those is its business; this makes the answer not depend on it.
//
// So a beat's command may be one granted command with plain arguments: no
// redirection, pipes, chaining, background jobs, line breaks, and no
// expansion of any kind outside single quotes - not $(...), not ${...}, and
// not plain $NAME either (the beat's process carries fleet.env, so
// `fleet-board say @all INFO $CLIENT_SECRET` would put a credential on the
// board). Those operators are refused where bash would act on them, which is
// outside quotes: inside quotes ; & | < > are plain characters, so a message
// may say "done; nothing new". Globs and ~ are refused outside quotes, and so
// is a leading NAME=value. Double-quoted text is still checked for $, because
// bash expands it there, and a backtick or a line break is refused anywhere.
// A backslash outside single quotes and an unbalanced quote are refused:
// either one moves where bash thinks a quote ends.
//
// Behind the syntax rules (PrimeSec design review 39260):
//
//   - ARGUMENT POLICY (Scenario-223): the arguments each granted command may
//     take, as static data in this root-owned binary the beat cannot edit
//     (policy.go). A command not in the table, a flag not in its row, or a
//     value outside its rule is refused.
//   - PER-BEAT LIMITS (Scenario-224): run-checkin gives each beat an id
//     (CHECKIN_BEAT_ID). The guard counts the beat's calls under
//     $FLEET_HOME/state/checkin-counts and refuses one once the beat has made
//     more than its share: all calls, alerts, board writes, database writes,
//     with limits from CHECKIN_MAX_*. Without a beat id nothing is counted.
//
// Exit 2 blocks the call, and the message goes back to the model. ANY
// failure - unreadable input, a crash - also exits 2: a guard that fails open
// is not a guard.
//
// It replaced the Python checkin-bash-guard, verdict for verdict: the Go
// tests hold it to the Python's answers on several hundred calls.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/layout"
	"github.com/zany2dmax/cti-agent/internal/pyfmt"
)

func main() {
	argv0 := os.Args[0]
	if abs, err := filepath.Abs(argv0); err == nil {
		argv0 = abs
	}
	os.Exit(run(os.Stdin, os.Stderr, os.Getenv, argv0))
}

func run(stdin io.Reader, stderr io.Writer, getenv func(string) string, argv0 string) (code int) {
	reason := ""
	defer func() {
		// Fail closed on anything, a panic included.
		if r := recover(); r != nil {
			reason = fmt.Sprintf("could not read the hook input (%v)", r)
			code = 2
			_, _ = fmt.Fprintf(stderr, "checkin-bash-guard: %s\n", reason)
		}
	}()
	g := guard{getenv: getenv, binDirs: map[string]bool{filepath.Dir(argv0): true, filepath.Join(layout.CodeDir, "bin"): true}}
	raw, err := io.ReadAll(stdin)
	switch {
	case err != nil:
		reason = "could not read the hook input (OSError)"
	case !utf8.Valid(raw):
		// Python read stdin with surrogate escapes, so bad bytes reached
		// the JSON parser and failed there.
		reason = "could not read the hook input (JSONDecodeError)"
	default:
		var event any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&event); err != nil || dec.More() {
			reason = "could not read the hook input (JSONDecodeError)"
		} else {
			reason = g.verdict(event)
		}
	}
	if reason == "" {
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "checkin-bash-guard: %s\n", reason)
	return 2
}

type guard struct {
	getenv  func(string) string
	binDirs map[string]bool
}

var assignment = regexp.MustCompile(`^\s*[A-Za-z_][A-Za-z0-9_]*=`)

const (
	forbiddenAnywhere = "`\n\r"
	forbiddenUnquoted = "$"
	forbiddenBare     = "<>|;&*?[~{}()#"
)

// expandable walks the command the way bash reads quotes and returns the
// characters bash would read outside single quotes, those outside every
// quote, and a problem: a backslash outside single quotes, or an unbalanced
// quote. A regex for single-quoted spans once took the ' inside "'" as the
// start of one and hid $(id) between two of them (PrimeSec 10969091).
func expandable(cmd string) (seen, bare []rune, problem string) {
	var quote rune
	for _, c := range cmd {
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			return seen, bare, "a backslash outside single quotes"
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				seen = append(seen, c)
			}
		case c == '\'' || c == '"':
			quote = c
		default:
			seen = append(seen, c)
			bare = append(bare, c)
		}
	}
	if quote != 0 {
		return seen, bare, "an unbalanced quote"
	}
	return seen, bare, ""
}

// found is the characters of set that appear in text, sorted, once each.
func found(set string, text []rune) []string {
	in := map[rune]bool{}
	for _, c := range text {
		if strings.ContainsRune(set, c) {
			in[c] = true
		}
	}
	var out []rune
	for c := range in {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	s := make([]string, len(out))
	for i, c := range out {
		s[i] = string(c)
	}
	return s
}

// repr is Python's repr(s)[1:-1]: the string escaped, without its quotes.
func repr(s string) string {
	r := pyfmt.ReprString(s)
	return r[1 : len(r)-1]
}

func (g guard) verdict(event any) string {
	ev, ok := event.(map[string]any)
	if !ok {
		return "hook input is not a JSON object"
	}
	if ev["tool_name"] != "Bash" {
		return ""
	}
	input := ev["tool_input"]
	if truthy(input) {
		if _, ok := input.(map[string]any); !ok {
			return "could not read the hook input (AttributeError)"
		}
	}
	m, _ := input.(map[string]any)
	cmd, ok := m["command"].(string)
	if !ok {
		return "Bash call has no command string"
	}
	runes := []rune(cmd)
	bad := found(forbiddenAnywhere, runes)
	seen, bare, problem := expandable(cmd)
	bad = append(bad, found(forbiddenUnquoted, seen)...)
	bad = append(bad, found(forbiddenBare, bare)...)
	if problem != "" {
		bad = append(bad, problem)
	}
	if assignment.MatchString(cmd) {
		bad = append(bad, "NAME=value prefix")
	}
	if over := g.count("bash"); over != "" {
		return over
	}
	if len(bad) > 0 {
		shown := make([]string, len(bad))
		for i, b := range bad {
			shown[i] = repr(b)
		}
		return "shell syntax is not allowed on a beat (" + strings.Join(shown, " ") + "). Run one " +
			"granted command with plain arguments; reword text that needs these characters."
	}
	why, kind := g.policyVerdict(cmd)
	if why != "" {
		return why + ". A beat may run only the granted commands with the arguments their rules allow."
	}
	if kind != "" {
		return g.count(kind)
	}
	return ""
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case json.Number:
		f, err := x.Float64()
		return err != nil || f != 0
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// split is shlex.split(cmd) for a command that has passed the syntax walk:
// words separated by spaces and tabs, quotes removed, ” an empty word. No
// backslash or unbalanced quote reaches it.
func split(cmd string) []string {
	var out []string
	var word strings.Builder
	inWord := false
	var quote rune
	for _, c := range cmd {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if inWord {
				out = append(out, word.String())
				word.Reset()
				inWord = false
			}
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, word.String())
	}
	return out
}

// policyVerdict is (reason to refuse, "") or ("", the per-beat counter the
// call belongs to, or "").
func (g guard) policyVerdict(cmd string) (string, string) {
	tokens := split(cmd)
	if len(tokens) == 0 {
		return "empty command", ""
	}
	exe, args := tokens[0], tokens[1:]
	dir, name := pathSplit(exe)
	pol, ok := policy[name]
	if !g.binDirs[dir] || !ok {
		return short(exe) + " is not a command a beat may run", ""
	}
	if bad := pol(args); bad != "" {
		return name + ": " + bad, ""
	}
	switch {
	case name == "cti-alert" && contains(args, "--for-real"):
		return "", "alert"
	case name == "fleet-board" && args[0] == "say":
		return "", "board_write"
	case name == "fleet-db" && (args[0] == "remember" || args[0] == "task" || args[0] == "mail" || args[0] == "ack"):
		if args[0] == "task" && len(args) == 2 && args[1] == "list" {
			return "", ""
		}
		if args[0] == "mail" && len(args) > 1 && args[1] == "inbox" {
			return "", ""
		}
		return "", "db_write"
	}
	return "", ""
}

// pathSplit is os.path.split: the head keeps no trailing slash unless it is
// all slashes, so "a//b" is ("a", "b") and "/b" is ("/", "b").
func pathSplit(p string) (string, string) {
	i := strings.LastIndex(p, "/") + 1
	head, tail := p[:i], p[i:]
	if head != strings.Repeat("/", len(head)) {
		head = strings.TrimRight(head, "/")
	}
	return head, tail
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// syslogWarn logs a refusal to the journal, best effort: the refusal does not
// depend on it.
func syslogWarn(msg string) {
	w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_AUTH, "checkin-bash-guard")
	if err != nil {
		return
	}
	_ = w.Warning(msg)
	_ = w.Close()
}
