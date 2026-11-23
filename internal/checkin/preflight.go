package checkin

// The three file checks run-checkin makes around a beat. They were python3
// heredocs in the runner; the rules are the same.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
)

// GuardWired reports whether the beat's --settings file runs guard as its
// Bash PreToolUse hook, with hooks switched on. The guard is a hook, and a
// hook whose command does not exist fails OPEN, so the settings must name it
// at this box's own path. disableAllHooks must be present and false.
func GuardWired(settings []byte, guard string) bool {
	var s map[string]any
	if json.Unmarshal(settings, &s) != nil {
		return false
	}
	if v, ok := s["disableAllHooks"].(bool); !ok || v {
		return false
	}
	hooks, _ := s["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	for _, x := range pre {
		m, ok := x.(map[string]any)
		if !ok || m["matcher"] != "Bash" {
			continue
		}
		hs, _ := m["hooks"].([]any)
		for _, y := range hs {
			if h, ok := y.(map[string]any); ok && h["type"] == "command" && h["command"] == guard {
				return true
			}
		}
	}
	return false
}

// risky are the settings keys that would matter if a later Claude Code
// loaded a file the beat cannot see: hooks, permissions, MCP servers, env,
// helper commands, plugins.
var risky = []string{"hooks", "permissions", "mcpServers", "enabledMcpjsonServers",
	"enableAllProjectMcpServers", "env", "apiKeyHelper", "awsAuthRefresh",
	"awsCredentialExport", "otelHeadersHelper", "statusLine",
	"enabledPlugins", "extraKnownMarketplaces", "allowedTools"}

// unset is a value that sets nothing: null, false, zero, "", [] or {}.
func unset(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case json.Number:
		f, err := x.Float64()
		return err == nil && f == 0
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

// readError names why a file could not be read, as the audit always has.
func readError(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError"
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	case errors.Is(err, syscall.EISDIR):
		return "IsADirectoryError"
	case errors.As(err, &se), errors.As(err, &te), errors.Is(err, errUnexpectedEnd):
		return "JSONDecodeError"
	case errors.Is(err, errNotUTF8):
		return "UnicodeDecodeError"
	}
	return "OSError"
}

var (
	errNotUTF8       = errors.New("not UTF-8")
	errUnexpectedEnd = errors.New("unexpected end of JSON input")
)

// SteeringProblems audits Claude Code's own config files in the service
// account's reach (settings.json, .claude.json): one line per file that
// cannot be read as a JSON object, and per risky key set at the top level or
// under any projects[...] entry. A path that does not exist is skipped, and a
// file reached twice (a symlink) is read once.
func SteeringProblems(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, path := range paths {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path // a dangling link is still audited, by its own name
		}
		if abs, err := filepath.Abs(real); err == nil {
			real = abs
		}
		if seen[real] {
			continue
		}
		if _, err := os.Lstat(path); err != nil {
			continue
		}
		seen[real] = true
		// #nosec G304 -- fixed config paths under the service account's HOME.
		raw, err := os.ReadFile(path)
		if err == nil && !utf8.Valid(raw) {
			err = errNotUTF8
		}
		var data any
		if err == nil {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if derr := dec.Decode(&data); derr != nil {
				err = derr
				if derr.Error() == "EOF" || strings.Contains(derr.Error(), "unexpected EOF") {
					err = errUnexpectedEnd
				}
			}
		}
		if err != nil {
			out = append(out, fmt.Sprintf("%s: cannot be read as JSON (%s)", path, readError(err)))
			continue
		}
		top, ok := data.(map[string]any)
		if !ok {
			out = append(out, path+": not a JSON object")
			continue
		}
		type scope struct {
			where string
			d     map[string]any
		}
		scopes := []scope{{"", top}}
		if projects, ok := top["projects"].(map[string]any); ok {
			for _, k := range objectKeys(raw, "projects") {
				if v, ok := projects[k].(map[string]any); ok {
					scopes = append(scopes, scope{"projects[" + k + "].", v})
				}
			}
		}
		for _, s := range scopes {
			for _, key := range risky {
				if !unset(s.d[key]) {
					out = append(out, fmt.Sprintf("%s: %s%s is set", path, s.where, key))
				}
			}
		}
	}
	return out
}

// objectKeys is the keys of the object at top-level key name, in the order
// the file has them, so the audit lists projects as the file does.
func objectKeys(raw []byte, name string) []string {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(top[name]))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return keys
		}
		k, _ := t.(string)
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return keys
		}
		if !seen[k] { // a repeated key: the last value wins, at the first place
			seen[k] = true
			keys = append(keys, k)
		}
	}
	return keys
}

// Tripped is the limits the guard enforced during a beat, from its counter
// file: "limit reached for bash, alert", or "" for a beat that tripped none.
// A file that cannot be read is an error, which the runner reports as an
// anomaly: a beat whose counts are unknown is not a quiet beat.
func Tripped(path string) (string, error) {
	// #nosec G304 -- the runner passes the beat's own counter file.
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return "", err
	}
	var t []string
	switch x := d["tripped"].(type) {
	case nil:
	case []any:
		for _, v := range x {
			if s, ok := v.(string); ok {
				t = append(t, s)
			}
		}
	default:
		if !unset(x) {
			return "", fmt.Errorf("tripped is not a list")
		}
	}
	if len(t) == 0 {
		return "", nil
	}
	return "limit reached for " + strings.Join(t, ", "), nil
}
