// Package shellgate catches one specific shell bug, in the fleet's own
// scripts, before it reaches a box.
//
// # THE BUG
//
//	V="$(grep -E "^KEY=" file | tail -1 | cut -d= -f2-)"
//
// Under `set -e` this ends the script whenever the key is absent: grep exits 1
// when it matches nothing, `set -o pipefail` carries that 1 to the end of the
// pipeline even though tail and cut succeeded, the assignment therefore fails,
// and the shell exits. Without pipefail the bare form `V="$(grep ... file)"`
// does the same thing on its own.
//
// It exits SILENTLY. No message, no trace, and an operator running it by hand
// sees only their prompt return.
//
// # WHY A GATE RATHER THAN CARE
//
// This shipped three times in this repository and was found only by its
// consequences:
//
//   - install-fedora.sh read four optional FLEET_* keys this way. The first box
//     whose fleet.env predated the Patch Tuesday lane exited four lines after
//     printing "daemon-reload", with 400 lines left. No wrapper update, no
//     version manifest, no verification - and the tail of the output was
//     indistinguishable from a successful install.
//   - check_path in the same file read config the same way, which made its own
//     "KEY is unset" diagnostic unreachable: a missing key killed the script one
//     line before the branch that reported missing keys.
//   - scrub-history.sh counted matching blobs with `git grep -l ... | wc -l`.
//     git grep exits 1 on zero matches, and zero matches is the SUCCESS case,
//     so a fully scrubbed history aborted the verification instead of passing
//     it.
//
// All three are the project's recurring failure shape: something reported
// success while doing nothing. The shape is not detectable by reading, because
// the broken line looks exactly like the correct one. So it gets a gate.
//
// # THE FIX, WHICHEVER FITS
//
//	v="$(sed -n "s/^KEY=//p" file | tail -1)"   # sed exits 0 on no match
//	n=$({ git grep -l "$p" || true; } | wc -l)  # rescue just the grep
//	if grep -q KEY file; then ...               # a condition, not an assignment
package shellgate

import (
	"fmt"
	"strings"
)

// Finding is one suspect line.
type Finding struct {
	File string
	Line int
	Text string
	Why  string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s\n    %s", f.File, f.Line, f.Why, strings.TrimSpace(f.Text))
}

// searchers exit non-zero on "found nothing", which is the whole problem.
// `wc`, `sort` and friends do not, so they are not listed.
var searchers = []string{"grep", "egrep", "fgrep", "rg", "ag"}

// rescued are the idioms that make a non-zero status harmless.
var rescued = []string{"|| true", "||true", "|| :", "||:", "|| echo", "|| printf"}

// conditional contexts, where a non-zero status is the POINT and `set -e` is
// explicitly suspended by the shell.
var conditional = []string{"if ", "elif ", "while ", "until ", "case ", "return ", "! "}

// Scan reports lines in a single script that can end it silently.
//
// Only scripts that actually set -e are examined: the same line in a script
// without it is merely a variable that ends up empty, which is a different and
// much smaller problem.
func Scan(name, content string) []Finding {
	lines := strings.Split(content, "\n")
	if !setsErrexit(lines) {
		return nil
	}

	var out []Finding
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if hasAny(line, rescued) || startsWithAny(line, conditional) {
			continue
		}
		// `[ -n "$(grep ...)" ]` and `x && y` are condition contexts too.
		if strings.HasPrefix(line, "[") || strings.Contains(line, "] &&") {
			continue
		}
		sub, ok := substitution(line)
		if !ok || !containsCommand(sub, searchers) {
			continue
		}
		// A substitution used as a command's ARGUMENT dies with that command
		// rather than on its own, and the caller usually handles it. The
		// dangerous form is an assignment, where the failing status becomes the
		// status of the assignment itself.
		if !assignsSubstitution(line) {
			continue
		}
		out = append(out, Finding{
			File: name, Line: i + 1, Text: raw,
			Why: "assignment from a search command - it exits non-zero when it " +
				"finds nothing, and `set -e` will end the script there, silently",
		})
	}
	return out
}

func setsErrexit(lines []string) bool {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "set -") {
			continue
		}
		// -e, -eu, -euo pipefail: the flag letters run together.
		flags, _, _ := strings.Cut(strings.TrimPrefix(l, "set -"), " ")
		if strings.ContainsRune(flags, 'e') {
			return true
		}
	}
	return false
}

// substitution returns the contents of the first balanced $( ... ) on the line.
func substitution(line string) (string, bool) {
	start := strings.Index(line, "$(")
	if start < 0 {
		return "", false
	}
	depth := 0
	for i := start + 1; i < len(line); i++ {
		switch line[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return line[start+2 : i], true
			}
		}
	}
	return "", false
}

// assignsSubstitution reports whether any statement on the line assigns a
// command substitution.
//
// Per statement, not per line, because the shape that made check_path's own
// "KEY is unset" branch unreachable was two statements on one line:
//
//	local cur; cur="$(grep -E "^$1=" "$CONF_DIR/fleet.env" | tail -1)"
//
// The leading token there is `local`, so a whole-line test sees no assignment
// and waves it through - which is precisely the line that needed catching.
func assignsSubstitution(line string) bool {
	for _, stmt := range strings.Split(line, ";") {
		stmt = strings.TrimSpace(stmt)
		if strings.Contains(stmt, "$(") && isAssignment(stmt) {
			return true
		}
	}
	return false
}

// isAssignment reports whether the line's leading token is NAME= or
// `local NAME=` / `export NAME=` style, which is where the status leaks.
func isAssignment(line string) bool {
	for _, p := range []string{"local ", "export ", "declare ", "readonly ", "typeset "} {
		if strings.HasPrefix(line, p) {
			line = strings.TrimSpace(strings.TrimPrefix(line, p))
		}
	}
	eq := strings.Index(line, "=")
	if eq <= 0 {
		return false
	}
	name := line[:eq]
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9' && i > 0)
		if !ok {
			return false
		}
	}
	return true
}

// containsCommand reports whether any name appears as a command word, so that
// a variable called `grepped` or a path like /usr/bin/foo-grep-bar does not
// masquerade as one.
func containsCommand(s string, names []string) bool {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '|' || r == ';' || r == '\n' || r == '&'
	}) {
		fields := strings.Fields(f)
		// Skip a `git` / `sudo` / `command` prefix: `git grep` is a searcher.
		for len(fields) > 1 && (fields[0] == "git" || fields[0] == "sudo" ||
			fields[0] == "command" || fields[0] == "LC_ALL=C") {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		cmd := fields[0]
		if i := strings.LastIndex(cmd, "/"); i >= 0 {
			cmd = cmd[i+1:]
		}
		for _, n := range names {
			if cmd == n {
				return true
			}
		}
	}
	return false
}

func hasAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func startsWithAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
