// Package sanitize cleans what a command prints before the orchestrator's
// model reads it (PrimeSec design review 39260, Scenario-222).
//
// # WHY
//
// A heartbeat reads the journal, the board, the memory database and a
// handful of reports, and most of that text started life in somebody else's
// mail or feed: a subject line, an advisory title, a product name. Text the
// model reads is text that can try to steer it. Control characters are the
// cheap tool for that (an escape sequence can hide a line from the person
// auditing the trace while the model still reads it, a carriage return can
// overwrite what a line seemed to say), and an enormous single line is the
// cheap way to bury the real content. So every command whose output the beat
// reads passes through this, and only for the beat: a lane that parses the
// same output (fleet-db rollup, say) is left exactly as it was.
//
// # WHAT IT DOES
//
//   - removes control characters other than newline and tab, the C1
//     controls, bidirectional overrides and zero-width characters;
//   - cuts any line over MaxLine runes and says how much it cut;
//   - cuts the whole output at MaxTotal bytes and says so;
//   - logs every line it changed to the journal (never to stderr: stderr goes
//     back into the model), with the first 80 printable characters so an
//     operator can see what the attempt looked like.
//
// The Python twin is fleet-kit/fleet/bin/fleet-sanitize. Both read the same
// cases from testdata/sanitize-cases.json, so they cannot drift.
package sanitize

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"os"
	"os/exec"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits. A line longer than MaxLine is cut; output longer than MaxTotal is
// cut. Tab and newline are the only control characters that survive.
const (
	MaxLine    = 1024
	MaxTotal   = 64 * 1024
	maxLogged  = 20
	excerptLen = 80
)

// Event describes one line that was changed.
type Event struct {
	Line    int
	Removed int    // characters removed or cut
	Cut     bool   // the line was cut for length
	Excerpt string // first printable characters of the cleaned line
}

func removable(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case unicode.IsControl(r): // C0, DEL and C1
		return true
	// Format characters (soft hyphen, zero width, bidi controls and isolates,
	// the Arabic letter mark, interlinear annotation, the invisible math
	// operators and the whole tag block that can hide text a person cannot
	// see), and the line and paragraph separators.
	case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
		return true
	case r >= 0xe0100 && r <= 0xe01ef: // variation selectors supplement
		return true
	case r == 0x115f, r == 0x1160, r == 0x3164, r == 0xffa0: // Hangul fillers
		return true
	}
	return false
}

// Text cleans s and reports what it changed.
func Text(s string) (string, []Event) {
	var out strings.Builder
	var events []Event
	lines := strings.Split(strings.ToValidUTF8(s, "�"), "\n")
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r") // a CRLF line end is not an attack
		var b strings.Builder
		removed := 0
		for _, r := range line {
			if removable(r) {
				removed++
				continue
			}
			b.WriteRune(r)
		}
		clean := b.String()
		cut := false
		if n := utf8.RuneCountInString(clean); n > MaxLine {
			runes := []rune(clean)
			clean = string(runes[:MaxLine]) + fmt.Sprintf(" [cut %d chars]", n-MaxLine)
			removed += n - MaxLine
			cut = true
		}
		if removed > 0 {
			ex := []rune(clean)
			if len(ex) > excerptLen {
				ex = ex[:excerptLen]
			}
			events = append(events, Event{Line: i + 1, Removed: removed, Cut: cut, Excerpt: string(ex)})
		}
		out.WriteString(clean)
		if i < len(lines)-1 {
			out.WriteByte('\n')
		}
	}
	res := out.String()
	if len(res) > MaxTotal {
		cut := MaxTotal
		for cut > 0 && !utf8.RuneStart(res[cut]) {
			cut--
		}
		dropped := len(res) - cut
		res = res[:cut] + fmt.Sprintf("\n[output cut: more than %d bytes]\n", MaxTotal)
		events = append(events, Event{Line: 0, Removed: dropped, Cut: true, Excerpt: "total output over the cap"})
	}
	return res, events
}

// Log writes the events to the journal under the cti-sanitize tag.
func Log(source string, events []Event) {
	if len(events) == 0 {
		return
	}
	w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_AUTH, "cti-sanitize")
	if err != nil {
		return // the cleaning does not depend on the log
	}
	defer func() { _ = w.Close() }()
	for i, e := range events {
		if i == maxLogged {
			_ = w.Warning(fmt.Sprintf("%s: %d more changed line(s) not listed", source, len(events)-maxLogged))
			break
		}
		kind := "stripped"
		if e.Cut {
			kind = "cut"
		}
		_ = w.Warning(fmt.Sprintf("%s: line %d %s (%d characters): %.80q", source, e.Line, kind, e.Removed, e.Excerpt))
	}
}

// ForBeat reports whether output should be cleaned: only inside a heartbeat,
// whose environment run-checkin sets and the beat cannot change.
func ForBeat() bool { return os.Getenv("CHECKIN_BEAT_ID") != "" }

// Run calls fn with os.Stdout captured and writes the cleaned output to the
// real stdout, returning fn's exit code. Outside a beat it only calls fn.
func Run(source string, fn func() int) int {
	if !ForBeat() {
		return fn()
	}
	real := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: cannot clean output for the orchestrator: %v\n", source, err)
		return 1 // fail closed: raw output is not an option inside a beat
	}
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, r); close(done) }()
	os.Stdout = w
	code := fn()
	_ = w.Close()
	<-done
	_ = r.Close()
	os.Stdout = real
	clean, events := Text(buf.String())
	Log(source, events)
	_, _ = io.WriteString(real, clean)
	return code
}

// Child is for a command with exits all through its main: it runs the same
// binary again as a child with CHECKIN_BEAT_ID removed, captures the child's
// stdout, writes it cleaned, and returns the child's exit code. A command
// whose main can return calls Run instead.
func Child(source string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: cannot clean output for the orchestrator: %v\n", source, err)
		return 1
	}
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CHECKIN_BEAT_ID=") {
			env = append(env, kv)
		}
	}
	// #nosec G204 -- the binary re-runs itself with its own arguments
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	var buf bytes.Buffer
	cmd.Stdout = &buf
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			fmt.Fprintf(os.Stderr, "%s: %v\n", source, err)
			return 1
		}
		code = ee.ExitCode()
	}
	clean, events := Text(buf.String())
	Log(source, events)
	_, _ = io.WriteString(os.Stdout, clean)
	return code
}
