package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// oneLine is a security control, so it gets a test rather than a comment
// claiming it works.
//
// The journal is where an operator goes to find out why a lane misbehaved. A
// log record that can contain a newline is a record that anyone able to
// influence the text can forge, and journalctl renders the forged line
// looking exactly like one this program wrote.
func TestOneLineCannotBeUsedToForgeAJournalRecord(t *testing.T) {
	forged := "manifest broken\nSep 21 06:00:01 host cti-agent[1]: recorded 0 message(s)"
	got := oneLine(forged)

	if strings.Contains(got, "\n") {
		t.Errorf("a newline survived, so a second journal line can be forged: %q", got)
	}
	// Replaced, not stripped: a message that arrived with newlines in it
	// should look odd, so somebody notices, rather than look clean.
	if !strings.Contains(got, "?") {
		t.Errorf("the mangling should be visible: %q", got)
	}
	if !strings.Contains(got, "manifest broken") {
		t.Errorf("the real message was lost: %q", got)
	}
}

func TestOneLineStripsEveryControlCharacterNotJustNewlines(t *testing.T) {
	// Tab and carriage return push text around; the ANSI escape repaints the
	// terminal. All three are CWE-117 in a log record, and all three are C0
	// controls, which is why the check is unicode.IsControl and not a list.
	for _, c := range []struct {
		name string
		in   string
	}{
		{"newline", "a\nb"},
		{"carriage return", "a\rb"},
		{"tab", "a\tb"},
		{"vertical tab", "a\vb"},
		{"form feed", "a\fb"},
		{"null", "a\x00b"},
		{"ANSI escape", "a\x1b[2Kb"},
		{"C1 control", "ab"},
	} {
		got := oneLine(c.in)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: control %q survived in %q", c.name, r, got)
			}
		}
	}
}

func TestOneLineLeavesOrdinaryTextAlone(t *testing.T) {
	// The common case is an ordinary error, and mangling it would make the
	// control worse than the problem.
	in := `/var/lib/cti-agent/state/patchtuesday-2026-09.json does not parse: ` +
		`invalid character 'x' looking for beginning of value`
	if got := oneLine(in); got != in {
		t.Errorf("an ordinary error was altered:\n  in  %q\n  out %q", in, got)
	}
	// Non-ASCII is not a control character. A hostname or path with an
	// accented letter in it should read normally.
	if got := oneLine("café.example.invalid"); got != "café.example.invalid" {
		t.Errorf("non-ASCII text was mangled: %q", got)
	}
}

// A log line is a record, not a transport for a file. Without a cap, a corrupt
// manifest could put its whole contents into the journal.
func TestOneLineTruncatesSomethingTheSizeOfAFile(t *testing.T) {
	got := oneLine(strings.Repeat("A", 5000))
	if len(got) > 400 {
		t.Errorf("no cap: logged %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("truncation has to be visible, got %q", got[max(0, len(got)-40):])
	}
}

// Cutting at a byte offset lands mid-character often enough, and then the
// control meant to make the log readable is what puts invalid UTF-8 in it.
func TestTruncationDoesNotSplitACharacter(t *testing.T) {
	got := oneLine(strings.Repeat("é", 5000))
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got[max(0, len(got)-20):])
	}
	if !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("expected truncation, got %d bytes", len(got))
	}
}
