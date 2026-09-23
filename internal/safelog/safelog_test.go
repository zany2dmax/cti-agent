package safelog

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Line is a security control, so it gets a test rather than a comment
// claiming it works.
//
// The journal is where an operator goes to find out why a lane misbehaved. A
// log record that can contain a newline is a record that anyone able to
// influence the text can forge, and journalctl renders the forged line
// looking exactly like one this program wrote.
func TestLineCannotBeUsedToForgeAJournalRecord(t *testing.T) {
	forged := "manifest broken\nSep 21 06:00:01 host cti-agent[1]: recorded 0 message(s)"
	got := Line(forged)

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

func TestLineStripsEveryControlCharacterNotJustNewlines(t *testing.T) {
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
		{"C1 control", "a\u0085b"},
	} {
		got := Line(c.in)
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: control %q survived in %q", c.name, r, got)
			}
		}
	}
}

func TestLineLeavesOrdinaryTextAlone(t *testing.T) {
	// The common case is an ordinary error, and mangling it would make the
	// control worse than the problem.
	in := `/var/lib/cti-agent/state/patchtuesday-2026-09.json does not parse: ` +
		`invalid character 'x' looking for beginning of value`
	if got := Line(in); got != in {
		t.Errorf("an ordinary error was altered:\n  in  %q\n  out %q", in, got)
	}
	// Non-ASCII is not a control character. A hostname or path with an
	// accented letter in it should read normally.
	if got := Line("café.example.invalid"); got != "café.example.invalid" {
		t.Errorf("non-ASCII text was mangled: %q", got)
	}
}

// A log line is a record, not a transport for a file. Without a cap, a corrupt
// manifest could put its whole contents into the journal.
func TestLineTruncatesSomethingTheSizeOfAFile(t *testing.T) {
	got := Line(strings.Repeat("A", 5000))
	if n := utf8.RuneCountInString(got); n != DefaultMax {
		t.Errorf("capped at %d runes, want exactly %d", n, DefaultMax)
	}
	// Visible, so a reader can tell the record was cut rather than the
	// message having ended there. An ellipsis is the marker; it is short
	// because LineMax is also used for a 60-character display column, and a
	// wordier marker would eat a quarter of it.
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncation has to be visible, got %q", got[max(0, len(got)-40):])
	}
}

// Cutting at a byte offset lands mid-character often enough, and then the
// control meant to make the log readable is what puts invalid UTF-8 in it.
func TestLineTruncationDoesNotSplitACharacter(t *testing.T) {
	got := Line(strings.Repeat("é", 5000))
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got[max(0, len(got)-20):])
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("expected truncation, got %d bytes", len(got))
	}
	// 5000 runes in, DefaultMax out - counted in runes, not the 10000 bytes
	// the old byte-slicing version would have measured.
	if n := utf8.RuneCountInString(got); n != DefaultMax {
		t.Errorf("got %d runes, want %d", n, DefaultMax)
	}
}

// Truncate is exported and used for display columns, so it gets its own
// coverage rather than only being exercised through Line.
func TestTruncateCountsRunesAndMarksTheCut(t *testing.T) {
	cases := []struct {
		name string
		in   string
		max  int
		want string
	}{
		{"under the cap is untouched", "abcdef", 10, "abcdef"},
		{"exactly at the cap is untouched", "abcdef", 6, "abcdef"},
		{"one over is cut and marked", "abcdefg", 6, "abc..."},
		{"empty stays empty", "", 10, ""},
		// Counted in runes: six accented characters is six, not twelve, so a
		// cap of 6 must leave it alone. The byte-counting version cut it.
		{"multi-byte counted as runes", "ééééée", 6, "ééééée"},
		{"multi-byte cut on a boundary", "ééééééé", 6, "ééé..."},
		// A cap too small for the marker would produce something that is cut
		// without saying so.
		{"absurd cap still marks the cut", "abcdefgh", 1, "a..."},
	}
	for _, c := range cases {
		if got := Truncate(c.in, c.max); got != c.want {
			t.Errorf("%s: Truncate(%q, %d) = %q, want %q",
				c.name, c.in, c.max, got, c.want)
		}
	}
}

// The case this package was extracted for: a mail subject is the most
// obviously attacker-controlled string in the system, and cti-mailbox prints
// it to the journal unattended.
func TestAForgedSubjectLineCannotForgeAJournalRecord(t *testing.T) {
	subject := "Invoice overdue\nSep 23 06:00:01 host cti-mailbox[1]: " +
		"moved 40 message(s) to Deleted Items"

	got := LineMax(subject, 60)
	if strings.Contains(got, "\n") {
		t.Errorf("a subject smuggled a newline into a log record: %q", got)
	}
	if n := utf8.RuneCountInString(got); n > 60 {
		t.Errorf("result is %d runes, want at most 60", n)
	}
	if !strings.HasPrefix(got, "Invoice overdue?") {
		t.Errorf("the real subject should survive, mangled visibly: %q", got)
	}
}
