// Package safelog makes text safe to put in a log record.
//
// # WHY THIS EXISTS AS A PACKAGE
//
// A log line is a record, and a record that can contain a newline is a record
// anyone who can influence the text can forge. journalctl renders the forged
// line looking exactly like one this program wrote, which makes the journal
// useless for the one job it has here: telling an operator what actually
// happened. That is CWE-117.
//
// This started as an unexported helper in cmd/cti-agent, which is the lane
// that logs config paths and parse errors. Writing the threat model down
// afterwards turned up the lane that needed it more and did not have it:
// cti-mailbox prints the SUBJECT LINES OF OTHER PEOPLE'S MAIL to the journal,
// on a timer, unattended. A subject is attacker-controlled - anyone can mail a
// published security address - so it is the most obviously hostile string in
// the whole system, being printed by the one lane that also moves mail.
//
// One implementation, in a package both can import, rather than a copy that
// only half the callers get. The same reasoning as internal/fleetenv.
package safelog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// DefaultMax is the cap on a single sanitised value. A log line is a record,
// not a transport for a file.
const DefaultMax = 300

// Line makes a string safe to put in a log record: every control character is
// replaced, and the result is capped at DefaultMax runes.
//
// Replaces rather than strips, so the mangling is visible. A message that
// arrived with newlines in it should look odd, not look clean - "odd" is the
// signal that somebody put something strange in a subject line.
func Line(s string) string { return LineMax(s, DefaultMax) }

// LineMax is Line with an explicit cap, for callers printing into a
// fixed-width column.
func LineMax(s string, max int) string {
	// unicode.IsControl covers it: newline, carriage return and tab are all C0
	// controls, as are the C1 range and DEL. Listing them separately would be
	// three redundant comparisons in front of the check that decides.
	out := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	return Truncate(out, max)
}

// Truncate shortens to at most max runes, marking that it did so.
//
// Runes, not bytes. A byte-offset cut lands in the middle of a multi-byte
// character often enough, and then the control meant to make the log readable
// is the thing that puts invalid UTF-8 in it. The version of this in
// cti-mailbox sliced bytes.
//
// max below 4 is treated as 4, because the marker has to fit for the result to
// be honest about being cut.
func Truncate(s string, max int) string {
	const marker = "..."
	if max < 4 {
		max = 4
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max-len(marker)]) + marker
}
