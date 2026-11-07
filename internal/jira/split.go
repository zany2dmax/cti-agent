package jira

import (
	"fmt"
	"strings"
)

// MaxText is the most characters sent in one description or comment. Jira
// refuses more than 32767 ("The entered text is too long", HTTP 400), and the
// refusal is all-or-nothing: the lock-down ticket's weekly list of 206 DNS
// changes went over it and the whole update was lost. A margin is left for the
// "part n of m" line and for how Jira counts characters.
const MaxText = 30000

// SplitText cuts text into pieces of at most max characters, at line breaks
// where it can so wiki markup (a list, a heading and what follows it) is not
// torn mid-line. A single line longer than max is cut at a character
// boundary. Text that already fits comes back as it was, one piece.
//
// Every piece after the first starts with "(continued)" and every piece but
// the last ends with a note that more follows, so a reader landing on any one
// of them knows there is another.
func SplitText(text string, max int) []string {
	if max < 200 {
		max = 200
	}
	if len([]rune(text)) <= max {
		return []string{text}
	}
	// Room for the note added to each piece.
	room := max - 80
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.TrimRight(string(cur), "\n"))
			cur = cur[:0]
		}
	}
	for _, line := range strings.SplitAfter(text, "\n") {
		lr := []rune(line)
		for len(lr) > room {
			// One line longer than a whole piece: cut it where it stands.
			flush()
			parts = append(parts, string(lr[:room]))
			lr = lr[room:]
		}
		if len(cur)+len(lr) > room {
			flush()
		}
		cur = append(cur, lr...)
	}
	flush()
	n := len(parts)
	for i := range parts {
		if i > 0 {
			parts[i] = fmt.Sprintf("_(part %d of %d, continued)_\n\n%s", i+1, n, parts[i])
		}
		if i < n-1 {
			parts[i] += fmt.Sprintf("\n\n_(part %d of %d - continues in the next comment)_", i+1, n)
		}
	}
	return parts
}
