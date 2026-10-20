// Package ticketref is what a Jira step tells the report it runs before: which
// ticket, what happened to it this run, and its link - validated, because it
// goes into an email.
//
// Shared by the domains lane (one lock-down ticket) and the AppSec lane (one
// ticket per application). Each lane words its own line; the checks on what
// may reach an email live here, once.
package ticketref

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

// Ref is one ticket's outcome.
type Ref struct {
	// Action is one of: created, commented, unchanged, resolved, none,
	// would-create, would-comment, would-resolve, error, gate-closed, skipped.
	Action string `json:"action"`
	Key    string `json:"key,omitempty"`
	URL    string `json:"url,omitempty"`
	Status string `json:"status,omitempty"`
	Note   string `json:"note,omitempty"`
	// Assignee is who the ticket was assigned to, when this run assigned it.
	Assignee string `json:"assignee,omitempty"`
}

var (
	keyRE = regexp.MustCompile(`^[A-Z][A-Z0-9]{0,15}-[0-9]{1,9}$`)
	urlRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+/browse/[A-Z][A-Z0-9]{0,15}-[0-9]{1,9}$`)
)

// SafeKey is the ref's key if it is a well-formed Jira key, else "".
func (r Ref) SafeKey() string {
	if keyRE.MatchString(r.Key) {
		return r.Key
	}
	return ""
}

// SafeURL is the browse link if it is https and for this ref's key, else "".
func (r Ref) SafeURL() string {
	k := r.SafeKey()
	if k != "" && urlRE.MatchString(r.URL) && strings.HasSuffix(r.URL, "/"+k) {
		return r.URL
	}
	return ""
}

// SafeStatus is the status with control characters removed, " (status)"
// ready to append, or "".
func (r Ref) SafeStatus() string {
	if s := strings.TrimSpace(Clean(r.Status)); s != "" && len(s) < 60 {
		return " (" + s + ")"
	}
	return ""
}

// SafeNote is the note, cleaned and bounded.
func (r Ref) SafeNote() string {
	n := strings.TrimSpace(Clean(r.Note))
	if rs := []rune(n); len(rs) > 200 {
		n = string(rs[:200]) + "..."
	}
	return n
}

// Clean drops control characters, so a field from Jira cannot break a line.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// Write writes v as JSON, 0600.
func Write(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Read reads JSON written by Write into v.
func Read(path string, v any) error {
	// #nosec G304 -- the runner's own ref file under $FLEET_HOME/state.
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
