package vmscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/zany2dmax/cti-agent/internal/netmap"
)

// # THE SPREADSHEET FIXES GO TO THE HELP DESK AS ONE TICKET
//
// The rows the network team has to correct (a blank or invalid network, one
// outside its location's block, an overlap, a location with no network to
// check) are written as a list that cti-jira --vmscan-fixes files as ONE
// ticket, unassigned, for the help desk to route, and comments on only when the
// list changes - the domains lane's lock-down ticket, for the spreadsheet. Only
// these: the "not scanned" networks are a different question, for the teams
// in the gap-teams setting, and stay in the email.
//
// The list's hash ignores sheet row numbers: inserting a row above a location
// moves every row below it, and that is not a change anyone has to act on.

// SheetFix is one location the network team has to correct.
type SheetFix struct {
	Location string `json:"location"`
	Row      int    `json:"row,omitempty"`
	Kind     string `json:"kind"`
	Title    string `json:"title"`
	Problem  string `json:"problem"`
	Action   string `json:"action"`
}

// FixesFile is what cti-vmscan --fixes-out writes for cti-jira.
type FixesFile struct {
	Generated string     `json:"generated"`
	Hash      string     `json:"hash"`
	Fixes     []SheetFix `json:"fixes"`
	// Cleanup is what is wrong in the sheet without stopping the check, and
	// the operator's notes; a second section of the same ticket.
	Cleanup []SheetFix `json:"cleanup"`
	// Held: the coverage check did not run, so the list says nothing about
	// the sheet. cti-jira files, comments on and resolves nothing - an empty
	// list would otherwise tell the open ticket it is finished.
	Held    bool   `json:"held,omitempty"`
	HeldWhy string `json:"heldWhy,omitempty"`
}

// Fixes is the coverage check's spreadsheet questions as a fixes list.
func (c *Coverage) Fixes(now time.Time) FixesFile {
	f := FixesFile{Generated: now.UTC().Format(time.RFC3339), Fixes: []SheetFix{}, Cleanup: []SheetFix{}}
	if c == nil {
		f.Held, f.HeldWhy = true, "the coverage check was not asked for"
		return f
	}
	if c.Unavailable != "" {
		f.Held, f.HeldWhy = true, c.Unavailable
		return f
	}
	for _, k := range questionOrder {
		for _, q := range c.questionsOf(k) {
			f.Fixes = append(f.Fixes, SheetFix{Location: q.Location, Row: q.Row, Kind: string(k),
				Title: questionTitle(k), Problem: q.Why, Action: questionAction(k)})
		}
	}
	for _, k := range netmap.CleanupOrder {
		for _, x := range c.cleanupOf(k) {
			f.Cleanup = append(f.Cleanup, SheetFix{Location: x.Location, Row: x.Row, Kind: string(k),
				Title: netmap.CleanupTitle(k), Problem: x.Why, Action: netmap.CleanupAction(k)})
		}
	}
	f.Hash = FixesHash(append(append([]SheetFix(nil), f.Fixes...), f.Cleanup...))
	return f
}

// FixesHash identifies a list by what it asks, not where in the sheet.
func FixesHash(fixes []SheetFix) string {
	lines := make([]string, 0, len(fixes))
	for _, x := range fixes {
		lines = append(lines, strings.Join([]string{x.Location, x.Kind, x.Problem}, "\x1f"))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\x1e")))
	return hex.EncodeToString(sum[:8])
}

// JSON is the file's bytes.
func (f FixesFile) JSON() []byte {
	b, _ := json.MarshalIndent(f, "", "  ")
	return append(b, '\n')
}
