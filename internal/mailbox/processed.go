// Package mailbox records which messages a run actually processed, and decides
// what the cleanup lane is allowed to do with them.
//
// # WHY A LOG AT ALL
//
// The operator's rule for the cleanup lane is "make sure a given email has
// been processed before deleting it". That is a claim about the past, so
// something has to have written it down. Nothing in the fleet did: the agent
// read the mailbox, extracted CVEs and wrote a markdown report, and the
// message IDs were discarded on the way.
//
// Without this file, a cleanup lane would have to infer "processed" from
// something adjacent - a report existing, a digest having been sent, a subject
// appearing in a table - and every one of those is true in cases where the
// message was never read. Inferring the safety condition for a destructive
// action from a correlated signal is how mail disappears.
//
// # WHY JSON AND NOT THE FLEET DATABASE
//
// The fleet's memory is SQLite, but it is reached through fleet-db, a Python
// script. The Go binaries have no SQLite driver and go.mod has no
// dependencies, deliberately - adding cgo to the build to write a list of
// message IDs would cost a C toolchain on the deployment host. This follows
// internal/budget: a small JSON file, written atomically, owned by one
// package.
package mailbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Processed is one message a completed run read.
type Processed struct {
	// ID is the Graph message ID as it was when the run read it. Graph's move
	// operation changes the ID, so an entry whose message has already been
	// moved will simply not be found in the inbox again - which is the
	// behaviour we want from a second run.
	ID       string    `json:"id"`
	Subject  string    `json:"subject"`
	Received time.Time `json:"received"`
	// HasCVE records whether this message contributed to the findings. It is
	// the difference between a CTI advisory and everything else that lands in
	// a shared security mailbox.
	HasCVE bool `json:"has_cve"`
	// AutoReply is what the SENDING system declared, captured at read time
	// rather than re-derived later, so the cleanup lane and the agent cannot
	// disagree about what a message is.
	AutoReply bool      `json:"auto_reply"`
	ReadAt    time.Time `json:"read_at"`
}

// Log is the on-disk record.
type Log struct {
	Entries []Processed `json:"entries"`
}

// Store reads and writes the log. Now is injectable so retention is testable
// without waiting a fortnight.
type Store struct {
	Path string
	Now  func() time.Time
	// Retain bounds the file. Entries older than this are pruned, which also
	// bounds how long after reading a message the lane may still move it: an
	// advisory read three weeks ago and never cleaned up stays where it is
	// rather than being archived on the strength of a stale record.
	Retain time.Duration
}

// DefaultRetain is generous next to a daily cleanup and short enough that the
// file stays small and the authority to move a message expires.
const DefaultRetain = 14 * 24 * time.Hour

// LogPath is where the processed-message log lives.
//
// Returns "" when FLEET_HOME is not set, which switches the whole feature off
// rather than writing state into whatever directory the binary happened to
// start in. The agent runs by hand during development and under systemd in
// production; only the second has a state directory, and a log written to a
// developer's checkout would give the cleanup lane a set of message IDs from
// somebody's laptop.
func LogPath() string {
	if p := strings.TrimSpace(os.Getenv("FLEET_PROCESSED_LOG")); p != "" {
		return p
	}
	home := strings.TrimSpace(os.Getenv("FLEET_HOME"))
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state", "processed-messages.json")
}

func NewStore(path string) *Store {
	return &Store{Path: path, Now: time.Now, Retain: DefaultRetain}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) retain() time.Duration {
	if s.Retain > 0 {
		return s.Retain
	}
	return DefaultRetain
}

// Load reads the log. A missing file is an empty log, not an error - the first
// run has nothing to remember.
//
// A CORRUPT FILE IS AN ERROR, unlike the budget ledger, which returns an empty
// one and carries on. The asymmetry is deliberate: an empty budget ledger
// means "spend a beat", which is harmless, whereas an empty processed log
// means "nothing has been processed", which is exactly the state in which the
// cleanup lane must refuse to act. Returning empty-and-no-error would turn a
// truncated file into a silent licence to... do nothing, which is safe - but
// the operator would never learn the file was broken, and the inbox would
// quietly stop being cleaned.
func (s *Store) Load() (*Log, error) {
	// #nosec G304 -- s.Path is the log location from the service configuration.
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Log{}, nil
		}
		return nil, fmt.Errorf("mailbox: reading %s: %w", s.Path, err)
	}
	var l Log
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("mailbox: %s is corrupt: %w", s.Path, err)
	}
	return &l, nil
}

// Record adds entries, replacing any with the same ID, and prunes old ones.
func (s *Store) Record(l *Log, seen []Processed) {
	now := s.now()
	byID := make(map[string]Processed, len(l.Entries)+len(seen))
	for _, e := range l.Entries {
		byID[e.ID] = e
	}
	for _, e := range seen {
		if strings.TrimSpace(e.ID) == "" {
			continue
		}
		if e.ReadAt.IsZero() {
			e.ReadAt = now
		}
		byID[e.ID] = e
	}
	cutoff := now.Add(-s.retain())
	out := make([]Processed, 0, len(byID))
	for _, e := range byID {
		if e.ReadAt.After(cutoff) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReadAt.After(out[j].ReadAt) })
	l.Entries = out
}

// Save writes atomically. A half-written log read by the cleanup lane would
// look like a shorter one, and a shorter one means fewer messages are eligible
// to move - safe, but it would also mean the lane silently stopped working.
func (s *Store) Save(l *Log) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".processed-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	// 0600: subject lines from a security mailbox are not for other accounts
	// on the box.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.Path)
}

// Index is the log keyed by message ID, for the cleanup lane's lookups.
func (l *Log) Index() map[string]Processed {
	m := make(map[string]Processed, len(l.Entries))
	for _, e := range l.Entries {
		m[e.ID] = e
	}
	return m
}

// ProcessedToday reports whether any message was read today in the given
// location, and how many.
//
// This is the "only after a CTI email is processed" gate. It asks specifically
// for a message that CARRIED A CVE: a day on which the agent read nothing but
// out-of-office replies has not processed a CTI email, and the cleanup lane
// must not treat it as a normal day.
func (l *Log) ProcessedToday(now time.Time, loc *time.Location) (bool, int) {
	if loc == nil {
		loc = time.UTC
	}
	y, m, d := now.In(loc).Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, loc)
	n := 0
	for _, e := range l.Entries {
		if e.HasCVE && !e.ReadAt.Before(start) {
			n++
		}
	}
	return n > 0, n
}
