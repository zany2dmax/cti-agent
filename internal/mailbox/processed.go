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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zany2dmax/cti-agent/internal/statefile"
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
	// HasCVE records whether this message is CVE mail the digest OWNS: it held a
	// CVE and came from a trusted feed, a colleague, or a sender the receiving
	// server authenticated. It is the difference between a CTI advisory and
	// everything else that lands in a shared security mailbox, and it is what
	// lets the cleanup archive the message. (Records written by 1.7 or earlier
	// have it for any sender who mentioned a CVE, until the 14-day log expires
	// them.)
	HasCVE bool `json:"has_cve"`
	// AutoReply is what the SENDING system declared, captured at read time
	// rather than re-derived later, so the cleanup lane and the agent cannot
	// disagree about what a message is.
	AutoReply bool      `json:"auto_reply"`
	ReadAt    time.Time `json:"read_at"`

	// Owner names the lane responsible for this message, when that is not
	// the digest. Only a lane's OWN log sets it, and only for mail it
	// recognised as its input and then reported on - cti-appscan writes
	// "appscan" for the Qualys WAS notifications its weekly covered. Empty
	// on the digest's entries, whose ownership is HasCVE.
	Owner string `json:"owner,omitempty"`

	// Delete asks the cleanup to move an owned message to Deleted Items
	// instead of Archive, once the owner's grace has passed. Only a lane's own
	// log sets it, and only for a COMPANION notice: one the scanner sends
	// alongside a results notice ("scan completed", "scheduled to start") that
	// carries nothing once the lane has reported on that run. The operator's
	// choice: those are noise, not records worth filing. Deleted Items is
	// still recoverable; nothing here purges.
	Delete bool `json:"delete,omitempty"`

	// Ref is the owning lane's own name for what the message is about -
	// cti-appscan writes the scan's reference - so a lane that reports per
	// item can record only the messages of the items it actually delivered
	// (cti-appscan --commit-seen --only-sent). The cleanup does not read it.
	Ref string `json:"ref,omitempty"`
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

// OwnerAppScan is the application-security lane's name in Processed.Owner.
const OwnerAppScan = "appscan"

// OwnerVMScan is the VM scan lane's name in Processed.Owner: the Qualys VMDR
// results notices its weekly combined and sent.
const OwnerVMScan = "vmscan"

// OwnerSupplier is the supplier-request lane's name in Processed.Owner: the
// messages of a supplier request it judged and either dismissed as not critical
// or filed a Kanban item for. A request set aside as not a supplier request is
// never recorded: that thread is left for a person.
const OwnerSupplier = "supplier"

// OwnerLogPath is where a lane other than the digest records the mail it
// owns: $FLEET_HOME/state/processed-<owner>.json, "" without FLEET_HOME.
//
// A file per lane, not one shared file. The digest and the weekly lanes are
// separate processes on separate timers, and two writers doing
// load-modify-rename on one file lose each other's entries on a collision -
// silently, as a message that is simply never archived.
//
// Beside FLEET_PROCESSED_LOG when that override is set, so a test or
// development run that redirects the digest's log is not paired with the
// production lane logs.
func OwnerLogPath(owner string) string {
	if strings.ContainsAny(owner, `/\.`) || owner == "" {
		return ""
	}
	name := "processed-" + owner + ".json"
	if p := strings.TrimSpace(os.Getenv("FLEET_PROCESSED_LOG")); p != "" {
		return filepath.Join(filepath.Dir(p), name)
	}
	home := strings.TrimSpace(os.Getenv("FLEET_HOME"))
	if home == "" {
		return ""
	}
	return filepath.Join(home, "state", name)
}

// Merge combines the digest's index with owner lanes' entries. A message in
// both keeps the digest's view (CVE, auto-reply) and gains the owner; a
// message only an owner lane read is added with that owner.
//
// Owner entries older than DefaultRetain before now are dropped: an owner
// log is pruned only when its lane next writes, which for a weekly lane can
// be a week late, and an expired record must not carry authority to move
// mail meanwhile.
func Merge(now time.Time, digest map[string]Processed, owned ...*Log) map[string]Processed {
	cutoff := now.Add(-DefaultRetain)
	out := make(map[string]Processed, len(digest))
	for id, e := range digest {
		out[id] = e
	}
	for _, l := range owned {
		if l == nil {
			continue
		}
		for _, e := range l.Entries {
			if strings.TrimSpace(e.Owner) == "" || !e.ReadAt.After(cutoff) {
				continue // claims nothing: no owner, or the record has expired
			}
			if cur, ok := out[e.ID]; ok {
				// The digest reads everything, so a lane's message is nearly
				// always here already. Everything the lane decides about it
				// has to be carried across: copying only Owner once lost
				// nothing, but would now silently archive what the lane said
				// to delete.
				cur.Owner = e.Owner
				cur.Delete = e.Delete
				out[e.ID] = cur
				continue
			}
			out[e.ID] = e
		}
	}
	return out
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
	var l Log
	// Parsing only: a file that does not parse fails closed. A file that parses
	// is REPAIRED, entry by entry (Normalize), not rejected: this log is
	// trusted by the mailbox cleanup, and one bad entry (a clock that stepped
	// back, a subject longer than an older version allowed) must not stop every
	// lane until someone deletes the file by hand.
	err := statefile.Read(s.Path, &l, statefile.Options{MaxBytes: maxLogBytes})
	switch {
	case err == nil:
		if notes := l.Normalize(s.now()); len(notes) > 0 {
			fmt.Fprintf(os.Stderr, "mailbox: repaired %s: %s\n", s.Path, strings.Join(notes, "; "))
		}
		return &l, nil
	case errors.Is(err, os.ErrNotExist):
		return &Log{}, nil
	case errors.Is(err, statefile.ErrInvalid):
		return nil, fmt.Errorf("mailbox: %s is corrupt: %w", s.Path, err)
	}
	return nil, fmt.Errorf("mailbox: reading %s: %w", s.Path, err)
}

// Bounds on a processed log. Mail is kept for two weeks, so even a busy
// mailbox is a few thousand entries; the caps catch a damaged file, not a
// large legitimate one. Subjects are clipped on the way in (Record) rather
// than refused, since a long subject is ordinary mail and a refused write would
// stop the lane remembering what it had read.
const (
	maxEntries = 50000
	maxIDLen   = 2048
	maxSubject = 1000
	maxRef     = 512
	// ReadAt is set by this host; the sender controls neither it nor Received.
	readAtSkew = 24 * time.Hour
)

// Validate says whether the log is one this package could have written.
func (l *Log) Validate(now time.Time) error {
	if len(l.Entries) > maxEntries {
		return fmt.Errorf("%d entries, more than the %d a log holds", len(l.Entries), maxEntries)
	}
	seen := make(map[string]bool, len(l.Entries))
	for i, e := range l.Entries {
		switch {
		case strings.TrimSpace(e.ID) == "":
			return fmt.Errorf("entry %d has no message id", i)
		case len(e.ID) > maxIDLen:
			return fmt.Errorf("entry %d has a %d byte message id, over %d", i, len(e.ID), maxIDLen)
		case seen[e.ID]:
			return fmt.Errorf("entry %d repeats a message id", i)
		case e.ReadAt.After(now.Add(readAtSkew)):
			// An entry dated ahead is never pruned, so mail would stay
			// eligible to move on a record that never expires.
			return fmt.Errorf("entry %d is read-dated %s, in the future", i, e.ReadAt.UTC().Format(time.RFC3339))
		case len(e.Subject) > maxSubject:
			return fmt.Errorf("entry %d has a %d byte subject, over %d", i, len(e.Subject), maxSubject)
		case len(e.Ref) > maxRef:
			return fmt.Errorf("entry %d has a %d byte ref, over %d", i, len(e.Ref), maxRef)
		}
		seen[e.ID] = true
	}
	return nil
}

func (s *Store) opts(l *Log) statefile.Options {
	return statefile.Options{MaxBytes: maxLogBytes, Validate: func() error { return l.Validate(s.now()) }}
}

// maxLogBytes caps the file: far above maxEntries' worth of indented entries
// (about 500 bytes each), so the entry cap is what limits the log, not the size
// cap.
const maxLogBytes = 32 << 20

// Normalize repairs what a log written by an older version, or under a skewed
// clock, can hold, and says what it did. It drops entries with no usable
// message id (empty, over-long or a repeat of an earlier one), pulls a read time
// that is ahead of the clock back to now (so it expires like any other entry and
// still counts as read), and clips a subject or ref to its limit. After it,
// Validate passes. Only an unparseable file is a failure.
func (l *Log) Normalize(now time.Time) []string {
	var notes []string
	seen := make(map[string]bool, len(l.Entries))
	out := l.Entries[:0:0]
	dropped, clamped, clipped := 0, 0, 0
	for _, e := range l.Entries {
		if strings.TrimSpace(e.ID) == "" || len(e.ID) > maxIDLen || seen[e.ID] {
			dropped++
			continue
		}
		seen[e.ID] = true
		if e.ReadAt.After(now.Add(readAtSkew)) {
			e.ReadAt = now
			clamped++
		}
		if len(e.Subject) > maxSubject || len(e.Ref) > maxRef {
			e.Subject, e.Ref = clipUTF8(e.Subject, maxSubject), clipUTF8(e.Ref, maxRef)
			clipped++
		}
		out = append(out, e)
	}
	l.Entries = out
	if len(l.Entries) > maxEntries {
		sort.Slice(l.Entries, func(i, j int) bool { return l.Entries[i].ReadAt.After(l.Entries[j].ReadAt) })
		notes = append(notes, fmt.Sprintf("kept the newest %d of %d entries", maxEntries, len(l.Entries)))
		l.Entries = l.Entries[:maxEntries]
	}
	if dropped > 0 {
		notes = append(notes, fmt.Sprintf("dropped %d entries with no usable id", dropped))
	}
	if clamped > 0 {
		notes = append(notes, fmt.Sprintf("pulled %d future read times back to now", clamped))
	}
	if clipped > 0 {
		notes = append(notes, fmt.Sprintf("clipped %d long subjects or refs", clipped))
	}
	return notes
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
		e.Subject = clipUTF8(e.Subject, maxSubject)
		e.Ref = clipUTF8(e.Ref, maxRef)
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

// Save validates the log and writes it atomically, mode 0600
// (internal/statefile). A half-written log read by the cleanup lane would look
// like a shorter one, and a shorter one means fewer messages are eligible to
// move - safe, but it would also mean the lane silently stopped working. A log
// that fails validation is not written, and the old one stays. 0600: subject
// lines from a security mailbox are not for other accounts on the box.
func (s *Store) Save(l *Log) error {
	return statefile.Write(s.Path, l, s.opts(l))
}

// Index is the log keyed by message ID, for the cleanup lane's lookups.
func (l *Log) Index() map[string]Processed {
	m := make(map[string]Processed, len(l.Entries))
	for _, e := range l.Entries {
		m[e.ID] = e
	}
	return m
}

// ProcessedToday reports whether the digest read real mail today in the given
// location, and how many messages.
//
// This is the cleanup lane's health gate: archive only on a day the digest is
// known to have read the mailbox. "Real mail" means anything but an automatic
// reply - a day on which the agent read nothing but out-of-office replies is
// not evidence that it is reading the mailbox, and must not count.
//
// IT USED TO ASK FOR A MESSAGE THAT CARRIED A CVE, and that was a bug. A quiet
// day - the intel newsletters, the Qualys notices and the supplier mail all
// read, none of them naming a CVE - looked exactly like a broken fleet, so
// nothing was archived: not the scan notices cti-appscan and cti-vmscan own,
// on any quiet day, which in a week of "no new CVEs" briefs was most days.
// Mail held that way for MAILBOX_LOOKBACK_HOURS then fell out of the window
// and stayed in the inbox for good. Whether the digest found a CVE is a fact
// about the threat landscape, not about whether the fleet is working.
func (l *Log) ProcessedToday(now time.Time, loc *time.Location) (bool, int) {
	if loc == nil {
		loc = time.UTC
	}
	y, m, d := now.In(loc).Date()
	start := time.Date(y, m, d, 0, 0, 0, 0, loc)
	n := 0
	for _, e := range l.Entries {
		if !e.AutoReply && !e.ReadAt.Before(start) {
			n++
		}
	}
	return n > 0, n
}

// clipUTF8 cuts s to at most n bytes without splitting a character.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
