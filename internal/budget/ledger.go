// Package budget rations the heartbeat's share of a Claude subscription.
//
// The fleet and its operator draw on the same quota. Nothing in the Claude
// Code CLI reports how much of that quota is left, and the fleet runs on a
// different machine from the operator's own sessions, so there is no way to
// observe contention and yield. The only honest design is a self-imposed
// ceiling: the fleet spends at most N beats per rolling window and M per day,
// and whatever remains is the operator's.
//
// Two limits rather than one, because they fail differently. The daily cap
// bounds total spend. The rolling-window cap bounds *bursts* - which is the
// case that actually locks someone out, since systemd's Persistent=true fires
// every missed beat at once when a box comes back from an outage.
//
// State is a JSON file, not SQLite: the Go module has no dependencies and
// adding a cgo driver to gate a counter would cost more than it returns.
package budget

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Outcome is how a beat ended. It drives backoff, so the distinction between
// "the model refused us" and "the script broke" matters: only the former means
// slowing down will help.
type Outcome string

const (
	OutcomeOK        Outcome = "ok"
	OutcomeRateLimit Outcome = "ratelimit"
	OutcomeError     Outcome = "error"
	// OutcomeExhausted is the account being out of credit or subscription,
	// as distinct from being throttled. Waiting does not fix it, so it must
	// not be reported as a transient backoff or as a code failure. See
	// classify.go for what mistaking it cost.
	OutcomeExhausted Outcome = "exhausted"
)

// Charges reports whether a beat consumed model quota, and therefore whether
// it counts against the ceilings.
//
// OK spent a request. So did a rate limit - being refused is evidence the
// request reached the service. An error did not: the lane broke, usually
// before it ever called the model.
//
// # WHY THIS MATTERS MORE THAN IT LOOKS
//
// Charging errors inverts the fleet's own diagnosis. A crash-looping
// orchestrator burns the daily ceiling on failures, the gate then holds, and
// the fleet reports a BUDGET problem while the actual problem is code. That is
// precisely the confusion classify.go exists to prevent, reintroduced one
// level down. Thirty-one failed beats from 21 September onward were each
// charged for a model call they never made.
//
// There is no retry-storm risk in letting errors go uncharged: the pace is set
// by a two-hourly systemd timer, not by retries, so a broken lane cannot beat
// faster than a working one.
// Exhausted does not charge either. The ceilings exist to stop this fleet
// crowding out its operator; rationing ourselves against a balance of zero
// protects nobody from anything.
func (o Outcome) Charges() bool {
	return o == OutcomeOK || o == OutcomeRateLimit
}

// NeedsAPerson reports whether no amount of waiting will clear this. The
// caller should hold and escalate rather than back off and retry.
func (o Outcome) NeedsAPerson() bool { return o == OutcomeExhausted }

// Beat is one recorded attempt.
type Beat struct {
	At      time.Time `json:"at"`
	Outcome Outcome   `json:"outcome"`
	Note    string    `json:"note,omitempty"`
}

// Limits are the ceilings. Defaults assume the shipped two-hour cadence: 12
// beats a day, so 2-3 land in any 5h window. WindowBeats=4 therefore never
// binds during normal operation and exists purely to absorb catch-up bursts
// and retry storms. A limit that fires constantly is one people disable.
type Limits struct {
	Window        time.Duration
	WindowBeats   int
	DailyBeats    int
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	BackoffFactor int
}

func DefaultLimits() Limits {
	return Limits{
		Window:        5 * time.Hour, // matches how Claude's limits reset
		WindowBeats:   4,
		DailyBeats:    14, // 12 scheduled + 2 manual runs
		BackoffBase:   30 * time.Minute,
		BackoffMax:    6 * time.Hour,
		BackoffFactor: 2,
	}
}

// Ledger is the on-disk state.
type Ledger struct {
	Beats []Beat `json:"beats"`
	// CooldownUntil is set when a rate limit is observed. It is stored rather
	// than recomputed so that a cooldown survives a restart - a fleet that
	// forgets it was throttled will immediately get throttled again.
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
	// AlertedFor marks the cooldown we have already emailed about, so that
	// "alert on every denied beat" does not become "alert twice for the same
	// beat" when a caller checks more than once.
	AlertedFor time.Time `json:"alerted_for,omitempty"`
}

// Decision is the answer to "may I spend a beat?".
type Decision struct {
	Allow  bool
	Reason string // human-readable, goes straight into the journal and the email
	// RetryAfter is when the caller could next succeed. Zero when unknown.
	RetryAfter time.Time
}

// Store reads and writes the ledger. Now is injectable so the boundary
// conditions are testable without sleeping through a five-hour window.
type Store struct {
	Path   string
	Limits Limits
	Now    func() time.Time
}

func NewStore(path string, lim Limits) *Store {
	return &Store{Path: path, Limits: lim, Now: time.Now}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Load reads the ledger. A missing file is an empty ledger, not an error: the
// first beat on a fresh install must not be blocked by its own bookkeeping.
// A corrupt file is also an empty ledger, loudly - refusing to run because a
// counter file got truncated would turn a cosmetic problem into an outage.
func (s *Store) Load() (*Ledger, error) {
	// s.Path is the ledger location from the service
	// configuration, written only by this package.
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Ledger{}, nil
		}
		return nil, fmt.Errorf("budget: reading %s: %w", s.Path, err)
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return &Ledger{}, fmt.Errorf("budget: %s is corrupt, starting fresh: %w", s.Path, err)
	}
	return &l, nil
}

// Save writes atomically. A half-written ledger read by the next beat would
// look like an empty one, which would silently disable the whole ceiling.
func (s *Store) Save(l *Ledger) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	// Keep the file bounded. Two days of history is more than any limit reads.
	l.Beats = prune(l.Beats, s.now().Add(-48*time.Hour))

	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Path), ".budget-*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
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

func prune(beats []Beat, cutoff time.Time) []Beat {
	out := beats[:0]
	for _, b := range beats {
		if b.At.After(cutoff) {
			out = append(out, b)
		}
	}
	return out
}

// Check answers whether a beat may be spent, without recording anything.
// Order matters: cooldown first, because a rate-limited fleet must back off
// even when it is nowhere near its own ceilings.
func (s *Store) Check(l *Ledger) Decision {
	now := s.now()

	if !l.CooldownUntil.IsZero() && now.Before(l.CooldownUntil) {
		return Decision{
			Reason: fmt.Sprintf("backing off after a rate limit until %s (%s remaining)",
				l.CooldownUntil.Format(time.RFC3339),
				now.Sub(l.CooldownUntil).Abs().Round(time.Minute)),
			RetryAfter: l.CooldownUntil,
		}
	}

	inWindow := countSince(l.Beats, now.Add(-s.Limits.Window))
	if inWindow >= s.Limits.WindowBeats {
		return Decision{
			Reason: fmt.Sprintf("window ceiling reached: %d beats in the last %s, limit %d",
				inWindow, s.Limits.Window, s.Limits.WindowBeats),
			RetryAfter: oldestInWindow(l.Beats, now.Add(-s.Limits.Window)).Add(s.Limits.Window),
		}
	}

	today := countSince(l.Beats, startOfDay(now))
	if today >= s.Limits.DailyBeats {
		return Decision{
			Reason: fmt.Sprintf("daily ceiling reached: %d beats today, limit %d",
				today, s.Limits.DailyBeats),
			RetryAfter: startOfDay(now).Add(24 * time.Hour),
		}
	}

	return Decision{Allow: true, Reason: fmt.Sprintf(
		"%d/%d in window, %d/%d today", inWindow, s.Limits.WindowBeats, today, s.Limits.DailyBeats)}
}

// Record appends an outcome and updates the cooldown. Only beats that actually
// reached the model count against the ceilings; a beat that never ran because
// the binary was missing should not consume quota it never spent.
func (s *Store) Record(l *Ledger, o Outcome, note string) {
	now := s.now()
	l.Beats = append(l.Beats, Beat{At: now, Outcome: o, Note: note})

	switch o {
	case OutcomeRateLimit:
		l.CooldownUntil = now.Add(s.backoffFor(l))
	case OutcomeExhausted:
		// Straight to the maximum, not up the exponential ramp. The ramp
		// assumes waiting helps; here it does not, and starting at 30 minutes
		// means 12 pointless retries before the backoff gets long enough to
		// stop being noise.
		l.CooldownUntil = now.Add(s.Limits.BackoffMax)
	case OutcomeOK:
		// Clear the cooldown only on a clean run. An error is not evidence
		// that the throttle lifted.
		l.CooldownUntil = time.Time{}
		l.AlertedFor = time.Time{}
	}
}

// backoffFor grows the cooldown with each consecutive rate limit, so a fleet
// that keeps getting refused stops asking rather than hammering a quota its
// operator is trying to use.
func (s *Store) backoffFor(l *Ledger) time.Duration {
	n := consecutiveRateLimits(l.Beats)
	d := s.Limits.BackoffBase
	for i := 1; i < n; i++ {
		d *= time.Duration(s.Limits.BackoffFactor)
		if d >= s.Limits.BackoffMax {
			return s.Limits.BackoffMax
		}
	}
	if d > s.Limits.BackoffMax {
		return s.Limits.BackoffMax
	}
	return d
}

// consecutiveRateLimits counts back from the most recent beat. The beat just
// recorded is included, so the first rate limit yields 1 and BackoffBase.
func consecutiveRateLimits(beats []Beat) int {
	sorted := append([]Beat(nil), beats...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })
	n := 0
	for i := len(sorted) - 1; i >= 0; i-- {
		if sorted[i].Outcome != OutcomeRateLimit {
			break
		}
		n++
	}
	return n
}

// countSince counts the beats after cutoff that actually spent quota. The
// name is deliberately not countAllSince: every caller is a ceiling check,
// and a ceiling that counts failures is the bug this replaced.
func countSince(beats []Beat, cutoff time.Time) int {
	n := 0
	for _, b := range beats {
		if b.At.After(cutoff) && b.Outcome.Charges() {
			n++
		}
	}
	return n
}

// CountCharged exposes the same count for reporting, so `cti-budget status`
// can show recorded and charged side by side. "24 stored, 0 charged" is the
// line that makes a silently broken lane obvious.
func CountCharged(beats []Beat, cutoff time.Time) int {
	return countSince(beats, cutoff)
}

// CountSinceAny counts beats after cutoff whatever their outcome. Reporting
// only: a ceiling must use countSince.
func CountSinceAny(beats []Beat, cutoff time.Time) int {
	n := 0
	for _, b := range beats {
		if b.At.After(cutoff) {
			n++
		}
	}
	return n
}

// NewestBeat returns the most recent beat. Beats are appended in order, but
// this scans rather than taking the last element: the ledger is JSON on disk
// and a hand-edit or a merge could reorder it, and "when did the fleet last
// beat" is exactly the answer nobody should have to distrust.
func NewestBeat(beats []Beat) (Beat, bool) {
	var newest Beat
	found := false
	for _, b := range beats {
		if !found || b.At.After(newest.At) {
			newest, found = b, true
		}
	}
	return newest, found
}

// oldestInWindow finds the earliest CHARGING beat in the window. RetryAfter is
// "when does a slot free up", and only a charging beat occupies one; deriving
// it from an error would tell the operator to wait for quota nothing spent.
func oldestInWindow(beats []Beat, cutoff time.Time) time.Time {
	var oldest time.Time
	for _, b := range beats {
		if b.At.After(cutoff) && b.Outcome.Charges() &&
			(oldest.IsZero() || b.At.Before(oldest)) {
			oldest = b.At
		}
	}
	if oldest.IsZero() {
		return cutoff
	}
	return oldest
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// ShouldAlert reports whether this denial is new enough to be worth an email,
// and marks it. Without this, a six-hour backoff at a two-hour cadence sends
// the same message three times.
func (s *Store) ShouldAlert(l *Ledger, d Decision) bool {
	if d.Allow {
		return false
	}
	key := d.RetryAfter
	if key.IsZero() {
		key = s.now()
	}
	if l.AlertedFor.Equal(key) {
		return false
	}
	l.AlertedFor = key
	return true
}
