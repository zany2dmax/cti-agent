package budget

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/statefile"
)

var vnow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func TestValidateAcceptsWhatRecordWrites(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "b.json"), Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	l := &Ledger{}
	for _, o := range []Outcome{OutcomeOK, OutcomeRateLimit, OutcomeError, OutcomeExhausted} {
		s.Record(l, o, "a note")
	}
	if err := l.Validate(vnow); err != nil {
		t.Fatalf("a ledger Record built was refused: %v", err)
	}
	if err := s.Save(l); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRefusesWhatCouldSteerTheCeiling(t *testing.T) {
	for name, l := range map[string]*Ledger{
		"unknown outcome":  {Beats: []Beat{{At: vnow, Outcome: "banana"}}},
		"no time":          {Beats: []Beat{{Outcome: OutcomeOK}}},
		"future beat":      {Beats: []Beat{{At: vnow.Add(48 * time.Hour), Outcome: OutcomeOK}}},
		"long note":        {Beats: []Beat{{At: vnow, Outcome: OutcomeOK, Note: strings.Repeat("x", maxNote+1)}}},
		"cooldown forever": {CooldownUntil: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
		"alert forever":    {AlertedFor: vnow.Add(30 * 24 * time.Hour)},
		"too many beats":   {Beats: make([]Beat, maxBeats+1)},
	} {
		if err := l.Validate(vnow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// small clock skew and a weekly-limit cooldown are normal
	ok := &Ledger{Beats: []Beat{{At: vnow.Add(10 * time.Minute), Outcome: OutcomeOK}}, CooldownUntil: vnow.Add(6 * 24 * time.Hour)}
	if err := ok.Validate(vnow); err != nil {
		t.Errorf("normal state refused: %v", err)
	}
}

// Save never writes an out-of-bounds ledger: it brings the ledger within bounds
// first (and Validate is the check that it did), so the beat that was just
// recorded is not lost to a refused write.
func TestSaveWritesARepairedLedgerNeverAnOutOfBoundsOne(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	s := &Store{Path: p, Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	bad := &Ledger{
		Beats:         []Beat{{At: vnow, Outcome: OutcomeOK}, {At: vnow.Add(100 * time.Hour), Outcome: "banana"}},
		CooldownUntil: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := s.Save(bad); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var onDisk Ledger
	if err := statefile.Read(p, &onDisk, statefile.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := onDisk.Validate(vnow); err != nil {
		t.Fatalf("an out-of-bounds ledger reached the disk: %v", err)
	}
	if onDisk.CooldownUntil.After(vnow.Add(DefaultLimits().BackoffMax)) || len(onDisk.Beats) != 2 {
		t.Errorf("repair should pull the cooldown in and keep every beat: %+v", onDisk)
	}
}

// A file that parses but could not have been written by us is REPAIRED, not
// thrown away: resetting the ledger would clear both ceilings and the cooldown.
// The repair errs toward spending less.
func TestLoadRepairsAnInvalidLedgerInsteadOfResettingIt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	body := `{"beats":[` +
		`{"at":"2026-11-19T11:30:00Z","outcome":"ok"},` +
		`{"at":"2099-01-01T00:00:00Z","outcome":"ratelimit"},` + // a clock that stepped back
		`{"at":"2026-11-19T11:40:00Z","outcome":"banana"}` + // unknown outcome
		`],"cooldown_until":"9999-01-01T00:00:00Z"}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Path: p, Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	l, err := s.Load()
	if err != nil {
		t.Fatalf("a ledger that parses must not be refused: %v", err)
	}
	if len(l.Beats) != 3 {
		t.Fatalf("beats were dropped (that would hand the heartbeat spare quota): %+v", l.Beats)
	}
	if !l.Beats[1].At.Equal(vnow) || l.Beats[1].Outcome != OutcomeRateLimit {
		t.Errorf("a future beat should count as now: %+v", l.Beats[1])
	}
	if l.Beats[2].Outcome != OutcomeError {
		t.Errorf("an unknown outcome should count as an error: %+v", l.Beats[2])
	}
	if want := vnow.Add(DefaultLimits().BackoffMax); !l.CooldownUntil.Equal(want) {
		t.Errorf("the cooldown should be pulled in to the longest backoff, not cleared: %v", l.CooldownUntil)
	}
	if err := l.Validate(vnow); err != nil {
		t.Errorf("a repaired ledger must validate: %v", err)
	}
	// and it can be saved
	if err := s.Save(l); err != nil {
		t.Errorf("a repaired ledger could not be saved: %v", err)
	}
}

// An unparseable ledger is still reset, loudly: the policy for a damaged file.
func TestLoadStillResetsAnUnparseableLedger(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Path: p, Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	l, err := s.Load()
	if err == nil || !strings.Contains(err.Error(), "corrupt, starting fresh") || l == nil || len(l.Beats) != 0 {
		t.Fatalf("l=%v err=%v", l, err)
	}
}

// A backoff longer than the ledger accepts must still be recorded: dropping the
// beat would fail open.
func TestAnOverlongBackoffIsClampedNotDropped(t *testing.T) {
	lim := DefaultLimits()
	lim.BackoffMax = 30 * 24 * time.Hour // a month
	s := &Store{Path: filepath.Join(t.TempDir(), "b.json"), Limits: lim, Now: func() time.Time { return vnow }}
	l := &Ledger{}
	s.Record(l, OutcomeExhausted, "out of credit")
	if err := s.Save(l); err != nil {
		t.Fatalf("the beat that earned the cooldown was refused: %v", err)
	}
	got, err := s.Load()
	if err != nil || got.CooldownUntil.IsZero() || !got.CooldownUntil.Before(vnow.Add(8*24*time.Hour)) || len(got.Beats) != 1 {
		t.Fatalf("cooldown %v, beats %d, err %v", got.CooldownUntil, len(got.Beats), err)
	}
}

func TestRecordClipsALongNoteWithoutSplittingACharacter(t *testing.T) {
	s := &Store{Path: filepath.Join(t.TempDir(), "b.json"), Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	l := &Ledger{}
	s.Record(l, OutcomeError, strings.Repeat("é", 600)) // two bytes each
	n := l.Beats[0].Note
	if len(n) > maxNote || strings.ContainsRune(n, '�') {
		t.Fatalf("note %d bytes: %q", len(n), n[len(n)-4:])
	}
	if err := l.Validate(vnow); err != nil {
		t.Fatal(err)
	}
}
