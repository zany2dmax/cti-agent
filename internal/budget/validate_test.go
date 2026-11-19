package budget

import (
	"errors"
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

func TestARefusedSaveLeavesTheLedgerAlone(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	s := &Store{Path: p, Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	good := &Ledger{}
	s.Record(good, OutcomeOK, "")
	if err := s.Save(good); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	bad := &Ledger{CooldownUntil: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.Save(bad); !errors.Is(err, statefile.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Error("a refused save changed the file")
	}
}

// A file that parses but could not have been written by us is treated like a
// corrupt one: start fresh, loudly. It must not be trusted as a real ceiling.
func TestLoadTreatsAnInvalidLedgerAsCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, []byte(`{"beats":[],"cooldown_until":"9999-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Store{Path: p, Limits: DefaultLimits(), Now: func() time.Time { return vnow }}
	l, err := s.Load()
	if err == nil || !strings.Contains(err.Error(), "corrupt, starting fresh") {
		t.Fatalf("err = %v", err)
	}
	if l == nil || !l.CooldownUntil.IsZero() || len(l.Beats) != 0 {
		t.Fatalf("the ledger was not reset: %+v", l)
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
