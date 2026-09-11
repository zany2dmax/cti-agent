package budget

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// base is a fixed mid-morning instant. Tests move the clock explicitly rather
// than sleeping, which is the only way to exercise a five-hour window.
var base = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

func newTestStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	now := base
	s := NewStore(filepath.Join(t.TempDir(), "budget.json"), DefaultLimits())
	s.Now = func() time.Time { return now }
	return s, &now
}

func TestFirstBeatOnAFreshInstallIsAllowed(t *testing.T) {
	// Bookkeeping must never be the reason the fleet has not started.
	s, _ := newTestStore(t)
	l, err := s.Load()
	if err != nil {
		t.Fatalf("Load on a missing file should be clean: %v", err)
	}
	if d := s.Check(l); !d.Allow {
		t.Errorf("first beat denied: %s", d.Reason)
	}
}

func TestWindowCeilingStopsABurst(t *testing.T) {
	// The case this exists for: systemd Persistent=true firing every missed
	// beat at once after an outage.
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < s.Limits.WindowBeats; i++ {
		if d := s.Check(l); !d.Allow {
			t.Fatalf("beat %d denied early: %s", i, d.Reason)
		}
		s.Record(l, OutcomeOK, "")
		*now = now.Add(time.Minute)
	}
	d := s.Check(l)
	if d.Allow {
		t.Fatal("a burst past the window ceiling was allowed")
	}
	if d.RetryAfter.IsZero() {
		t.Error("denial should say when to try again")
	}
}

func TestWindowCeilingReleasesAsBeatsAgeOut(t *testing.T) {
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < s.Limits.WindowBeats; i++ {
		s.Record(l, OutcomeOK, "")
		*now = now.Add(time.Minute)
	}
	if s.Check(l).Allow {
		t.Fatal("expected to be at the ceiling")
	}
	*now = now.Add(s.Limits.Window)
	if d := s.Check(l); !d.Allow {
		t.Errorf("window should have rolled off: %s", d.Reason)
	}
}

func TestDailyCeilingBindsEvenWhenTheWindowIsClear(t *testing.T) {
	s, now := newTestStore(t)
	s.Limits.WindowBeats = 1000 // isolate the daily limit
	l, _ := s.Load()
	for i := 0; i < s.Limits.DailyBeats; i++ {
		s.Record(l, OutcomeOK, "")
		*now = now.Add(time.Minute)
	}
	if d := s.Check(l); d.Allow {
		t.Error("daily ceiling did not bind")
	}
}

func TestRateLimitTriggersCooldownEvenWellUnderTheCeilings(t *testing.T) {
	// Being under our own limit says nothing about being under Anthropic's.
	s, _ := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeRateLimit, "429")
	d := s.Check(l)
	if d.Allow {
		t.Fatal("a rate-limited fleet kept going")
	}
	if got := l.CooldownUntil.Sub(base); got != s.Limits.BackoffBase {
		t.Errorf("first cooldown = %s, want %s", got, s.Limits.BackoffBase)
	}
}

func TestBackoffGrowsThenCaps(t *testing.T) {
	s, now := newTestStore(t)
	l, _ := s.Load()
	want := []time.Duration{30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour,
		6 * time.Hour, 6 * time.Hour}
	for i, w := range want {
		s.Record(l, OutcomeRateLimit, "")
		if got := l.CooldownUntil.Sub(*now); got != w {
			t.Errorf("consecutive rate limit %d: cooldown %s, want %s", i+1, got, w)
		}
		*now = now.Add(time.Minute)
	}
}

func TestASuccessfulBeatClearsTheCooldown(t *testing.T) {
	s, now := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeRateLimit, "")
	*now = now.Add(31 * time.Minute)
	s.Record(l, OutcomeOK, "")
	if !l.CooldownUntil.IsZero() {
		t.Error("a clean run should clear the cooldown")
	}
	if d := s.Check(l); !d.Allow {
		t.Errorf("still holding after recovery: %s", d.Reason)
	}
}

func TestAnErrorDoesNotClearTheCooldown(t *testing.T) {
	// A script failure is not evidence that the throttle lifted.
	s, now := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeRateLimit, "")
	*now = now.Add(time.Minute)
	s.Record(l, OutcomeError, "some other breakage")
	if l.CooldownUntil.IsZero() {
		t.Error("cooldown was cleared by an unrelated error")
	}
}

func TestCooldownSurvivesARestart(t *testing.T) {
	// State in memory would mean a reboot loop becomes a hammering loop.
	s, _ := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeRateLimit, "")
	if err := s.Save(l); err != nil {
		t.Fatal(err)
	}
	reloaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if d := s.Check(reloaded); d.Allow {
		t.Error("cooldown did not survive reload")
	}
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	s, _ := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeOK, "")
	if err := s.Save(l); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ledger mode = %o, want 600", fi.Mode().Perm())
	}
	// No temp files left behind: a directory full of .budget-*.tmp would be
	// a slow leak on a box nobody logs into.
	entries, _ := os.ReadDir(filepath.Dir(s.Path))
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSavePrunesAncientHistory(t *testing.T) {
	s, now := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeOK, "old")
	*now = now.Add(72 * time.Hour)
	s.Record(l, OutcomeOK, "new")
	if err := s.Save(l); err != nil {
		t.Fatal(err)
	}
	if len(l.Beats) != 1 {
		t.Errorf("kept %d beats, want 1 after pruning", len(l.Beats))
	}
}

func TestCorruptLedgerFailsOpenWithAWarning(t *testing.T) {
	// Refusing to run because a counter file got truncated would turn a
	// cosmetic problem into an outage.
	s, _ := newTestStore(t)
	if err := os.WriteFile(s.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := s.Load()
	if err == nil {
		t.Error("corruption should be reported")
	}
	if l == nil {
		t.Fatal("a usable empty ledger should still be returned")
	}
	if d := s.Check(l); !d.Allow {
		t.Error("a corrupt ledger should not block the heartbeat")
	}
}

func TestShouldAlertOncePerDistinctDenial(t *testing.T) {
	// A six-hour backoff at a two-hour cadence would otherwise send the same
	// email three times.
	s, now := newTestStore(t)
	l, _ := s.Load()
	s.Record(l, OutcomeRateLimit, "")

	d := s.Check(l)
	if !s.ShouldAlert(l, d) {
		t.Fatal("the first denial should alert")
	}
	*now = now.Add(2 * time.Hour)
	if s.ShouldAlert(l, s.Check(l)) {
		t.Error("the same cooldown alerted twice")
	}

	// A new cooldown is a new event and does alert.
	*now = now.Add(2 * time.Hour)
	s.Record(l, OutcomeRateLimit, "")
	if !s.ShouldAlert(l, s.Check(l)) {
		t.Error("a fresh rate limit should alert again")
	}
}

func TestAllowedBeatsNeverAlert(t *testing.T) {
	s, _ := newTestStore(t)
	l, _ := s.Load()
	if s.ShouldAlert(l, s.Check(l)) {
		t.Error("alerted while everything was fine")
	}
}

func TestCheckDoesNotConsumeBudget(t *testing.T) {
	// Check must be side-effect free apart from alert bookkeeping, or a
	// caller that checks twice would spend two beats for one.
	s, _ := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < 20; i++ {
		if d := s.Check(l); !d.Allow {
			t.Fatalf("check %d denied without any beat being recorded: %s", i, d.Reason)
		}
	}
}
