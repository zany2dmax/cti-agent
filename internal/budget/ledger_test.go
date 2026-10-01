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

// ─── errors must not consume quota ──────────────────────────────────────────
//
// Record has always documented this. The code did not do it: countSince
// counted every beat regardless of outcome, so a broken lane rationed the
// fleet for model calls it never made. These tests fail against that code.

func TestAnErrorBeatDoesNotFillTheWindow(t *testing.T) {
	// The 21 September regression, in miniature: the orchestrator could not
	// start, every beat errored, and the fleet reported a budget hold.
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < s.Limits.WindowBeats*3; i++ {
		s.Record(l, OutcomeError, "sandbox refused to start")
		*now = now.Add(time.Minute)
	}
	if d := s.Check(l); !d.Allow {
		t.Fatalf("%d failed beats closed the window: %s", s.Limits.WindowBeats*3, d.Reason)
	}
}

func TestAnErrorBeatDoesNotFillTheDay(t *testing.T) {
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < s.Limits.DailyBeats+5; i++ {
		s.Record(l, OutcomeError, "lane broke")
		*now = now.Add(time.Minute)
	}
	if d := s.Check(l); !d.Allow {
		t.Fatalf("failed beats closed the day: %s", d.Reason)
	}
}

func TestARateLimitStillCharges(t *testing.T) {
	// Being refused is evidence the request reached the service, so it spends.
	//
	// The cooldown would mask this - a held fleet is held either way - so the
	// clock is stepped past the backoff but NOT past the window. Four
	// consecutive rate limits give 30m*2^3 = 4h of backoff against a 5h
	// window, so 4h30m clears the cooldown while the beats are still inside
	// the ceiling. If either limit changes, this test fails loudly rather
	// than passing for the wrong reason.
	s, now := newTestStore(t)
	l, _ := s.Load()

	oldest := *now
	for i := 0; i < s.Limits.WindowBeats; i++ {
		s.Record(l, OutcomeRateLimit, "429")
		*now = now.Add(time.Minute)
	}

	*now = oldest.Add(4*time.Hour + 30*time.Minute)
	if now.Before(l.CooldownUntil) {
		t.Fatalf("test setup: still inside the cooldown until %s", l.CooldownUntil)
	}
	if now.Sub(oldest) >= s.Limits.Window {
		t.Fatalf("test setup: beats aged out of the %s window", s.Limits.Window)
	}

	if d := s.Check(l); d.Allow {
		t.Error("rate-limited beats did not count against the ceiling")
	}
}

func TestErrorsDoNotDilateRetryAfter(t *testing.T) {
	// RetryAfter answers "when does a slot free up". A slot is occupied only
	// by a charging beat, so an error must not be the one the clock runs from.
	s, now := newTestStore(t)
	l, _ := s.Load()

	s.Record(l, OutcomeError, "broke immediately") // oldest beat, charges nothing
	*now = now.Add(30 * time.Minute)

	firstCharged := *now
	for i := 0; i < s.Limits.WindowBeats; i++ {
		s.Record(l, OutcomeOK, "")
		*now = now.Add(time.Minute)
	}

	d := s.Check(l)
	if d.Allow {
		t.Fatal("window should be full")
	}
	want := firstCharged.Add(s.Limits.Window)
	if !d.RetryAfter.Equal(want) {
		t.Errorf("RetryAfter = %s, want %s (derived from the oldest CHARGING beat)",
			d.RetryAfter.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

func TestChargesIsExplicitAboutEveryOutcome(t *testing.T) {
	// A new Outcome must make a deliberate choice here rather than defaulting
	// into "free", which would silently widen the ceiling.
	for _, tc := range []struct {
		o    Outcome
		want bool
	}{
		{OutcomeOK, true},
		{OutcomeRateLimit, true},
		{OutcomeError, false},
	} {
		if got := tc.o.Charges(); got != tc.want {
			t.Errorf("%s.Charges() = %v, want %v", tc.o, got, tc.want)
		}
	}
}

func TestRecordedAndChargedDifferWhenLanesFail(t *testing.T) {
	// The reporting case: "24 recorded, 0 charged" is what makes a silently
	// broken lane visible in `cti-budget status`.
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < 6; i++ {
		s.Record(l, OutcomeError, "")
		*now = now.Add(time.Minute)
	}
	s.Record(l, OutcomeOK, "")

	if len(l.Beats) != 7 {
		t.Fatalf("recorded %d beats, want 7", len(l.Beats))
	}
	if c := CountCharged(l.Beats, now.Add(-48*time.Hour)); c != 1 {
		t.Errorf("charged = %d, want 1", c)
	}
}

func TestNewestBeatIgnoresFileOrder(t *testing.T) {
	// "When did the fleet last beat" must not depend on the JSON being in
	// order on disk. A hand-edit or a merge could reorder it.
	early := base.Add(-10 * time.Hour)
	late := base.Add(-1 * time.Hour)
	beats := []Beat{
		{At: late, Outcome: OutcomeError},
		{At: early, Outcome: OutcomeOK},
	}
	got, ok := NewestBeat(beats)
	if !ok {
		t.Fatal("NewestBeat found nothing in a non-empty ledger")
	}
	if !got.At.Equal(late) {
		t.Errorf("newest = %s, want %s", got.At, late)
	}
	if _, ok := NewestBeat(nil); ok {
		t.Error("an empty ledger reported a newest beat")
	}
}

func TestAStoppedFleetDoesNotReportStaleBeatsAsRecent(t *testing.T) {
	// The misdiagnosis this prevents. Pruning to 48h happens in Save, and Save
	// only runs when a beat is recorded - so a fleet that STOPPED keeps its old
	// beats forever. Counting len(Beats) reported them as current activity and
	// the operator concluded the heartbeat was alive.
	s, now := newTestStore(t)
	l, _ := s.Load()
	for i := 0; i < 24; i++ {
		s.Record(l, OutcomeOK, "")
		*now = now.Add(time.Minute)
	}
	*now = now.Add(5 * 24 * time.Hour) // five days of silence

	if n := len(l.Beats); n != 24 {
		t.Fatalf("stored %d beats, want 24 still on disk", n)
	}
	cutoff := now.Add(-48 * time.Hour)
	if n := CountSinceAny(l.Beats, cutoff); n != 0 {
		t.Errorf("%d beats counted as being in the last 48h, want 0", n)
	}
	if n := CountCharged(l.Beats, cutoff); n != 0 {
		t.Errorf("%d beats counted as charged, want 0", n)
	}
	newest, ok := NewestBeat(l.Beats)
	if !ok {
		t.Fatal("no newest beat")
	}
	if age := now.Sub(newest.At); age < 5*24*time.Hour {
		t.Errorf("newest beat age %s, want at least 5 days", age)
	}
}
