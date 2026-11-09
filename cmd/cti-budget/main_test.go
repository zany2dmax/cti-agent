package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAnUnreadableLedgerFailsClosed: Load returns nil for a ledger it cannot
// read, and every subcommand used to dereference it. A directory stands in for
// an unreadable file, because a chmod does not stop a test run as root.
func TestAnUnreadableLedgerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	ledger := filepath.Join(dir, "budget.json")
	if err := os.Mkdir(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_HOME", dir)
	t.Setenv("FLEET_BUDGET_FILE", ledger)

	out, err := os.CreateTemp(dir, "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	for _, args := range [][]string{
		{"check"},
		{"record", "--outcome", "ok"},
		{"status"},
	} {
		if code := run(args, out, out); code != exitFailure {
			t.Errorf("%v: exit %d, want %d", args, code, exitFailure)
		}
	}
	if fi, err := os.Stat(ledger); err != nil || !fi.IsDir() {
		t.Error("record replaced a ledger it could not read")
	}
}

// TestTheConfiguredCeilingsHaveAHardCeiling: PrimeSec 10786557. A huge
// FLEET_BUDGET_*_BEATS left the brake running but holding nothing.
func TestTheConfiguredCeilingsHaveAHardCeiling(t *testing.T) {
	t.Setenv("FLEET_HOME", t.TempDir())
	t.Setenv("FLEET_BUDGET_WINDOW_BEATS", "999999")
	t.Setenv("FLEET_BUDGET_DAILY_BEATS", "999999")
	s := storeFromEnv()
	if got := s.Limits.WindowBeats; got != maxWindowBeats {
		t.Errorf("WindowBeats = %d, want the hard ceiling %d", got, maxWindowBeats)
	}
	if got := s.Limits.DailyBeats; got != maxDailyBeats {
		t.Errorf("DailyBeats = %d, want the hard ceiling %d", got, maxDailyBeats)
	}

	t.Setenv("FLEET_BUDGET_WINDOW_BEATS", "6")
	t.Setenv("FLEET_BUDGET_DAILY_BEATS", "20")
	s = storeFromEnv()
	if s.Limits.WindowBeats != 6 || s.Limits.DailyBeats != 20 {
		t.Errorf("a raise within the ceiling was not honoured: %+v", s.Limits)
	}
}
