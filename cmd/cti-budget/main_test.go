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
