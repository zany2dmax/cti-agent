package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnrichedIsConfinedToTheFleetsState(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(state, "enriched-2026-11-03.json")
	outside := filepath.Join(home, "enriched-2026-11-03.json")
	secret := filepath.Join(home, "fleet.env")
	link := filepath.Join(state, "enriched-link.json")
	wrongName := filepath.Join(state, "budget.json")
	for _, p := range []string{good, outside, secret, wrongName} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(state, "enriched-dir.json"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := confineEnriched(good, home); err != nil {
		t.Errorf("%s refused: %v", good, err)
	}
	if _, err := confineEnriched(outside, ""); err != nil {
		t.Errorf("without FLEET_HOME, %s refused: %v", outside, err)
	}
	for _, p := range []string{
		secret, outside, link, wrongName, filepath.Join(state, "enriched-dir.json"),
		filepath.Join(state, "..", "fleet.env"), filepath.Join(state, "missing-enriched.json"),
	} {
		if _, err := confineEnriched(p, home); err == nil {
			t.Errorf("%s accepted, want refused", p)
		}
	}
	if _, err := confineEnriched(secret, ""); err == nil {
		t.Errorf("without FLEET_HOME, %s accepted by name, want refused", secret)
	}
}
