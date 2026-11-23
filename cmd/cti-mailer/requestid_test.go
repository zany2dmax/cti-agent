package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheRequestIDFileIsWrittenWhole(t *testing.T) {
	p := filepath.Join(t.TempDir(), "enriched-2026-11-22-request-id")
	if err := os.WriteFile(p, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeRequestID(p, "0f1e2d3c-aaaa-bbbb-cccc-1234567890ab"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "0f1e2d3c-aaaa-bbbb-cccc-1234567890ab\n" {
		t.Fatalf("%q %v", b, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if err := writeRequestID(filepath.Join(t.TempDir(), "no", "such", "dir"), "x"); err == nil {
		t.Error("a missing directory was not an error")
	}
}
