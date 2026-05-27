package cti

import "testing"

func TestExtractCVEs(t *testing.T) {
	got := ExtractCVEs("foo CVE-2026-9082 bar cve-2025-12345 CVE-2026-9082")
	want := []string{"CVE-2025-12345", "CVE-2026-9082"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
