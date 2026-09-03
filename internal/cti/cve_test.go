package cti

import (
	"sort"
	"testing"
)

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

func TestCVELessOrdersNumericallyNotLexicographically(t *testing.T) {
	// The bug this guards: plain string comparison put CVE-2026-9586 after
	// CVE-2026-83549, because '9' > '8'. Sequence numbers are variable
	// length, so lexicographic order interleaves them meaninglessly.
	in := []string{
		"CVE-2026-18672", "CVE-2026-19219", "CVE-2026-58400",
		"CVE-2026-63219", "CVE-2026-83548", "CVE-2026-83549", "CVE-2026-9586",
	}
	want := []string{
		"CVE-2026-9586", "CVE-2026-18672", "CVE-2026-19219", "CVE-2026-58400",
		"CVE-2026-63219", "CVE-2026-83548", "CVE-2026-83549",
	}
	got := append([]string(nil), in...)
	sort.Slice(got, func(i, j int) bool { return CVELess(got[i], got[j]) })
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %s, want %s\nfull order: %v", i, got[i], want[i], got)
		}
	}
}

func TestCVELessSortsByYearFirst(t *testing.T) {
	if !CVELess("CVE-2008-4250", "CVE-2026-1") {
		t.Error("an older year must sort first regardless of sequence number")
	}
	if CVELess("CVE-2026-1", "CVE-2008-4250") {
		t.Error("comparison is not antisymmetric across years")
	}
}

func TestCVELessIsAStrictWeakOrdering(t *testing.T) {
	// sort.Slice requires this; violating it can panic or corrupt the order.
	ids := []string{"CVE-2026-1", "CVE-2026-2", "CVE-2025-9999", "CVE-2026-1"}
	for _, a := range ids {
		if CVELess(a, a) {
			t.Errorf("CVELess(%s, %s) must be false", a, a)
		}
		for _, b := range ids {
			if a != b && CVELess(a, b) && CVELess(b, a) {
				t.Errorf("both CVELess(%s,%s) and CVELess(%s,%s) are true", a, b, b, a)
			}
		}
	}
}

func TestCVELessPutsMalformedIDsLast(t *testing.T) {
	// A malformed ID should be visible in the report, not silently reorder
	// everything around it.
	if !CVELess("CVE-2026-1", "not-a-cve") {
		t.Error("a valid CVE must sort before a malformed one")
	}
	if CVELess("not-a-cve", "CVE-2026-1") {
		t.Error("a malformed ID must not sort before a valid one")
	}
	got := []string{"zzz", "CVE-2026-5", "aaa"}
	sort.Slice(got, func(i, j int) bool { return CVELess(got[i], got[j]) })
	if got[0] != "CVE-2026-5" {
		t.Errorf("valid CVE should lead: %v", got)
	}
}
