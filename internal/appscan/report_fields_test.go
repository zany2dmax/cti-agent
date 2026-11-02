package appscan

import (
	"strings"
	"testing"
)

func TestAnUnreachableScanIsAFaultWithNoCounts(t *testing.T) {
	down := publicScan()
	down.HostsScanned, down.ActiveHosts = 1, 0
	b := Render([]ScanResult{down, deepScan()}, weekEnding())

	if !strings.HasPrefix(b.Subject, "[UNREACHABLE]") && !strings.Contains(b.Subject, "[UNREACHABLE]") {
		t.Errorf("subject = %q", b.Subject)
	}
	if !strings.Contains(b.Text, "no host answered (1 scanned, 0 active)") {
		t.Errorf("no fault line:\n%s", b.Text)
	}
	open := b.Text[strings.Index(b.Text, "OPEN NOW"):]
	open = open[:strings.Index(open, "CHANGED THIS WEEK")]
	if strings.Contains(open, down.App) {
		t.Errorf("an unreachable scan's zeroes are in OPEN NOW:\n%s", open)
	}
	if strings.Contains(b.Text, "authentication failed") {
		t.Error("an unreachable scan was reported as a login failure")
	}
}

func TestARowSaysWhenItHasNoBaselineOrWasRunByHand(t *testing.T) {
	s := deepScan()
	s.FirstScan, s.Launch = true, "Manual"
	s.SensitiveCounts = Counts{Serious: 2}
	b := Render([]ScanResult{s, publicScan()}, weekEnding())
	for _, want := range []string{
		"first scan with this setup",
		"run by hand, not by the schedule",
		"2 sensitive-content finding(s)",
	} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("text has no %q", want)
		}
		if !strings.Contains(b.HTML, want) {
			t.Errorf("HTML has no %q", want)
		}
	}
	// The ordinary scheduled re-scan gets no notes at all.
	if n := rowNotes(publicScan()); len(n) != 0 {
		t.Errorf("notes on an ordinary row: %v", n)
	}
}
