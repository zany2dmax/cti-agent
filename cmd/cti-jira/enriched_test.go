package main

import (
	"context"
	"errors"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/vulnlookup"
)

func quiet(string, ...any) {}

func row(cve, priority, status string, kev any, hostCount int) enrichedRow {
	return enrichedRow{
		CVE: cve, Priority: priority, Status: status, KEV: kev,
		HostCount: hostCount, QIDs: "92101, 92145",
	}
}

// stubFill answers with a fixed host list, so selection can be tested without
// a scanner.
func stubFill(hosts []string, count int, floor bool) hostFiller {
	return func(_ context.Context, cve string) (vulnlookup.Result, error) {
		return vulnlookup.Result{
			CVE: cve, Status: vulnlookup.StatusPresent,
			Hosts: hosts, HostCount: count, HostCountIsFloor: floor,
			ExternalIDs: []string{"92101", "92145"},
		}, nil
	}
}

func TestOnlyPresentKEVOrSev5IsTicketed(t *testing.T) {
	rows := []enrichedRow{
		row("CVE-1", "Sev5", "PRESENT", 0, 5),      // Sev5, present
		row("CVE-2", "Sev1", "PRESENT", 1, 2),      // KEV outranks the band
		row("CVE-3", "Sev4", "PRESENT", 0, 99),     // below the bar
		row("CVE-4", "Sev5", "NOT_PRESENT", 1, 0),  // KEV, but not in the estate
		row("CVE-5", "Sev5", "UNKNOWN", 1, 0),      // no detections to act on
	}
	got := selectForTicketing(context.Background(), rows,
		stubFill([]string{"a.example.com"}, 1, false), quiet)

	if len(got) != 2 {
		t.Fatalf("selected %d findings, want 2: %+v", len(got), got)
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.CVE] = true
	}
	if !seen["CVE-1"] || !seen["CVE-2"] {
		t.Errorf("wrong selection: %v", seen)
	}
}

func TestANotPresentKEVIsNotTicketed(t *testing.T) {
	// A ticket for a CVE the scanner cannot find is noise aimed at IT, and it
	// would carry an empty host list - the thing that makes a ticket useless.
	rows := []enrichedRow{row("CVE-2026-1", "Sev5", "NOT_PRESENT", 1, 0)}
	if got := selectForTicketing(context.Background(), rows,
		stubFill(nil, 0, false), quiet); len(got) != 0 {
		t.Errorf("filed a ticket for a CVE that is not in the estate: %+v", got)
	}
}

func TestTheScannerCountWinsOverTheDigestCount(t *testing.T) {
	// The enriched file is a snapshot from earlier in the run; the host names
	// come from the lookup that happens now. Reporting the older number next
	// to the newer names would make the ticket contradict its own CSV.
	rows := []enrichedRow{row("CVE-1", "Sev5", "PRESENT", 1, 200)}
	got := selectForTicketing(context.Background(), rows,
		stubFill([]string{"a", "b", "c"}, 361, true), quiet)
	if len(got) != 1 {
		t.Fatal("expected one finding")
	}
	if got[0].Count() != 361 {
		t.Errorf("Count() = %d, want the scanner's 361", got[0].Count())
	}
	if !got[0].HostFloor() {
		t.Error("the floor flag did not survive selection")
	}
}

func TestALookupFailureDropsOneFindingNotTheRun(t *testing.T) {
	// A scanner hiccup should cost one ticket. This lane runs between enrich
	// and brief, so anything that aborts it delays the security email.
	boom := func(_ context.Context, cve string) (vulnlookup.Result, error) {
		if cve == "CVE-BAD" {
			return vulnlookup.Result{}, errors.New("429 from the scanner")
		}
		return vulnlookup.Result{Status: vulnlookup.StatusPresent,
			Hosts: []string{"a"}, HostCount: 1}, nil
	}
	rows := []enrichedRow{
		row("CVE-BAD", "Sev5", "PRESENT", 1, 1),
		row("CVE-OK", "Sev5", "PRESENT", 1, 1),
	}
	var warned int
	got := selectForTicketing(context.Background(), rows, boom,
		func(string, ...any) { warned++ })

	if len(got) != 1 || got[0].CVE != "CVE-OK" {
		t.Errorf("a failed lookup took out the whole run: %+v", got)
	}
	if warned != 1 {
		t.Errorf("the dropped finding was not reported: %d warnings", warned)
	}
}

func TestWorstFirst(t *testing.T) {
	// A run that dies part-way should have filed the biggest exposure first.
	rows := []enrichedRow{
		row("CVE-SMALL", "Sev5", "PRESENT", 1, 1),
		row("CVE-BIG", "Sev5", "PRESENT", 1, 1),
		row("CVE-LOW", "Sev1", "PRESENT", 1, 1),
	}
	fill := func(_ context.Context, cve string) (vulnlookup.Result, error) {
		n := 5
		if cve == "CVE-BIG" {
			n = 500
		}
		return vulnlookup.Result{Status: vulnlookup.StatusPresent,
			Hosts: make([]string, n), HostCount: n}, nil
	}
	got := selectForTicketing(context.Background(), rows, fill, quiet)
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].CVE != "CVE-BIG" {
		t.Errorf("order = %s first, want CVE-BIG", got[0].CVE)
	}
	if got[2].CVE != "CVE-LOW" {
		t.Errorf("lowest severity should sort last, got %s", got[2].CVE)
	}
}

func TestSeverityUnderstandsBothScales(t *testing.T) {
	// An enriched file written before the P1-P4 -> Sev5-Sev1 rename can still
	// be replayed. Scoring every old row 0 would file nothing and explain
	// nothing.
	for in, want := range map[string]int{
		"Sev5": 5, "Sev1": 1, "P1": 5, "P2": 4, "P4": 2,
		"": 0, "nonsense": 0,
	} {
		if got := severity(in); got != want {
			t.Errorf("severity(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestTheKEVFlagSurvivesEveryShapeItHasHad(t *testing.T) {
	for _, v := range []any{1.0, "1", "true", true} {
		if !truthy(v) {
			t.Errorf("truthy(%#v) = false", v)
		}
	}
	for _, v := range []any{0.0, "0", "", nil, false} {
		if truthy(v) {
			t.Errorf("truthy(%#v) = true", v)
		}
	}
}

func TestTheTicketMapSitsBesideTheFileItDescribes(t *testing.T) {
	// So that replaying an old day reads that day's tickets, not today's.
	got := TicketMapPath("/var/lib/cti-agent/state/enriched-2026-10-02.json")
	want := "/var/lib/cti-agent/state/enriched-2026-10-02-tickets.json"
	if got != want {
		t.Errorf("TicketMapPath = %q, want %q", got, want)
	}
}

func TestATitleIsOneClauseNotAWholeAdvisory(t *testing.T) {
	r := enrichedRow{
		CVE: "CVE-1", Priority: "Sev5", Status: "PRESENT", KEV: 1.0,
		Desc: "A use-after-free was addressed. This issue is fixed in many " +
			"products and the rest of this paragraph is not a ticket title.",
	}
	f := r.toFinding()
	if f.Title != "A use-after-free was addressed" {
		t.Errorf("Title = %q", f.Title)
	}
}
