package kev

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 15, 14, 30, 0, 0, time.UTC)

func f(cve, status string, hosts int, due string) Finding {
	return Finding{CVE: cve, Status: status, HostCount: hosts, KEVDue: due, KEV: 1,
		Priority: "P1"}
}

func TestDaysLeftComparesCalendarDaysNotInstants(t *testing.T) {
	// A deadline is a date. Using wall-clock time would flip "due today" to
	// overdue at noon, which is both wrong and impossible to explain.
	d, ok := f("CVE-1", "PRESENT", 1, "2026-09-15").DaysLeft(now)
	if !ok || d != 0 {
		t.Errorf("due today gave (%d,%v), want (0,true) even at 14:30", d, ok)
	}
}

func TestDaysLeftSigns(t *testing.T) {
	for _, tc := range []struct {
		due  string
		want int
	}{
		{"2026-09-01", -14},
		{"2026-09-14", -1},
		{"2026-09-15", 0},
		{"2026-09-16", 1},
		{"2026-10-15", 30},
	} {
		got, ok := f("CVE-1", "PRESENT", 1, tc.due).DaysLeft(now)
		if !ok || got != tc.want {
			t.Errorf("due %s -> (%d,%v), want %d", tc.due, got, ok, tc.want)
		}
	}
}

func TestDaysLeftDistinguishesAbsentFromZero(t *testing.T) {
	// "No deadline" and "due today" must not collapse into the same zero.
	for _, due := range []string{"", "   ", "not-a-date", "2026-13-45", "2026"} {
		if _, ok := f("CVE-1", "PRESENT", 1, due).DaysLeft(now); ok {
			t.Errorf("due %q reported a usable deadline", due)
		}
	}
}

func TestPresentRequiresHostsNotJustStatus(t *testing.T) {
	// PRESENT with zero hosts is a provider quirk, not an exposure.
	if f("CVE-1", "PRESENT", 0, "2026-09-01").Present() {
		t.Error("PRESENT with 0 hosts counted as present")
	}
	if !f("CVE-1", "present", 1, "2026-09-01").Present() {
		t.Error("case-insensitive PRESENT with hosts should count")
	}
}

func TestAnalyzeOnlyCountsWhatWeActuallyRun(t *testing.T) {
	// The central rule: a deadline on a CVE we do not have is not an
	// obligation. Counting those inflates the number and destroys trust in
	// the section the first time someone checks one.
	e := &Enriched{Findings: []Finding{
		f("CVE-A", "PRESENT", 5, "2026-09-01"),     // overdue, ours
		f("CVE-B", "NOT_PRESENT", 0, "2026-09-01"), // overdue, not ours
		f("CVE-C", "UNKNOWN", 0, "2026-09-01"),     // overdue, unverified
	}}
	r := Analyze(e, now, 14)
	if len(r.Overdue) != 1 || r.Overdue[0].CVE != "CVE-A" {
		t.Errorf("overdue = %+v, want only CVE-A", cveList(r.Overdue))
	}
	if r.NotHere != 1 {
		t.Errorf("NotHere = %d, want 1", r.NotHere)
	}
	if r.Unverified != 1 {
		t.Errorf("Unverified = %d, want 1 - UNKNOWN is not the same as clean", r.Unverified)
	}
}

func TestAnalyzeBands(t *testing.T) {
	e := &Enriched{Findings: []Finding{
		f("CVE-OVERDUE", "PRESENT", 1, "2026-09-10"),
		f("CVE-TODAY", "PRESENT", 1, "2026-09-15"),
		f("CVE-SOON", "PRESENT", 1, "2026-09-25"),
		f("CVE-LATER", "PRESENT", 1, "2026-12-01"),
	}}
	r := Analyze(e, now, 14)
	if got := cveList(r.Overdue); len(got) != 1 || got[0] != "CVE-OVERDUE" {
		t.Errorf("overdue = %v", got)
	}
	// Due today belongs in "soon", not "overdue" - the day is not over.
	if got := cveList(r.DueSoon); len(got) != 2 || got[0] != "CVE-TODAY" {
		t.Errorf("due soon = %v, want CVE-TODAY then CVE-SOON", got)
	}
	if got := cveList(r.Later); len(got) != 1 || got[0] != "CVE-LATER" {
		t.Errorf("later = %v", got)
	}
}

func TestOverdueOrderedByHowLateNotByHostCount(t *testing.T) {
	// A deadline missed a month ago outranks one missed yesterday on more
	// machines. Host count is the tiebreaker, not the driver.
	e := &Enriched{Findings: []Finding{
		f("CVE-YESTERDAY", "PRESENT", 400, "2026-09-14"),
		f("CVE-MONTH", "PRESENT", 2, "2026-08-15"),
	}}
	r := Analyze(e, now, 14)
	if got := cveList(r.Overdue); got[0] != "CVE-MONTH" {
		t.Errorf("order = %v, want the month-old breach first", got)
	}
	if r.WorstOverdueDays() != 31 {
		t.Errorf("WorstOverdueDays = %d, want 31", r.WorstOverdueDays())
	}
}

func TestEqualDaysFallsBackToBlastRadius(t *testing.T) {
	e := &Enriched{Findings: []Finding{
		f("CVE-SMALL", "PRESENT", 3, "2026-09-10"),
		f("CVE-BIG", "PRESENT", 300, "2026-09-10"),
	}}
	r := Analyze(e, now, 14)
	if got := cveList(r.Overdue); got[0] != "CVE-BIG" {
		t.Errorf("order = %v, want the wider exposure first when equally late", got)
	}
}

func TestRansomwareCountedAcrossAllBandsButOnlyWhenPresent(t *testing.T) {
	mk := func(cve, status string, hosts int, due, rw string) Finding {
		x := f(cve, status, hosts, due)
		x.Ransomware = rw
		return x
	}
	e := &Enriched{Findings: []Finding{
		mk("CVE-1", "PRESENT", 1, "2026-09-01", "Known"),
		mk("CVE-2", "PRESENT", 1, "2026-12-01", "known"),
		mk("CVE-3", "NOT_PRESENT", 0, "2026-09-01", "Known"),
		mk("CVE-4", "PRESENT", 1, "2026-09-01", "Unknown"),
	}}
	if got := Analyze(e, now, 14).RansomwareCount(); got != 2 {
		t.Errorf("RansomwareCount = %d, want 2 (present only, any band)", got)
	}
}

func TestCleanMeansNothingActionable(t *testing.T) {
	// A far-future deadline is not something to act on today, so a report
	// containing only those is clean - otherwise --quiet would print daily
	// and teach the reader to skip it.
	e := &Enriched{Findings: []Finding{f("CVE-LATER", "PRESENT", 1, "2026-12-01")}}
	if !Analyze(e, now, 14).Clean() {
		t.Error("only-far-future should be Clean")
	}
	e.Findings = append(e.Findings, f("CVE-OVERDUE", "PRESENT", 1, "2026-09-01"))
	if Analyze(e, now, 14).Clean() {
		t.Error("an overdue finding is not Clean")
	}
}

func TestFindingsWithoutDeadlinesAreIgnoredEntirely(t *testing.T) {
	e := &Enriched{Findings: []Finding{
		{CVE: "CVE-NOKEV", Status: "PRESENT", HostCount: 9},
	}}
	r := Analyze(e, now, 14)
	if len(r.Overdue)+len(r.DueSoon)+len(r.Later) != 0 || r.NotHere != 0 || r.Unverified != 0 {
		t.Errorf("a finding with no KEV deadline leaked into the report: %+v", r)
	}
}

func TestMarkdownNamesTheOverdueAndTheUnverified(t *testing.T) {
	e := &Enriched{Findings: []Finding{
		f("CVE-2026-1111", "PRESENT", 12, "2026-08-20"),
		f("CVE-2026-2222", "UNKNOWN", 0, "2026-09-01"),
	}}
	md := Analyze(e, now, 14).Markdown(false)
	for _, want := range []string{"OVERDUE", "CVE-2026-1111", "-26", "coverage UNVERIFIED", "we did not look"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	// Hostnames must not appear unless asked for.
	if strings.Contains(md, "Sample hosts") {
		t.Error("hostnames rendered without --hosts")
	}
}

func TestMarkdownHostsAreOptIn(t *testing.T) {
	x := f("CVE-1", "PRESENT", 2, "2026-08-20")
	x.Hosts = "web01, web02"
	md := Analyze(&Enriched{Findings: []Finding{x}}, now, 14).Markdown(true)
	if !strings.Contains(md, "web01") {
		t.Error("--hosts should include sample hostnames")
	}
}

func TestMarkdownSaysSoWhenThereIsNothingToDo(t *testing.T) {
	md := Analyze(&Enriched{}, now, 14).Markdown(false)
	if !strings.Contains(md, "Nothing overdue") {
		t.Errorf("an empty report should say so plainly:\n%s", md)
	}
}

func TestLoadRejectsGarbageWithAUsableMessage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "enriched-2026-09-15.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "not valid enriched JSON") {
		t.Errorf("error should name the problem, got: %v", err)
	}
}

func TestLoadRoundTripsWhatEnrichActuallyWrites(t *testing.T) {
	// Guards against the decoder drifting from the lane's field names, which
	// would silently produce an empty report rather than an error.
	raw := `{"generated":"2026-09-15T06:00:00Z","total":2,"degraded":[],
	 "findings":[{"cve":"CVE-2026-1","status":"PRESENT","host_count":3,
	   "qids":"92345","priority":"P1","kev":1,"kev_due":"2026-09-01",
	   "ransomware":"Known","epss":0.64,"cvss":9.8,"sample_hosts":"a, b"}]}`
	dir := t.TempDir()
	p := filepath.Join(dir, "enriched-2026-09-15.json")
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Findings) != 1 {
		t.Fatalf("decoded %d findings", len(e.Findings))
	}
	got := e.Findings[0]
	if got.CVE != "CVE-2026-1" || got.HostCount != 3 || got.KEVDue != "2026-09-01" ||
		!got.IsRansomware() || got.EPSS != 0.64 {
		b, _ := json.Marshal(got)
		t.Errorf("field mapping drifted: %s", b)
	}
	r := Analyze(e, now, 14)
	if len(r.Overdue) != 1 {
		t.Errorf("expected the overdue finding to be recognised, got %+v", r)
	}
}

func cveList(rows []Dated) []string {
	out := make([]string, 0, len(rows))
	for _, d := range rows {
		out = append(out, d.CVE)
	}
	return out
}
