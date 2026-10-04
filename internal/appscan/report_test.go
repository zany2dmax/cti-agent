package appscan

import (
	"strings"
	"testing"
	"time"
)

func weekEnding() time.Time { return time.Date(2026, 10, 4, 0, 0, 0, 0, time.UTC) }

// blindScan mirrors the real unauthenticated scan: a wide crawl that found
// nothing, because it was never able to look past the login.
func blindScan() ScanResult {
	return ScanResult{
		Provider: "qualys-was", App: "Example Site", Complete: true,
		Status: "Finished : OK", LinksCrawled: 252,
		Auth:       Auth{Record: "", Status: "No Authentication specified"},
		ScanCounts: Counts{Serious: 1, Medium: 2, Minimal: 50},
		AppState: Lifecycle{
			Total:    Counts{Crit: 1, Serious: 16, Medium: 11, Minimal: 111},
			Active:   Counts{Serious: 1, Medium: 2, Minimal: 67},
			Reopened: Counts{Minimal: 5},
			Fixed:    Counts{Crit: 1, Serious: 15, Medium: 9, Minimal: 39},
		},
	}
}

// deepScan mirrors the real authenticated scan: a narrow crawl that found a
// great deal.
func deepScan() ScanResult {
	return ScanResult{
		Provider: "qualys-was", App: "Example Portal", Complete: true,
		Status: "Finished : OK", LinksCrawled: 67,
		Auth:       Auth{Record: "portal auth record", Status: "Successful"},
		ScanCounts: Counts{Urgent: 20, Crit: 4, Serious: 24, Medium: 8, Minimal: 2},
		AppState: Lifecycle{
			Total:    Counts{Urgent: 270, Crit: 100, Serious: 771, Medium: 102, Minimal: 27},
			Active:   Counts{Urgent: 23, Crit: 2, Serious: 21, Medium: 8, Minimal: 2},
			New:      Counts{Crit: 2, Serious: 1},
			Reopened: Counts{Serious: 4},
			Fixed:    Counts{Urgent: 247, Crit: 96, Serious: 745, Medium: 94, Minimal: 25},
		},
		ReportURL: "https://qualysguard.qg3.apps.qualys.com/was/#/reports/x",
		Findings: []Finding{
			{ID: "150084", Title: "Reflected Cross-Site Scripting", Severity: 5,
				URL: "https://portal.example/search", Param: "q", Status: "NEW"},
			{ID: "150003", Title: "SQL Injection", Severity: 4,
				URL: "https://portal.example/report", Param: "id", Status: "NEW"},
			{ID: "150124", Title: "Cookie Without Secure Flag", Severity: 3,
				URL: "https://portal.example/login", Status: "REOPENED"},
			{ID: "150999", Title: "Old news", Severity: 5,
				URL: "https://portal.example/x", Status: "ACTIVE"},
		},
	}
}

func render(t *testing.T, scans ...ScanResult) Block {
	t.Helper()
	return Render(scans, weekEnding())
}

// ─── the coverage gap ───────────────────────────────────────────────────────

func TestAnUnauthenticatedScanLeadsTheReport(t *testing.T) {
	// It comes before any vulnerability count. A scan that ran without
	// authentication did not find nothing - it was never able to look.
	// Sorting it in among real results by severity puts the least-known
	// application at the bottom of the page looking like the best one.
	b := render(t, deepScan(), blindScan())

	gap := strings.Index(b.Text, "COVERAGE GAPS")
	open := strings.Index(b.Text, "OPEN NOW")
	if gap < 0 {
		t.Fatalf("no coverage section:\n%s", b.Text)
	}
	if gap > open {
		t.Error("coverage gaps appear below the finding counts")
	}
	if !strings.Contains(b.Text, "not evidence") {
		t.Error("the report does not say the zeroes are not evidence")
	}
}

func TestTheCaveatTravelsWithTheNumber(t *testing.T) {
	// Not only in the section above. A zero from a blind scan read on its own
	// is the entire failure mode, so the qualifier goes everywhere the number
	// goes.
	b := render(t, deepScan(), blindScan())
	for _, line := range strings.Split(b.Text, "\n") {
		if strings.Contains(line, "Example Site") && strings.Contains(line, "Serious") {
			if !strings.Contains(line, "unauthenticated") {
				t.Errorf("an unqualified count line: %q", line)
			}
			return
		}
	}
	t.Error("no OPEN NOW line found for the blind scan")
}

func TestAConfiguredButFailedLoginIsAlsoACoverageGap(t *testing.T) {
	s := blindScan()
	s.Auth = Auth{Record: "portal auth record", Status: "Failed"}
	b := render(t, s)

	if !strings.Contains(b.Text, "COVERAGE GAPS") {
		t.Error("a failed login was not treated as a gap")
	}
	if !strings.Contains(b.Text, "but failed") {
		t.Errorf("the report does not distinguish configured-and-failed from "+
			"never-configured:\n%s", b.Text)
	}
}

func TestTheSubjectLeadsWithTheGapNotTheCount(t *testing.T) {
	// "23 Urgent open" is a known quantity somebody is working through. "One
	// application cannot be assessed" is a question nobody has answered.
	b := render(t, deepScan(), blindScan())
	if !strings.Contains(b.Subject, "without authentication") {
		t.Errorf("Subject = %q", b.Subject)
	}

	// With nothing blind, the count leads.
	b2 := render(t, deepScan())
	if !strings.Contains(b2.Subject, "23 Urgent") {
		t.Errorf("Subject = %q, want the open Urgent count", b2.Subject)
	}
}

// ─── the two count systems ──────────────────────────────────────────────────

func TestOpenNowReportsActiveNotLifecycleTotals(t *testing.T) {
	// The application carries 270 "Urgent" on record, of which 247 are Fixed.
	// Leading with 270 would be a false alarm an order of magnitude too large.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "23 Urgent") {
		t.Errorf("Active Urgent not reported:\n%s", b.Text)
	}
	if strings.Contains(b.Text, "270") {
		t.Errorf("a lifecycle total reached the report:\n%s", b.Text)
	}
}

func TestLowSeveritiesAreCountedNotLedWith(t *testing.T) {
	// 67 Minimal dominated the line in the first draft, pushing the one
	// number that matters off to the right. They are a tail now - present,
	// because silence and zero must not look the same, but not prominent.
	b := render(t, blindScan())
	if !strings.Contains(b.Text, "+69 lower") {
		t.Errorf("lower severities were not summarised:\n%s", b.Text)
	}
	if strings.Contains(b.Text, "67 Minimal") {
		t.Errorf("a Minimal count still leads a line:\n%s", b.Text)
	}
}

func TestAnApplicationWithNothingOpenSaysSo(t *testing.T) {
	s := deepScan()
	s.AppState.Active = Counts{}
	s.AppState.New = Counts{}
	s.AppState.Reopened = Counts{}
	if b := render(t, s); !strings.Contains(b.Text, "nothing open") {
		t.Errorf("an application with no open findings was rendered blank:\n%s", b.Text)
	}
}

// ─── what changed ───────────────────────────────────────────────────────────

func TestChangedUsesTheSameFloorAsAttention(t *testing.T) {
	// The two disagreeing is how an unauthenticated scan's five reopened
	// Minimal findings became the lead item in the section meant to carry
	// the week's actionable news.
	b := render(t, deepScan(), blindScan())

	changed := b.Text[strings.Index(b.Text, "CHANGED THIS WEEK"):]
	if strings.Contains(changed, "Example Site  ") {
		t.Errorf("Minimal-only churn was listed as a change:\n%s", changed)
	}
	if !strings.Contains(changed, "Example Portal") {
		t.Error("the application with 2 new Critical was not listed")
	}
}

func TestLowerSeverityChurnIsCountedRatherThanDropped(t *testing.T) {
	// Quiet is not the same as absent.
	b := render(t, deepScan(), blindScan())
	if !strings.Contains(b.Text, "1 other application(s) had Medium or Minimal") {
		t.Errorf("churn below the floor vanished entirely:\n%s", b.Text)
	}
}

func TestOnlyNewAndReopenedFindingsGetDetail(t *testing.T) {
	// The backlog is a remediation programme; what appeared since the last
	// scan is what a weekly report exists to surface.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "150084") || !strings.Contains(b.Text, "150124") {
		t.Error("a NEW or REOPENED finding is missing from the detail")
	}
	if strings.Contains(b.Text, "150999") {
		t.Errorf("an ACTIVE backlog finding was listed as a change:\n%s", b.Text)
	}
}

func TestFindingDetailCarriesTheUrlAndParameter(t *testing.T) {
	// Without these the reader has to open Qualys to know where to look,
	// which is the "go look in the portal" outcome this lane exists to avoid.
	b := render(t, deepScan())
	if !strings.Contains(b.Text, "https://portal.example/search") {
		t.Error("the vulnerable URL is missing")
	}
	if !strings.Contains(b.Text, "parameter: q") {
		t.Error("the vulnerable parameter is missing")
	}
}

func TestDetailIsCappedButTheCountIsNot(t *testing.T) {
	s := deepScan()
	s.Findings = nil
	for i := 0; i < 30; i++ {
		s.Findings = append(s.Findings, Finding{
			ID: "1", Title: "x", Severity: 3, Status: "NEW", URL: "https://x.example/"})
	}
	b := render(t, s)
	if !strings.Contains(b.Text, "and 18 more") {
		t.Errorf("the cap did not state the true remainder:\n%s", b.Text)
	}
}

func TestWithoutApiDetailTheReportSaysSo(t *testing.T) {
	// A missing detail section must not read as "no findings". The counts
	// come from the email and are still true.
	s := deepScan()
	s.Findings = nil
	b := render(t, s)
	if !strings.Contains(b.Text, "detail not available") {
		t.Errorf("absent detail was indistinguishable from none found:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "2 Critical") {
		t.Error("the counts from the notification were lost with the detail")
	}
}

// ─── the rest ───────────────────────────────────────────────────────────────

func TestAnIncompleteScanReportsNoCounts(t *testing.T) {
	s := deepScan()
	s.Complete = false
	s.Status = "Canceled"
	b := render(t, s)

	if !strings.Contains(b.Text, "did not complete") {
		t.Errorf("an incomplete scan was not flagged:\n%s", b.Text)
	}
	if !strings.Contains(b.Text, "never finished") {
		t.Error("the report does not explain why its counts are withheld")
	}
}

func TestNoScansIsNotRenderedAsAQuietWeek(t *testing.T) {
	// Zero scans may mean a scheduling problem. "Nothing to report" would be
	// the same text a genuinely clean week produces.
	b := Render(nil, weekEnding())
	if !strings.Contains(b.Text, "scheduling problem") {
		t.Errorf("an empty week did not raise the possibility:\n%s", b.Text)
	}
}

func TestNothingFromAScanBecomesAClickableLink(t *testing.T) {
	s := deepScan()
	s.App = `Evil</p><script>alert(1)</script>`
	s.Findings[0].URL = "https://evil.example/pwn"
	b := render(t, s)

	if strings.Contains(b.HTML, "<a href") {
		t.Errorf("an anchor reached the HTML:\n%s", b.HTML)
	}
	for _, bad := range []string{"<script>", "</script>"} {
		if strings.Contains(b.HTML, bad) {
			t.Errorf("unescaped %q reached the HTML", bad)
		}
	}
}

func TestTheReportIsStableAcrossRuns(t *testing.T) {
	// Two runs over the same week must produce the same document, or a diff
	// between weeks stops meaning anything.
	first := render(t, deepScan(), blindScan()).Text
	for i := 0; i < 20; i++ {
		if got := render(t, blindScan(), deepScan()).Text; got != first {
			t.Fatal("report ordering depends on input order")
		}
	}
}

func TestAnUnusableReportLinkIsStatedNotDropped(t *testing.T) {
	s := deepScan()
	s.ReportURL = ""
	s.LinkProblem = "link does not resolve to an allowed host: evil.example"
	b := render(t, s)
	if !strings.Contains(b.Text, "was not usable") {
		t.Errorf("a rejected link vanished silently:\n%s", b.Text)
	}
}
