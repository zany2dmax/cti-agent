package vmscan

import (
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/netmap"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParsesTheNonUMIWeekly(t *testing.T) {
	s, problems := Provider{}.Parse(fixture(t, "results-non-umi.html"))
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if s.Title != "Weekly Scheduled Scan for non-REDACTED-SUB/REDACTED-SUB" || !s.Finished() {
		t.Errorf("title/status = %q %q", s.Title, s.Status)
	}
	want := time.Date(2026, 11, 5, 13, 0, 24, 0, time.UTC)
	if !s.Start.Equal(want) {
		t.Errorf("start = %v, want %v", s.Start, want)
	}
	if s.Duration != 11*time.Hour+45*time.Minute+11*time.Second {
		t.Errorf("duration = %v", s.Duration)
	}
	if s.HostsScanned != 9730 || s.ActiveHosts != 1689 {
		t.Errorf("hosts = %d / %d", s.HostsScanned, s.ActiveHosts)
	}
	if len(s.TargetGroups) != 24 {
		t.Errorf("%d target groups, want 24: %v", len(s.TargetGroups), s.TargetGroups)
	}
	if s.Confirmed[5] != (Counts{Total: 1612, New: 99, Reopened: 0, Active: 1513, Closed: -5}) {
		t.Errorf("sev 5 = %+v", s.Confirmed[5])
	}
	if s.Confirmed.Sum() != 7539 || s.Potential.Sum() != 2464 {
		t.Errorf("sums = %d, %d", s.Confirmed.Sum(), s.Potential.Sum())
	}
	if s.InfoTotal != 49650 {
		t.Errorf("info = %d", s.InfoTotal)
	}
	if s.Ref != "scan/1793883625.34774" || !strings.HasPrefix(s.ReportURL, "https://qualysguard.qg3.apps.qualys.com/") {
		t.Errorf("link = %q (%q)", s.ReportURL, s.Ref)
	}
}

// The real notice has an invisible byte-order mark in front of one group name.
func TestAnInvisibleMarkDoesNotSpoilAGroupName(t *testing.T) {
	s, _ := Provider{}.Parse(fixture(t, "results-non-umi.html"))
	found := false
	for _, g := range s.TargetGroups {
		if strings.ContainsRune(g, '\ufeff') {
			t.Errorf("%q still carries a byte-order mark", g)
		}
		if g == "ARD Miami" {
			found = true
		}
	}
	if !found {
		t.Errorf("ARD Miami missing: %v", s.TargetGroups)
	}
}

func TestParsesTheUMITRJWeeklyAndADayLongDuration(t *testing.T) {
	s, problems := Provider{}.Parse(fixture(t, "results-umi-trj.html"))
	if len(problems) != 0 {
		t.Fatalf("problems: %v", problems)
	}
	if s.Title != "REDACTED-SUB/REDACTED-SUB Weekly" || len(s.TargetGroups) != 21 {
		t.Errorf("title %q, %d groups", s.Title, len(s.TargetGroups))
	}
	if s.Duration != 24*time.Hour+2*time.Minute+33*time.Second {
		t.Errorf("duration = %v (%s)", s.Duration, FormatDuration(s.Duration))
	}
	if FormatDuration(s.Duration) != "1d 00h02m" {
		t.Errorf("formatted = %s", FormatDuration(s.Duration))
	}
	if s.Confirmed[5].Total != 4092 || s.Potential[5].Total != 36 {
		t.Errorf("sev 5: %+v / %+v", s.Confirmed[5], s.Potential[5])
	}
}

// The hidden preheader repeats "Scan Title : ..." on one line; it must not be
// read as the field.
func TestOnlyTheVisibleBodyIsRead(t *testing.T) {
	body := fixture(t, "results-umi-trj.html")
	s, _ := Provider{}.Parse(body)
	if strings.Contains(s.Title, "Start Date") {
		t.Errorf("the preheader leaked into the title: %q", s.Title)
	}
}

func TestRecognisesOnlyQualysResultsNotices(t *testing.T) {
	p := Provider{}
	for _, c := range []struct {
		from, subject string
		want          bool
	}{
		{"qualys@qualys.net", "Qualys: Scan Results", true},
		{"Qualys <qualys@qualys.net>", "Qualys: Scan Results", true},
		{"qualys@qualys.net", "Qualys: Scan Completed", false},
		{"qualys@qualys.net", "FW: Qualys: Scan Results", false},
		{"qualys@qualys.net", "Qualys: Web Application Vulnerability Scan Results", false},
		{"qualys@qualys.net.attacker.example", "Qualys: Scan Results", false},
		{"\"qualys@qualys.net\" <evil@example.com>", "Qualys: Scan Results", false},
		{"user@example.com", "Qualys: Scan Results", false},
	} {
		if got := p.Recognises(c.from, c.subject); got != c.want {
			t.Errorf("Recognises(%q, %q) = %v, want %v", c.from, c.subject, got, c.want)
		}
	}
}

// Seen for real with the WAS lane: a scanner account whose notification
// sender was the team mailbox.
func TestALookalikeFromTheTeamMailboxIsFlaggedNotRead(t *testing.T) {
	p := Provider{}
	if !p.Lookalike("user@example.com", "Qualys: Scan Results") {
		t.Error("a results notice from the team mailbox is not flagged")
	}
	if p.Lookalike("qualys@qualys.net", "Qualys: Scan Results") {
		t.Error("the real notice is flagged")
	}
	if p.Lookalike("someone@example.com", "FW: Qualys: Scan Results") {
		t.Error("a person's forward is flagged; it needs a human, not a warning")
	}
}

func TestATemplateChangeAnnouncesItself(t *testing.T) {
	_, problems := Provider{}.Parse("<pre>nothing useful here</pre>")
	if len(problems) < 3 {
		t.Errorf("an unreadable notice reported only %v", problems)
	}
}

func both(t *testing.T) []Scan {
	t.Helper()
	a, _ := Provider{}.Parse(fixture(t, "results-non-umi.html"))
	b, _ := Provider{}.Parse(fixture(t, "results-umi-trj.html"))
	return []Scan{b, a}
}

func TestCombineKeepsBothWeekliesInTheExpectedOrder(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	if len(w.Scans) != 2 || len(w.Missing) != 0 {
		t.Fatalf("scans %d, missing %v", len(w.Scans), w.Missing)
	}
	if w.Scans[0].Title != DefaultScans[0] || w.Scans[1].Title != DefaultScans[1] {
		t.Errorf("order: %q, %q", w.Scans[0].Title, w.Scans[1].Title)
	}
}

func TestCombineCountsADuplicateNoticeOnceAndTakesTheNewestRun(t *testing.T) {
	s := both(t)
	older := s[1]
	older.Ref, older.Start = "scan/1", older.Start.Add(-7*24*time.Hour)
	dup := s[1] // same Ref as the newest
	w := Combine(append(s, older, dup), DefaultScans)
	if len(w.Scans) != 2 || !w.Scans[0].Start.Equal(s[1].Start) {
		t.Errorf("did not keep the newest run once: %+v", w.Scans)
	}
}

// A scheduled scan that left no notice is the first thing to say.
func TestAMissingScanIsReportedFirst(t *testing.T) {
	w := Combine(both(t)[:1], DefaultScans) // only REDACTED-SUB/REDACTED-SUB
	if len(w.Missing) != 1 || w.Missing[0] != DefaultScans[0] {
		t.Fatalf("missing = %v", w.Missing)
	}
	sub := w.Subject("Acme", time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if !strings.HasPrefix(sub, "[NO RESULT]") {
		t.Errorf("subject = %q", sub)
	}
	if !strings.Contains(w.Text("Acme", time.Now()), "No result came back for") {
		t.Error("the text does not lead with the missing scan")
	}
}

func TestAnUnfinishedScanIsFlagged(t *testing.T) {
	s := both(t)
	s[0].Status = "Canceled"
	w := Combine(s, DefaultScans)
	if sub := w.Subject("Acme", time.Now()); !strings.HasPrefix(sub, "[INCOMPLETE]") {
		t.Errorf("subject = %q", sub)
	}
}

func TestTheCombinedReportSaysTheyRanAndWhatTheyCoveredAndNothingMore(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	b := Render(w, "Acme", time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{"WEEKLY SCHEDULED SCAN FOR NON-REDACTED-SUB/REDACTED-SUB", "REDACTED-SUB/REDACTED-SUB WEEKLY", "ARD Miami", "REDACTED-SUB Charlotte",
		"Locations covered (24)", "Locations covered (21)", "9730", "7168"} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	for _, want := range []string{"Weekly Scheduled Scan for non-REDACTED-SUB/REDACTED-SUB", "REDACTED-SUB/REDACTED-SUB Weekly", "ARD Miami", "REDACTED-SUB Charlotte"} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	// The audience does not act on severities from here and the scans overlap,
	// so the report carries none: not in the subject, text or HTML.
	for _, bad := range []string{"Urgent", "Critical", "Serious", "Severity", "vulnerab", "Potential"} {
		for name, body := range map[string]string{"subject": b.Subject, "text": b.Text, "html": b.HTML} {
			if strings.Contains(body, bad) {
				t.Errorf("%s mentions %q", name, bad)
			}
		}
	}
	if !strings.Contains(b.Subject, "2 scheduled scans ran") {
		t.Errorf("subject = %q", b.Subject)
	}
	if strings.Contains(b.HTML, "<a href") {
		t.Error("a link was rendered as an anchor")
	}
}

func TestLocationsAreCountedOnceAcrossScans(t *testing.T) {
	s := both(t)
	// "REDACTED-SUB Data Center" and "Data Center" are different groups; the same group
	// named in both scans counts once.
	s[0].TargetGroups = append(s[0].TargetGroups, "Data Center")
	w := Combine(s, DefaultScans)
	if got := w.groups(); got != 24+21 {
		t.Errorf("distinct groups = %d, want %d", got, 24+21)
	}
}

func sampleCoverage() *Coverage {
	return &Coverage{Checked: 3, Covered: 1,
		Findings: []netmap.Finding{
			{Kind: netmap.NotInAnyGroup, Location: "Alpha Site", Subnet: "10.1.30.0/24", Row: 12},
			{Kind: netmap.GroupNotScanned, Location: "Beta Site", Subnet: "10.2.30.0/24", Group: "Beta", Row: 20},
			{Kind: netmap.ScannedNotInSheet, Group: "Mystery", Detail: "none of this scanned group's addresses appear in the spreadsheet"},
		},
		Questions: []netmap.Question{
			{Location: "Gamma Site", Kind: netmap.QNoCorpRow, Row: 30, Why: "no row counts as its corp network"},
			{Location: "Delta Site", Kind: netmap.QBlank, Row: 41, Why: "its corp row has no network written in it"},
			{Location: "Zeta Site", Kind: netmap.QInvalid, Row: 50, Why: `its corp network "10.29.30" is not a valid network`},
		},
	}
}

func TestTheCoverageCheckLeadsTheSubjectWhenANetworkIsNotScanned(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	w.Coverage = sampleCoverage()
	b := Render(w, "Acme", time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC))
	if !strings.Contains(b.Subject, "2 network(s) NOT SCANNED") {
		t.Errorf("subject = %q", b.Subject)
	}
	for _, want := range []string{
		"ADD TO QUALYS (2)",
		"Alpha Site (sheet row 12): 10.1.30.0/24 is in no Qualys Asset Group.",
		"Create a Qualys Asset Group for this network and add it to a scheduled scan.",
		"Beta Site (sheet row 20): 10.2.30.0/24 is in the Asset Group \"Beta\", which neither weekly scan covers.",
		"FIX OR CLARIFY IN THE SPREADSHEET (3)",
		"Delta Site (sheet row 41)", "Fill in this location's corp network in the spreadsheet.",
		"Zeta Site (sheet row 50)", "not a valid CIDR",
		"Gamma Site (sheet row 30)", "Add a row labelled corp",
		"CHECK IN QUALYS (1)", "Mystery",
		"HOW THE SPREADSHEET IS READ", "DECOMMISSIONED",
	} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, b.Text)
		}
	}
	for _, want := range []string{"ADD TO QUALYS (2)", "FIX OR CLARIFY IN THE SPREADSHEET (3)", "How the spreadsheet is read", "sheet row 41"} {
		if !strings.Contains(b.HTML, want) {
			t.Errorf("html lacks %q", want)
		}
	}
}

// The email goes to the network and acquisitions teams as well as security, so
// the same findings come as a worksheet they can work through.
func TestTheFindingsComeAsAWorksheet(t *testing.T) {
	c := sampleCoverage()
	rows, err := csv.NewReader(strings.NewReader(c.CSV())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1+2+3+1 {
		t.Fatalf("%d rows:\n%s", len(rows), c.CSV())
	}
	if strings.Join(rows[0], ",") != "category,location,sheet_row,network,asset_group,what_to_do" {
		t.Errorf("header = %v", rows[0])
	}
	if rows[1][0] != "add to Qualys" || rows[1][1] != "Alpha Site" || rows[1][2] != "12" || rows[1][3] != "10.1.30.0/24" {
		t.Errorf("first row = %v", rows[1])
	}
	var fix int
	for _, r := range rows[1:] {
		if r[0] == "fix in the spreadsheet" {
			fix++
			if r[2] == "" {
				t.Errorf("a spreadsheet fix with no row: %v", r)
			}
		}
	}
	if fix != 3 {
		t.Errorf("%d spreadsheet fixes", fix)
	}
	if (&Coverage{Unavailable: "x"}).CSV() != "" || (*Coverage)(nil).CSV() != "" {
		t.Error("an unavailable or absent check produced a worksheet")
	}
}

func TestAWorksheetCellCannotRunAsAFormula(t *testing.T) {
	c := &Coverage{Findings: []netmap.Finding{{Kind: netmap.NotInAnyGroup, Location: "=HYPERLINK(\"x\")", Subnet: "10.1.1.0/24"}}}
	if !strings.Contains(c.CSV(), "'=HYPERLINK") {
		t.Errorf("a formula was written as one:\n%s", c.CSV())
	}
}

func TestACoverageCheckThatCouldNotRunSaysSoAndIsNotACleanResult(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	w.Coverage = &Coverage{Unavailable: "the spreadsheet could not be read"}
	b := Render(w, "Acme", time.Now())
	if !strings.Contains(b.Text, "Not run this week: the spreadsheet could not be read") {
		t.Error("an unavailable check is not stated")
	}
	if strings.Contains(b.Text, "Nothing missing") || strings.Contains(b.Subject, "NOT SCANNED") {
		t.Errorf("an unavailable check reads as a result: %q", b.Subject)
	}
}

func TestACleanCoverageCheckSaysNothingIsMissing(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	w.Coverage = &Coverage{Checked: 40, Covered: 40}
	b := Render(w, "Acme", time.Now())
	if !strings.Contains(b.Text, "40 corporate networks checked, 40 fully inside") || !strings.Contains(b.Text, "Nothing missing") {
		t.Errorf("text:\n%s", b.Text)
	}
	if strings.Contains(b.Subject, "NOT SCANNED") {
		t.Errorf("subject = %q", b.Subject)
	}
}

func TestNoCoverageCheckLeavesTheReportAsItWas(t *testing.T) {
	w := Combine(both(t), DefaultScans)
	b := Render(w, "Acme", time.Now())
	if strings.Contains(b.Text, "COVERAGE CHECK") || strings.Contains(b.HTML, "Coverage check") {
		t.Error("a coverage section appeared with no check asked for")
	}
}
