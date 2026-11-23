package enrich

// The named expectations from the Python suite's ReportParsing, Prioritize,
// Degradation, KevDeadlines and BandLabelsDoNotOverclaim, ported with the
// lane. The golden tests prove the port matches; these say what matters.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const truthReport = `# CTI / CVE Daily Report

- Mailbox: ` + "`security@example.com`" + `
- Emails inspected: ` + "`312`" + `
- Lookup provider: ` + "`qualys`" + `

| CVE | Status | Provider | External IDs | Host Count | Max Score | Last Seen | Sample Hosts / Reason |
|---|---|---|---|---:|---:|---|---|
| CVE-2021-44228 | PRESENT | qualys | 376160 | 12 | 100 | 2026-09-01T22:00:00Z | h1, h2 |
| CVE-2020-1472 | PRESENT | qualys | 91668,91680 | 4 | 100 | 2026-06-03T19:10:28Z | h3 |
| CVE-2025-33073 | PRESENT | qualys | 92272 | 40 | 95 | 2026-06-03T22:53:25Z | h4 |
| CVE-2026-9110 | PRESENT | qualys | 288802 | 379 | 65 | 2026-06-03T23:12:38Z | h5 |
| CVE-2026-45659 | PRESENT | qualys | 110525 | 186 | 65 | 2026-06-03T23:10:22Z | h6, h6 |
| CVE-2023-35636 | PRESENT | qualys | 92089 | 4 | 37 | 2026-06-03T22:08:29Z | h7 |
| CVE-2008-4250 | NOT_PRESENT | qualys | 1225 | 0 | 0 |  |  |
| CVE-2022-0492 | NOT_PRESENT | qualys | 159639 | 0 | 0 |  |  |
| CVE-2026-49975 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
| CVE-2026-0826 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
| CVE-2026-8206 | UNKNOWN | qualys |  | 0 | 0 |  | No mapping found |
`

// cve -> cvss, epss, on KEV
var truthFixtures = map[string]struct {
	cvss string
	epss float64
	kev  bool
}{
	"CVE-2021-44228": {"10.0", 0.99999, true}, "CVE-2020-1472": {"10.0", 0.994, true},
	"CVE-2025-33073": {"8.8", 0.21, false}, "CVE-2026-9110": {"7.8", 0.04, false},
	"CVE-2026-45659": {"5.5", 0.0009, false}, "CVE-2023-35636": {"6.5", 0.003, false},
	"CVE-2008-4250": {"9.3", 0.944, false}, "CVE-2022-0492": {"8.8", 0.002, true},
	"CVE-2026-49975": {"9.9", 0.78, true}, "CVE-2026-0826": {"9.8", 0.006, false},
	"CVE-2026-8206": {"4.3", 0.0002, false},
}

func truthRun(t *testing.T) *Result {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw.md")
	if err := os.WriteFile(path, []byte(truthReport), 0o600); err != nil {
		t.Fatal(err)
	}
	s := stub{nvd: map[string]NVDEntry{}, epss: map[string]EPSSEntry{}, kev: map[string]KEVEntry{}}
	due := "2021-12-24"
	known := "Known"
	for c, f := range truthFixtures {
		n := json.Number(f.cvss)
		s.nvd[c] = NVDEntry{CVSS: &n, KEVNVD: f.kev, CPEProducts: &[][]string{}}
		s.epss[c] = EPSSEntry{EPSS: f.epss}
		if f.kev {
			s.kev[c] = KEVEntry{Due: &due, Ransomware: &known}
		}
	}
	res, err := Run(Options{Report: path, Today: day("2026-09-15"), Now: day("2026-09-15"),
		Logf: func(string, ...any) {}}, s)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// The calls a human acts on, asserted one by one.
func TestTheTruthTable(t *testing.T) {
	res := truthRun(t)
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.CVE] = f.Priority
	}
	for cve, want := range map[string]string{
		"CVE-2021-44228": "Sev5", // present, KEV, EPSS 100%
		"CVE-2020-1472":  "Sev5", // present, KEV, EPSS 99%
		"CVE-2025-33073": "Sev5", // present, EPSS 21% (over the 10% bar)
		"CVE-2026-9110":  "Sev4", // present on 379 hosts
		"CVE-2026-45659": "Sev4", // present on 186 hosts, CVSS only 5.5
		"CVE-2023-35636": "Sev4", // present on 4 hosts, CVSS 6.5
		"CVE-2026-49975": "Sev3", // UNKNOWN + KEV + EPSS 78%
		"CVE-2008-4250":  "Sev2", // EPSS 94% but NOT_PRESENT
		"CVE-2022-0492":  "Sev2", // KEV but NOT_PRESENT
		"CVE-2026-0826":  "Sev2", // UNKNOWN + CVSS 9.8 = coverage gap
		"CVE-2026-8206":  "Sev1", // UNKNOWN, CVSS 4.3, no exploitation
	} {
		if got[cve] != want {
			t.Errorf("%s is %s, want %s", cve, got[cve], want)
		}
	}
	// Ordered for triage: band, then host count.
	for i := 1; i < len(res.Findings); i++ {
		a, b := res.Findings[i-1], res.Findings[i]
		if sevRank[a.Priority] > sevRank[b.Priority] ||
			(a.Priority == b.Priority && a.HostCount < b.HostCount) {
			t.Errorf("%s before %s", a.CVE, b.CVE)
		}
		if b.Rationale == "" {
			t.Errorf("%s has no rationale", b.CVE)
		}
	}
	total := 0
	for _, p := range SevOrder {
		total += res.Counts[p]
	}
	if total != res.Total || res.Total != 11 {
		t.Errorf("counts %v, total %d", res.Counts, res.Total)
	}
	if res.SourceMeta[0] != [2]string{"mailbox", "security@example.com"} {
		t.Errorf("meta = %v", res.SourceMeta)
	}
}

// A digest that hides its own gaps is worse than no digest. Presence still
// comes from the scanner, so present rows stay actionable.
func TestAllSourcesDownIsReportedNotHidden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.md")
	if err := os.WriteFile(path, []byte(truthReport), 0o600); err != nil {
		t.Fatal(err)
	}
	none := stub{map[string]NVDEntry{}, map[string]EPSSEntry{}, map[string]KEVEntry{}}
	res, err := Run(Options{Report: path, Today: day("2026-09-15"), Logf: func(string, ...any) {}}, none)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Degraded) != 3 || res.Counts["Sev4"] == 0 {
		t.Fatalf("degraded %v, counts %v", res.Degraded, res.Counts)
	}
}

func TestKEVDeadlines(t *testing.T) {
	today := day("2026-09-15")
	days := func(due string) *int { return KEVDaysLeft(&due, today) }
	for due, want := range map[string]int{"2026-09-01": -14, "2026-09-15": 0, "2026-09-20": 5} {
		if got := days(due); got == nil || *got != want {
			t.Errorf("%s: %v, want %d", due, ptr(got), want)
		}
	}
	// "No deadline" and "due today" are opposite facts.
	for _, due := range []string{"", "   ", "not-a-date", "2026-13-45", "0000-01-01"} {
		if got := days(due); got != nil {
			t.Errorf("%q has deadline %d", due, *got)
		}
	}
	if KEVDaysLeft(nil, today) != nil {
		t.Error("nil has a deadline")
	}
	due := func(d string) *string { return &d }
	_, why, _ := prioritize(scoreInput{Status: "PRESENT", HostCount: 3, KEV: true, KEVDue: due("2026-09-01")}, today)
	if !strings.Contains(why, "PASSED 14d ago") {
		t.Errorf("overdue and present: %q", why)
	}
	_, why, _ = prioritize(scoreInput{Status: "NOT_PRESENT", KEV: true, KEVDue: due("2026-09-01")}, today)
	if strings.Contains(why, "PASSED") || !strings.Contains(why, "not detected here") {
		t.Errorf("overdue elsewhere: %q", why)
	}
	_, why, _ = prioritize(scoreInput{Status: "PRESENT", HostCount: 1, KEV: true, KEVDue: due("2026-09-15")}, today)
	if !strings.Contains(why, "TODAY") || strings.Contains(why, "PASSED") {
		t.Errorf("due today: %q", why)
	}
	// A deadline is an obligation about a risk, not a change to it.
	for _, d := range []*string{nil, due("2026-09-01"), due("2026-09-15"), due("2027-01-01")} {
		if p, _, _ := prioritize(scoreInput{Status: "PRESENT", HostCount: 1, KEV: true, KEVDue: d}, today); p != "Sev5" {
			t.Errorf("due %v moved the band to %s", d, p)
		}
	}
}

func TestTheDeadlineSummaryCountsOnlyWhatIsPresent(t *testing.T) {
	n := func(v int) *int { return &v }
	known := "Known"
	k := &KEVEntry{Ransomware: &known}
	rows := []*Finding{
		{CVE: "A", Status: "PRESENT", HostCount: 2, KEVDaysLeft: n(-5), KEV: k},
		{CVE: "B", Status: "PRESENT", HostCount: 1, KEVDaysLeft: n(3)},
		{CVE: "C", Status: "PRESENT", HostCount: 1, KEVDaysLeft: n(90)},
		{CVE: "D", Status: "NOT_PRESENT", KEVDaysLeft: n(-100), KEV: k},
		{CVE: "E", Status: "UNKNOWN", KEVDaysLeft: n(-7)},
		{CVE: "F", Status: "PRESENT", HostCount: 5},
	}
	s := kevSummary(rows)
	if s.Overdue != 1 || len(s.OverdueCVEs) != 1 || s.OverdueCVEs[0] != "A" || s.DueWithin14d != 1 ||
		s.WorstOverdueDays != 5 || s.RansomwarePresent != 1 {
		t.Fatalf("summary = %+v", s)
	}
	if e := kevSummary(nil); e.Overdue != 0 || e.OverdueCVEs == nil {
		t.Fatalf("empty summary = %+v", e)
	}
}

// The heading of the confirmed-present band cannot lie if the scoring can
// never put an unverified finding there.
func TestAnUnknownRowNeverReachesTheConfirmedBands(t *testing.T) {
	for _, c := range []struct {
		kev  bool
		epss float64
		cvss string
	}{{true, 0.9, "9.9"}, {false, 0.6, "9.9"}, {false, 0, "9.5"}, {false, 0, "2.0"}, {true, 0, "0.0"}} {
		p, _, _ := prioritize(scoreInput{Status: "UNKNOWN", KEV: c.kev, EPSS: c.epss, CVSS: json.Number(c.cvss)}, time.Now())
		if p == "Sev4" || p == "Sev5" {
			t.Errorf("UNKNOWN reached %s with %+v", p, c)
		}
	}
	unverified, _, _ := prioritize(scoreInput{Status: "UNKNOWN", KEV: true, EPSS: 0.9}, time.Now())
	quiet, _, _ := prioritize(scoreInput{Status: "PRESENT", HostCount: 300, EPSS: 0.001, CVSS: "7.0"}, time.Now())
	noise, _, _ := prioritize(scoreInput{Status: "UNKNOWN", EPSS: 0.0001, CVSS: "4.0"}, time.Now())
	if unverified != "Sev3" || sevRank[unverified] <= sevRank[quiet] || sevRank[unverified] >= sevRank[noise] {
		t.Errorf("unverified %s, present %s, noise %s: an exploited unknown sits mid-scale", unverified, quiet, noise)
	}
}

// The agent writes a pipe in a subject as \| (internal/report escape). The
// digest lists the subject as it was, pipes and all, at the start, middle or
// end, and the cells after it stay in their columns.
func TestASubjectKeepsItsPipes(t *testing.T) {
	report := "# r\n\n## Emails read this run\n\n| CVE? | Received | Subject |\n|---|---|---|\n" +
		"| yes | 2026-11-21 08:00 | Advisory: Log4j \\| again |\n" +
		"| no | 2026-11-21 09:00 | \\|lead and trail\\| |\n" +
		"| yes | 2026-11-21 10:00 | a \\| b \\| c |\n"
	path := filepath.Join(t.TempDir(), "raw.md")
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	got := ParseSubjects(path)
	want := []Subject{
		{true, "2026-11-21 08:00", "Advisory: Log4j | again"},
		{false, "2026-11-21 09:00", "|lead and trail|"},
		{true, "2026-11-21 10:00", "a | b | c"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
