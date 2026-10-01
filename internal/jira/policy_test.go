package jira

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// kev85880 is the real overdue finding this lane was built for.
func kev85880() Finding {
	hosts := make([]string, 441)
	for i := range hosts {
		hosts[i] = "host-" + string(rune('a'+i%26)) + itoa(i)
	}
	return Finding{
		CVE:      "CVE-2026-85880",
		QIDs:     []string{"92145", "92101"},
		Hosts:    hosts,
		KEV:      true,
		KEVDueOn: time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC),
		Severity: 5,
		QQL:      `vulnerabilities.vulnerability.qid:[92101,92145]`,
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestTheIdempotencyLabelIsCaseInsensitive(t *testing.T) {
	// CVE ids are not consistently cased in feeds, and Jira labels ARE
	// case-sensitive. Without normalising, CVE-2026-85880 and
	// cve-2026-85880 become two tickets for one vulnerability - which is
	// exactly the ticket storm this is here to prevent.
	a := IdempotencyLabel("CVE-2026-85880")
	b := IdempotencyLabel("cve-2026-85880")
	c := IdempotencyLabel("  CVE-2026-85880  ")
	if a != b || b != c {
		t.Errorf("labels differ: %q, %q, %q", a, b, c)
	}
	if a != "cti-cve-2026-85880" {
		t.Errorf("label = %q, want cti-cve-2026-85880", a)
	}
}

func TestTheSummaryLeadsWithOverdueWhenTheDeadlineHasPassed(t *testing.T) {
	s := Summary(kev85880(), now)
	if !strings.HasPrefix(s, "[OVERDUE] ") {
		t.Errorf("summary does not lead with OVERDUE: %q", s)
	}
	if !strings.Contains(s, "CVE-2026-85880") {
		t.Errorf("summary omits the CVE: %q", s)
	}
	if !strings.Contains(s, "441 hosts") {
		t.Errorf("summary omits the host count: %q", s)
	}
}

func TestTheSummaryDoesNotCryWolfBeforeTheDeadline(t *testing.T) {
	f := kev85880()
	f.KEVDueOn = now.Add(14 * 24 * time.Hour)
	if s := Summary(f, now); strings.Contains(s, "OVERDUE") {
		t.Errorf("a future deadline was reported as overdue: %q", s)
	}
}

func TestTheHostCountIsPluralisedCorrectly(t *testing.T) {
	// CVE-2026-53266 is a single host. "1 hosts" in a ticket title IT reads
	// every morning is the kind of sloppiness that makes automation look
	// untrustworthy.
	//
	// The first version of this test asserted on the punctuation AROUND the
	// count - "1 host -" or "1 host," - and failed against correct output,
	// because with no title and no KEV marker the summary ends at the count.
	// It was checking the shape of one example rather than the rule. Asserting
	// the rule means the negative case has to be explicit, since "1 host" is a
	// substring of "1 hosts".
	for _, tc := range []struct {
		hosts int
		want  string
	}{
		{0, "0 hosts"},
		{1, "1 host"},
		{2, "2 hosts"},
		{441, "441 hosts"},
	} {
		f := Finding{CVE: "CVE-2026-53266", Hosts: make([]string, tc.hosts), Severity: 5}
		s := Summary(f, now)
		if !strings.Contains(s, tc.want) {
			t.Errorf("%d hosts: summary %q does not contain %q", tc.hosts, s, tc.want)
		}
		if tc.hosts == 1 && strings.Contains(s, "1 hosts") {
			t.Errorf("a single host was pluralised: %q", s)
		}
	}
}

func TestTheSummaryNeverExceedsJirasLimit(t *testing.T) {
	// Over the limit is a 400 on create, so the ticket is lost rather than
	// ugly. Truncation is the correct trade.
	f := kev85880()
	f.Title = strings.Repeat("a very long vulnerability title ", 40)
	s := Summary(f, now)
	if len(s) > MaxSummary {
		t.Errorf("summary is %d bytes, limit %d", len(s), MaxSummary)
	}
	if !strings.HasSuffix(s, "...") {
		t.Errorf("a truncated summary should say so: %q", s[len(s)-20:])
	}
}

func TestTheSummaryCarriesNoNewlines(t *testing.T) {
	// A newline in a summary reaches Jira's email notifications as a header.
	f := kev85880()
	f.Title = "line one\nline two\r\nBcc: someone@example.com"
	s := Summary(f, now)
	if strings.ContainsAny(s, "\r\n") {
		t.Errorf("summary contains a line break: %q", s)
	}
}

func TestTheDescriptionStatesTheOverdueDaysAndPointsAtTheCSV(t *testing.T) {
	d := Description(kev85880(), now, "cve-2026-85880-hosts-2026-10-01.csv")
	for _, want := range []string{
		"CVE-2026-85880",
		"92101, 92145", // sorted, not insertion order
		"OVERDUE by 9 days",
		"[^cve-2026-85880-hosts-2026-10-01.csv]",
		"vulnerabilities.vulnerability.qid",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("description omits %q", want)
		}
	}
}

func TestTheDescriptionDoesNotInlineTheHostList(t *testing.T) {
	// 441 hostnames in a description is unreadable, and the whole reason the
	// host list is an attachment.
	f := kev85880()
	d := Description(f, now, CSVName(f.CVE, now))
	for _, h := range f.Hosts {
		if strings.Contains(d, h) {
			t.Fatalf("description inlines host %q - it belongs in the CSV", h)
		}
	}
}

func TestHostCSVSurvivesAHostnameWithAComma(t *testing.T) {
	// Scanner output is not input this codebase controls. strings.Join would
	// shift every following column and the CSV would parse, wrongly.
	f := Finding{
		CVE:   "CVE-2026-1",
		QIDs:  []string{"1"},
		Hosts: []string{`weird"name,with-comma`, "normal.example.com"},
	}
	raw, err := HostCSV(f)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if err != nil {
		t.Fatalf("the CSV we produced does not parse: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want header + 2", len(rows))
	}
	for _, r := range rows {
		if len(r) != 3 {
			t.Errorf("row %v has %d columns, want 3", r, len(r))
		}
	}
}

func TestSizeAloneDoesNotMakeItAFloor(t *testing.T) {
	// This replaces a test that asserted 1000+ hosts WAS a floor, back when
	// HostFloor() guessed from a magic number. The provider knows whether it
	// truncated, so it is asked - and a complete 1000-host list is a
	// measurement, not a lower bound. Reporting "at least 1000" for a count
	// the scanner is sure about understates nothing but erodes trust in the
	// cases where "at least" is doing real work.
	f := kev85880()
	f.Hosts = make([]string, 1000)
	f.HostCount = 1000
	if f.HostFloor() {
		t.Error("a complete 1000-host list was reported as a floor")
	}
	if s := Summary(f, now); strings.Contains(s, "at least") {
		t.Errorf("summary hedged a known count: %q", s)
	}

	// ...and the same list IS a floor once the scanner says it truncated.
	f.CountIsFloor = true
	if !f.HostFloor() {
		t.Error("a truncated scan was not reported as a floor")
	}
	if d := Description(f, now, ""); !strings.Contains(d, "floor") {
		t.Error("description does not state the floor")
	}
}

func TestTheWriteGateFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, project, allow string
		wantErr              bool
	}{
		{"unset allowlist refuses", "CR", "", true},
		{"allowlisted project passes", "CR", "CR", false},
		{"case does not matter", "cr", "CR,CO", false},
		{"whitespace does not matter", "CR", " CO , CR ", false},
		{"a different project refuses", "CO", "CR", true},
		{"no project key refuses", "", "CR", true},
		{"a substring is not a match", "C", "CR", true},
	} {
		err := CheckAllowed(tc.project, tc.allow)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: CheckAllowed(%q, %q) error = %v, wantErr %v",
				tc.name, tc.project, tc.allow, err, tc.wantErr)
		}
	}
}

func TestOnlyKEVOrSev5EarnsATicket(t *testing.T) {
	for _, tc := range []struct {
		f    Finding
		want bool
	}{
		{Finding{Severity: 5}, true},
		{Finding{Severity: 1, KEV: true}, true}, // KEV outranks the band
		{Finding{Severity: 4}, false},
		{Finding{Severity: 1}, false},
	} {
		if got := ShouldFile(tc.f); got != tc.want {
			t.Errorf("ShouldFile(sev%d kev=%v) = %v, want %v",
				tc.f.Severity, tc.f.KEV, got, tc.want)
		}
	}
}

func TestKEVFilesItselfAndEverythingElseWaits(t *testing.T) {
	// The autonomy rule: a KEV entry has an external deadline, so delay is
	// the bigger risk. A Sev5 that is not on KEV is the fleet's own judgement
	// and gets a human before it reaches IT.
	if NeedsApproval(Finding{KEV: true, Severity: 5}) {
		t.Error("a KEV finding should file without approval")
	}
	if !NeedsApproval(Finding{KEV: false, Severity: 5}) {
		t.Error("a non-KEV Sev5 should wait for approval")
	}
}

func TestFindJQLIsNotScopedByStatus(t *testing.T) {
	// A resolved ticket still counts as already filed. Scoping the duplicate
	// search to open issues means closing a ticket makes the fleet file a new
	// one the next morning.
	q := FindJQL("CR", "CVE-2026-85880")
	if strings.Contains(strings.ToLower(q), "statuscategory") ||
		strings.Contains(strings.ToLower(q), "resolution") {
		t.Errorf("duplicate search is status-scoped: %q", q)
	}
	if !strings.Contains(q, `labels = "cti-cve-2026-85880"`) {
		t.Errorf("JQL does not match on the idempotency label: %q", q)
	}
}

func TestLabelsCarryTheFiltersAHumanWants(t *testing.T) {
	got := Labels(kev85880())
	want := map[string]bool{
		"cti-cve-2026-85880": false, "cti-agent": false,
		"cisa-kev": false, "sev5": false,
	}
	for _, l := range got {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for l, seen := range want {
		if !seen {
			t.Errorf("label %q missing from %v", l, got)
		}
	}
}

func TestATruncatedScanReportsTheCountNotTheNamesItGot(t *testing.T) {
	// Qualys truncates its per-QID host lists on a large estate, so the union
	// of NAMES can be shorter than the number of MACHINES. Deriving the count
	// from the names understates exposure - and understating exposure in a
	// remediation ticket is the one direction that gets somebody hurt.
	f := Finding{
		CVE:          "CVE-2026-85880",
		Hosts:        make([]string, 120), // all the scanner would name
		HostCount:    361,                 // what it actually counted
		CountIsFloor: true,
		Severity:     5,
		KEV:          true,
	}
	if f.Count() != 361 {
		t.Errorf("Count() = %d, want 361", f.Count())
	}
	if !f.HostFloor() {
		t.Error("a truncated scan was not reported as a floor")
	}
	s := Summary(f, now)
	if !strings.Contains(s, "361") {
		t.Errorf("summary reports the names it got, not the machines: %q", s)
	}
	if !strings.Contains(s, "at least") {
		t.Errorf("summary states a floor as a measurement: %q", s)
	}
	d := Description(f, now, "x.csv")
	if !strings.Contains(d, "361") || !strings.Contains(d, "floor") {
		t.Errorf("description does not state the floor: %q", d)
	}
}

func TestAShortNameListAloneMakesItAFloor(t *testing.T) {
	// Even without CountIsFloor set, fewer names than machines means the CSV
	// is incomplete and the ticket must say so.
	f := Finding{CVE: "CVE-1", Hosts: make([]string, 5), HostCount: 50, Severity: 5}
	if !f.HostFloor() {
		t.Error("5 names for 50 machines was not treated as a floor")
	}
}

func TestCountFallsBackToTheListWhenUnset(t *testing.T) {
	// Callers that only have a list - including every existing test - keep
	// working rather than silently reporting zero.
	f := Finding{CVE: "CVE-1", Hosts: []string{"a", "b", "c"}, Severity: 5}
	if f.Count() != 3 {
		t.Errorf("Count() = %d, want 3", f.Count())
	}
	if f.HostFloor() {
		t.Error("a complete list was reported as a floor")
	}
}

func TestATableCellSurvivesAHostileDescription(t *testing.T) {
	// Titles come from NVD. In Jira wiki markup "|" ends the cell and a
	// newline ends the row, so a description containing either mangles the
	// table in the ticket IT actually reads - and plenty of CVE descriptions
	// contain both.
	f := kev85880()
	f.Title = "Heap overflow in foo|bar\nsecond line\r\nthird"
	f.CVSS = "9.8|injected"

	d := Description(f, now, "x.csv")
	for _, line := range strings.Split(d, "\n") {
		if !strings.HasPrefix(line, "|") {
			continue
		}
		// Count only UNescaped pipes: a well-formed two-column row has
		// exactly three.
		bare := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|")
		if bare != 3 {
			t.Errorf("row has %d unescaped pipes, want 3: %q", bare, line)
		}
	}
	if !strings.Contains(d, `foo\|bar`) {
		t.Error("the pipe was stripped rather than escaped - the text should survive")
	}
	if strings.Contains(d, "Heap overflow in foo\\|bar\nsecond") {
		t.Error("a newline survived into a table row")
	}
}
