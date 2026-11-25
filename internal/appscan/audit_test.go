package appscan

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var auditApps = []App{
	{ID: "1", Name: "Shop", URL: "https://shop.example.com"},
	{ID: "2", Name: "Portal", URL: "https://portal.example.com"},
	{ID: "3", Name: "Careers", URL: "https://careers.example.com"},
	{ID: "4", Name: "Staging", URL: "https://staging.example.com"},
	{ID: "5", Name: "Academy", URL: "https://academy.example.com"},
}

func auditWeek(t *testing.T) []ScanResult {
	t.Helper()
	fin := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	return []ScanResult{
		{AppID: "1", App: "Shop", Reference: "was/1.1", Complete: true, Status: "Finished",
			Finished: fin, Auth: Auth{Status: "Successful"}},
		{AppID: "2", App: "Portal", Reference: "was/2.1", Complete: true, Status: "Finished",
			Finished: fin, Auth: Auth{Status: "Successful"}},
		{AppID: "5", App: "Academy", Reference: "was/5.1", Complete: false, Status: "FINISHED", Finished: fin},
	}
}

// An application set up in the scanner with no scan this week is listed, in
// both the text and the HTML; with no application list the section is left
// out, never shown empty.
func TestTheWeeklyReportListsTheApplicationsNotScanned(t *testing.T) {
	week := auditWeek(t)
	b := RenderReport(week, auditApps, time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC), false)
	for _, body := range []string{b.Text, b.HTML} {
		// The HTML upper-cases its section headings.
		if !strings.Contains(strings.ToUpper(body), "NOT SCANNED THIS WEEK (2 OF 5)") {
			t.Fatalf("no NOT SCANNED section:\n%s", body)
		}
		for _, want := range []string{"Careers", "Staging", "careers.example.com"} {
			if !strings.Contains(body, want) {
				t.Errorf("%q missing", want)
			}
		}
	}
	section := b.Text[strings.Index(b.Text, "NOT SCANNED THIS WEEK"):]
	section = section[:strings.Index(section, "CHANGED THIS WEEK")]
	for _, scanned := range []string{"Shop", "Portal", "Academy"} {
		if strings.Contains(section, scanned) {
			t.Errorf("%s was scanned but is listed as not scanned", scanned)
		}
	}
	if none := RenderReport(week, nil, time.Now(), false); strings.Contains(none.Text, "NOT SCANNED THIS WEEK") {
		t.Error("the section was shown with no application list")
	}
	if old := Render(week, time.Now()); strings.Contains(old.Text, "NOT SCANNED THIS WEEK") {
		t.Error("Render, which has no application list, showed the section")
	}
}

// Qualys said FINISHED but the run is not in the scan list: say that, not
// "did not complete (FINISHED)".
func TestAnUnconfirmedFinishIsSaidPlainly(t *testing.T) {
	head, detail := faultLine(ScanResult{App: "Academy", Status: "FINISHED"})
	if strings.Contains(head, "did not complete") || !strings.Contains(head, "not confirmed") {
		t.Errorf("head %q", head)
	}
	if !strings.Contains(detail, "scan list") {
		t.Errorf("detail %q", detail)
	}
	if head, _ := faultLine(ScanResult{App: "Shop", Status: "Time Limit Reached"}); !strings.Contains(head, "did not complete (Time Limit Reached)") {
		t.Errorf("a real incomplete scan: %q", head)
	}
}

// The audit gives every application one verdict, problems first.
func TestTheAuditGivesEveryApplicationAVerdict(t *testing.T) {
	owners, _, err := ParseOwners(strings.NewReader("id:1 | a@example.com\nid:2 | b@example.com\nid:4 | d@example.com\nid:5 | e@example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	week := auditWeek(t)
	sent := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	delivered := DeliveredLog{
		AppKey(week[0]): {Ref: ScanRef(week[0]), At: sent, Status: "sent"},
		"4":             {Ref: "was/4.0", At: sent.AddDate(0, -1, 0), Status: "sent"},
	}
	rows := Audit(auditApps, week, owners, delivered)
	got := map[string]AuditRow{}
	for _, r := range rows {
		got[r.App.Name] = r
	}
	for name, want := range map[string]string{
		"Shop":    "report sent 2026-11-21",
		"Portal":  "scanned, report not sent yet",
		"Careers": "not scanned in this window",
		"Staging": "last report sent 2026-10-21",
		"Academy": "not in its scan list",
	} {
		if r := got[name]; !strings.Contains(r.Verdict, want) {
			t.Errorf("%s: verdict %q, want %q", name, r.Verdict, want)
		}
	}
	if got["Shop"].Problem || !got["Careers"].Problem || !got["Academy"].Problem {
		t.Error("problem flags wrong")
	}
	if !rows[0].Problem || rows[len(rows)-1].Problem {
		t.Error("problems are not listed first")
	}
	if got["Careers"].Owner != "" {
		t.Errorf("Careers has no owner on file, got %q", got["Careers"].Owner)
	}
	text := RenderAudit(rows, 7*24*time.Hour)
	for _, want := range []string{"5 web application(s) in the scanner; scans in the last 7 days; 4 need a look",
		"APP ID", "! not scanned", "a@example.com"} {
		if !strings.Contains(text, want) {
			t.Errorf("audit text lacks %q:\n%s", want, text)
		}
	}
}

// The JSON the check-in reads: every app, with a kind it can key on, and the
// count of those that need a look.
func TestTheAuditJSONGivesTheCheckInAKindPerApp(t *testing.T) {
	owners, _, _ := ParseOwners(strings.NewReader("id:1 | a@example.com\nid:2 | b@example.com\n"))
	rows := Audit(auditApps, auditWeek(t), owners, DeliveredLog{})
	var f AuditFile
	if err := json.Unmarshal(AuditJSON(rows, 8*24*time.Hour, time.Date(2026, 11, 25, 8, 30, 0, 0, time.UTC)), &f); err != nil {
		t.Fatal(err)
	}
	if f.WindowDays != 8 || len(f.Apps) != len(auditApps) || f.Problems != len(auditApps) {
		t.Fatalf("file %+v", f)
	}
	kinds := map[string]string{}
	for _, a := range f.Apps {
		kinds[a.Name] = a.Kind
	}
	for name, want := range map[string]string{"Careers": "not_scanned", "Shop": "pending", "Academy": "no_owner"} {
		if kinds[name] != want {
			t.Errorf("%s: kind %q, want %q", name, kinds[name], want)
		}
	}
}
