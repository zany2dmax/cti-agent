package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
)

func potentialSQLi() appscan.TicketFinding {
	return appscan.TicketFinding{ID: "150020", Title: "SQL injection", Severity: 5, Status: "NEW",
		Potential: true, Instances: []appscan.Instance{{URL: "https://app.example.com/search", Param: "id"}}}
}

// The developer must not be able to read a potential finding as either
// confirmed or absent: its own section, the callout, and the word on the line.
func TestPotentialFindingsAreListedAndCalledOut(t *testing.T) {
	tk := appTicket(xss("https://app.example.com/a"), potentialSQLi())
	body := appscanBody(tk, time.Now())
	for _, want := range []string{
		"h2. POTENTIAL - please verify",
		"listed here on purpose",
		`"Not confirmed" does *not* mean "not there"`,
		"POTENTIAL Urgent - unconfirmed, please verify",
		"*To verify:* 1 Urgent *POTENTIAL*",
		"*To fix:* 1 Urgent",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q", want)
		}
	}
	if strings.Index(body, "Reflected XSS") > strings.Index(body, "h2. POTENTIAL") {
		t.Error("confirmed findings must come before the potential section")
	}
	if s := appscanSummary(tk); s != "AppSec: Portal - 1 finding(s) to fix, 1 potential to verify (worst Urgent)" {
		t.Errorf("summary = %q", s)
	}
	if !strings.Contains(appscanFullText(tk, time.Now()), "[POTENTIAL Urgent - unconfirmed, please verify] SQL injection") {
		t.Error("attachment text does not mark the potential finding")
	}
}

func TestOnlyPotentialSummarySaysUnconfirmed(t *testing.T) {
	tk := appTicket(potentialSQLi())
	if s := appscanSummary(tk); s != "AppSec: Portal - 1 POTENTIAL finding(s) to verify (worst Urgent, unconfirmed)" {
		t.Errorf("summary = %q", s)
	}
	if !strings.Contains(appscanBody(tk, time.Now()), "*To fix:* nothing of Serious or above") {
		t.Error("header claims confirmed findings that are not there")
	}
}

// A long confirmed list cannot push the potential callout out of the text.
func TestPotentialCalloutSurvivesALongConfirmedList(t *testing.T) {
	var fs []appscan.TicketFinding
	for i := 0; i < 200; i++ {
		f := xss("https://app.example.com/" + strings.Repeat("x", 200) + itoa(i))
		f.ID = "15" + itoa(1000+i)
		fs = append(fs, f)
	}
	body := appscanBody(appTicket(append(fs, potentialSQLi())...), time.Now())
	if !strings.Contains(body, "listed here on purpose") {
		t.Fatal("the potential callout was squeezed out")
	}
	if len(body) > hardMax+200 {
		t.Fatalf("body %d bytes", len(body))
	}
}

func writeReports(t *testing.T, key string) string {
	t.Helper()
	dir := t.TempDir()
	r, err := appscan.WriteReport(dir, key, appscan.Report{Provider: "qualys-was", AppID: "101",
		App: "Portal", Body: []byte("PK\x03\x04zip"), Generated: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	m := appscan.ReportsManifest{Provider: "qualys-was", Reports: map[string]appscan.Report{key: r}}
	if err := appscan.WriteManifest(dir, m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScannerReportIsAttachedOnCreateAndNamedInTheText(t *testing.T) {
	fj, c := newAppJira(t)
	dir := writeReports(t, "id:101")
	tmp := t.TempDir()
	in := filepath.Join(tmp, "tickets.json")
	if err := os.WriteFile(in, appscan.TicketsFile{Tickets: []appscan.AppTicket{
		appTicket(xss("https://app.example.com/a"))}}.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := doAppscanTickets(context.Background(), c, testCfg, in, true, time.Now(), "", dir); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	if len(fj.creates) != 1 {
		t.Fatalf("creates %d", len(fj.creates))
	}
	key := "SEC-101"
	got := strings.Join(fj.attached[key], ",")
	if !strings.Contains(got, "appscan-") || !strings.Contains(got, "qualys-was-report-") {
		t.Fatalf("attachments on %s: %q", key, got)
	}
	if d, _ := fj.creates[0]["description"].(string); !strings.Contains(d, "session cookies") {
		t.Error("the description does not say the report carries session cookies")
	}
}

// A report the manifest does not list - stale, or another application's - is
// never attached.
func TestUnlistedReportIsNotAttached(t *testing.T) {
	fj, c := newAppJira(t)
	dir := writeReports(t, "id:999")
	if err := os.WriteFile(filepath.Join(dir, appscan.ReportFile("id:101")), []byte("PK\x03\x04x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	in := filepath.Join(tmp, "tickets.json")
	_ = os.WriteFile(in, appscan.TicketsFile{Tickets: []appscan.AppTicket{
		appTicket(xss("https://app.example.com/a"))}}.JSON(), 0o600)
	if rc := doAppscanTickets(context.Background(), c, testCfg, in, true, time.Now(), "", dir); rc != exitOK {
		t.Fatalf("rc %d", rc)
	}
	for _, n := range fj.attached["SEC-101"] {
		if strings.HasSuffix(n, ".zip") {
			t.Fatalf("attached %q", n)
		}
	}
	if d, _ := fj.creates[0]["description"].(string); strings.Contains(d, "*Attached:*") {
		t.Error("the text names an attachment that is not there")
	}
}
