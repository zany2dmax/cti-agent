package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/appscan"
	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/qualysrl"
)

// fakeFetcher stands in for any scanner: this is the whole interface a new
// provider has to meet.
type fakeFetcher struct {
	asked []string
	fail  map[string]error
	body  []byte // the archive every report returns; nil is a real one with a scan session in it
}

func (f *fakeFetcher) Name() string { return "fake-dast" }

func (f *fakeFetcher) AppReport(_ context.Context, r appscan.ReportRequest) (appscan.Report, error) {
	f.asked = append(f.asked, r.AppID)
	if err := f.fail[r.AppID]; err != nil {
		return appscan.Report{}, err
	}
	body := f.body
	if body == nil {
		// The scanner's report is made while logged in as the scan account,
		// so it carries that session, mid-line and quoted, as Prime found.
		var err error
		body, err = appscan.ZipOne("report.html", []byte("<html><p>app "+r.AppID+
			"</p><td>Set-Cookie: sid=\"SCANSESSION-"+r.AppID+"\"; Path=/</td></html>"), time.Now())
		if err != nil {
			return appscan.Report{}, err
		}
	}
	return appscan.Report{Provider: f.Name(), AppID: r.AppID, App: r.App, Body: body}, nil
}

// unzipped is the text of every file in a zip, for asserting on its content.
func unzipped(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	var out strings.Builder
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		c, _ := io.ReadAll(rc)
		_ = rc.Close()
		out.Write(c)
	}
	return out.String()
}

func targets(ids ...string) []target {
	var out []target
	for _, id := range ids {
		out = append(out, target{key: "id:" + id, id: id, name: "app " + id})
	}
	return out
}

// A report that cannot be redacted (here, one with no HTML in it) is not kept:
// it is a failure, and nothing is written for it.
func TestAReportThatCannotBeRedactedIsNotKept(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	raw, err := appscan.ZipOne("cookies.bin", []byte("sid=SCANSESSION"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, failed := fetchAll(context.Background(), &fakeFetcher{body: raw}, dir, targets("7"), 10, false, time.Minute)
	if failed != 1 || !strings.Contains(m.Failed["id:7"], "could not be redacted") {
		t.Fatalf("failed %d: %+v", failed, m.Failed)
	}
	if _, err := os.Stat(filepath.Join(dir, appscan.ReportFile("id:7"))); !os.IsNotExist(err) {
		t.Fatalf("a report that could not be redacted was written: %v", err)
	}
}

func TestFetchAllWritesReportsAndManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	f := &fakeFetcher{fail: map[string]error{"2": fmt.Errorf("scanner said no")}}
	m, failed := fetchAll(context.Background(), f, dir, targets("1", "2", "3"), 10, false, time.Minute)
	if failed != 1 || len(m.Reports) != 2 || m.Failed["id:2"] == "" {
		t.Fatalf("failed %d manifest %+v", failed, m)
	}
	r, ok, err := appscan.LoadReport(dir, "id:3", "3")
	if err != nil || !ok {
		t.Fatalf("load: %v %v", ok, err)
	}
	if text := unzipped(t, r.Body); !strings.Contains(text, "app 3") || strings.Contains(text, "SCANSESSION") {
		t.Fatalf("the written report is not the redacted one: %q", text)
	}
	// Nothing in the directory holds the session: the raw archive is never written.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if bytes.Contains(b, []byte("SCANSESSION")) || (appscan.IsZip(b) && strings.Contains(unzipped(t, b), "SCANSESSION")) {
			t.Fatalf("%s holds the scan session", e.Name())
		}
	}
	if _, ok, _ := appscan.LoadReport(dir, "id:2", "2"); ok {
		t.Fatal("a failed report loads")
	}
	st, _ := os.Stat(filepath.Join(dir, appscan.ReportFile("id:1")))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", st.Mode())
	}
}

// Once the budget is reserved for the other lanes, nothing more is asked.
func TestFetchAllStopsOnBudget(t *testing.T) {
	f := &fakeFetcher{fail: map[string]error{"2": fmt.Errorf("creating: %w", qualysrl.ErrBudget)}}
	m, failed := fetchAll(context.Background(), f, t.TempDir(), targets("1", "2", "3", "4"), 10, false, time.Minute)
	if len(f.asked) != 2 || failed != 3 || len(m.Reports) != 1 {
		t.Fatalf("asked %v failed %d", f.asked, failed)
	}
}

func TestFetchAllHonoursMax(t *testing.T) {
	f := &fakeFetcher{}
	_, failed := fetchAll(context.Background(), f, t.TempDir(), targets("1", "2", "3"), 2, false, time.Minute)
	if len(f.asked) != 2 || failed != 1 {
		t.Fatalf("asked %v failed %d", f.asked, failed)
	}
}

// Only applications whose ticket will be filed or commented get a report:
// an unchanged ticket would never attach it, and it costs API calls.
func TestTicketTargetsUsesThePreview(t *testing.T) {
	dir := t.TempDir()
	tf := appscan.TicketsFile{Tickets: []appscan.AppTicket{
		{Key: "id:1", AppID: "1", App: "New", Findings: []appscan.TicketFinding{{ID: "1"}}},
		{Key: "id:2", AppID: "2", App: "Changed", Findings: []appscan.TicketFinding{{ID: "1"}}},
		{Key: "id:3", AppID: "3", App: "Unchanged", Findings: []appscan.TicketFinding{{ID: "1"}}},
		{Key: "id:4", AppID: "4", App: "Skipped", Skip: "scan incomplete", Findings: []appscan.TicketFinding{{ID: "1"}}},
		{Key: "id:5", AppID: "5", App: "Clean"},
	}}
	tp := filepath.Join(dir, "t.json")
	_ = os.WriteFile(tp, tf.JSON(), 0o600)
	rp := filepath.Join(dir, "r.json")
	_ = os.WriteFile(rp, []byte(`{"apps":{"id:1":{"action":"would-create"},"id:2":{"action":"would-comment"},`+
		`"id:3":{"action":"unchanged"},"id:4":{"action":"skipped"},"id:5":{"action":"none"}}}`), 0o600)

	got, err := ticketTargets(tp, rp)
	if err != nil || len(got) != 2 || got[0].id != "1" || got[1].id != "2" {
		t.Fatalf("with preview: %+v %v", got, err)
	}
	all, err := ticketTargets(tp, "")
	if err != nil || len(all) != 3 {
		t.Fatalf("without preview: %+v %v", all, err)
	}
}

func TestUnknownProviderNamesTheInterface(t *testing.T) {
	t.Setenv("APPSCAN_REPORT_PROVIDER", "invicti")
	_, err := reportProvider(config.Config{})
	if err == nil || !strings.Contains(err.Error(), "appscan.ReportFetcher") {
		t.Fatalf("err = %v", err)
	}
}

// --list-ids reads the newest weekly file, never a -ref-, -plan- or -preview-
// sibling, and says which applications would get a report.
func TestListIDsUsesTheNewestWeeklyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, tf appscan.TicketsFile) {
		if err := os.WriteFile(filepath.Join(dir, name), tf.JSON(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("appscan-tickets-2026-10-12.json", appscan.TicketsFile{})
	write("appscan-tickets-2026-10-19.json", appscan.TicketsFile{Tickets: []appscan.AppTicket{
		{Key: "id:22", AppID: "22", App: "Shop", Findings: []appscan.TicketFinding{{ID: "1"}, {ID: "2", Potential: true}}},
		{Key: "id:11", AppID: "11", App: "Admin portal", Skip: "scan incomplete"},
		{Key: "name:x", App: "Unmatched"},
	}})
	write("appscan-tickets-ref-2026-10-26.json", appscan.TicketsFile{})
	write("appscan-tickets-plan-2026-10-26.json", appscan.TicketsFile{})

	path, err := newestTicketsFile(dir)
	if err != nil || filepath.Base(path) != "appscan-tickets-2026-10-19.json" {
		t.Fatalf("path %q err %v", path, err)
	}
	b, _ := os.ReadFile(path)
	var tf appscan.TicketsFile
	_ = json.Unmarshal(b, &tf)
	out := listIDs(tf, path)
	for _, want := range []string{"APP ID", "Admin portal", "skipped this week", "no id",
		"1 of 3 application(s) would get a report"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Admin portal") > strings.Index(out, "Shop") {
		t.Errorf("not sorted by name:\n%s", out)
	}
	if !regexp.MustCompile(`(?m)^22\s+1\s+1\s+yes\s+Shop$`).MatchString(out) {
		t.Errorf("Shop row wrong:\n%s", out)
	}
}

func TestListIDsWithNoFileSaysHowToMakeOne(t *testing.T) {
	_, err := newestTicketsFile(t.TempDir())
	// A dry run writes its tickets file under dryrun/appscan/, not here, so
	// the hint names where it is and how to pass it.
	if err == nil || !strings.Contains(err.Error(), "dryrun/appscan/") || !strings.Contains(err.Error(), "--tickets") {
		t.Fatalf("err = %v", err)
	}
}

// --list-ids lists every application the scanner defines, not only the ones
// last week's tickets file named: with WAS_TICKETS off no file is written,
// and the newest one can be a month old and name a quarter of them.
func TestListIDsListsEveryScannerApplication(t *testing.T) {
	home := t.TempDir()
	state := filepath.Join(home, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FLEET_HOME", home)
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	apps := []appscan.App{{ID: "22", Name: "Shop"}, {ID: "11", Name: "Admin portal"}, {ID: "33", Name: "Careers"}}
	write := func(day string, generated time.Time) {
		tf := appscan.TicketsFile{Generated: generated, Tickets: []appscan.AppTicket{
			{Key: "id:22", AppID: "22", App: "Shop", Findings: []appscan.TicketFinding{{ID: "1"}, {ID: "2", Potential: true}}}}}
		if err := os.WriteFile(filepath.Join(state, "appscan-tickets-"+day+".json"), tf.JSON(), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// A month-old file (tickets off since): every app, and no counts.
	write("2026-10-30", now.AddDate(0, 0, -26))
	tf, why := recentTickets(now)
	out := listApps(apps, tf, why)
	for _, want := range []string{"From the scanner: 3 web application(s)", "files tickets", "Admin portal", "Careers", "Shop"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "appscan-tickets-2026-10-30") {
		t.Errorf("a month-old file gave counts:\n%s", out)
	}

	// Last week's file: the same list, with its counts where it has them.
	write("2026-11-20", now.AddDate(0, 0, -5))
	tf, why = recentTickets(now)
	out = listApps(apps, tf, why)
	if !strings.Contains(out, "findings from appscan-tickets-2026-11-20.json") {
		t.Errorf("last week's file not used:\n%s", out)
	}
	shop := ""
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasSuffix(ln, "Shop") {
			shop = ln
		}
	}
	if f := strings.Fields(shop); len(f) < 4 || f[1] != "1" || f[2] != "1" {
		t.Errorf("Shop's counts: %q", shop)
	}
	if strings.Index(out, "Admin portal") > strings.Index(out, "Shop") {
		t.Errorf("not sorted by name:\n%s", out)
	}
}
