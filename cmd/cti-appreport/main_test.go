package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
}

func (f *fakeFetcher) Name() string { return "fake-dast" }

func (f *fakeFetcher) AppReport(_ context.Context, r appscan.ReportRequest) (appscan.Report, error) {
	f.asked = append(f.asked, r.AppID)
	if err := f.fail[r.AppID]; err != nil {
		return appscan.Report{}, err
	}
	return appscan.Report{Provider: f.Name(), AppID: r.AppID, App: r.App, Body: []byte("PK\x03\x04" + r.AppID)}, nil
}

func targets(ids ...string) []target {
	var out []target
	for _, id := range ids {
		out = append(out, target{key: "id:" + id, id: id, name: "app " + id})
	}
	return out
}

func TestFetchAllWritesReportsAndManifest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	f := &fakeFetcher{fail: map[string]error{"2": fmt.Errorf("scanner said no")}}
	m, failed := fetchAll(context.Background(), f, dir, targets("1", "2", "3"), 10, false, time.Minute)
	if failed != 1 || len(m.Reports) != 2 || m.Failed["id:2"] == "" {
		t.Fatalf("failed %d manifest %+v", failed, m)
	}
	r, ok, err := appscan.LoadReport(dir, "id:3", "3")
	if err != nil || !ok || string(r.Body) != "PK\x03\x043" {
		t.Fatalf("load: %v %v %q", ok, err, r.Body)
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
