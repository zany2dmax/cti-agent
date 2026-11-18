package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/graph"
	"github.com/zany2dmax/cti-agent/internal/netmap"
	"github.com/zany2dmax/cti-agent/internal/vmscan"
	"github.com/zany2dmax/cti-agent/internal/xlsx/xlsxtest"
)

// checkOut runs doCheck and returns its exit code and what it printed.
func checkOut(t *testing.T, cfg config.Config) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	code := doCheck(cfg, "")
	os.Stderr = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return code, string(out)
}

// --check is run by the heartbeat: it must exercise every input the coverage
// check needs, print counts and never a network or group name, and fail when
// the weekly would say its coverage check did not run.
func TestCheck(t *testing.T) {
	oldTok, oldDrive, oldGroups, oldScans, oldSched := graphToken, driveContent, fetchGroups, fetchScans, fetchSchedules
	t.Cleanup(func() {
		graphToken, driveContent, fetchGroups, fetchScans, fetchSchedules = oldTok, oldDrive, oldGroups, oldScans, oldSched
	})
	fetchSchedules = func(context.Context, string, string, string) ([]vmscan.Schedule, error) {
		return []vmscan.Schedule{{Title: "Secret Weekly", Active: true, Interval: 7 * 24 * time.Hour},
			{Title: "Off", Active: false}}, nil
	}
	fetchScans = func(context.Context, string, string, string, time.Time) ([]vmscan.Scan, error) {
		return []vmscan.Scan{{Title: "Secret Scan", LaunchType: "Scheduled"}, {Title: "By hand", LaunchType: "On-Demand"}}, nil
	}

	sheet := xlsxtest.Build(t, map[string][][]string{"Sites": {
		{"Site", "Subnet"}, {"Secret Plant", "10.1.30.0/24"}}}, []string{"Sites"})
	graphToken = func(context.Context, *graph.Client) error { return nil }
	driveContent = func(_ context.Context, _ *graph.Client, d, i string) ([]byte, error) {
		if d != "drive" || i != "item" {
			t.Errorf("drive %q item %q", d, i)
		}
		return sheet, nil
	}
	fetchGroups = func(context.Context, string, string, string) ([]netmap.Group, error) {
		return []netmap.Group{{Title: "Secret Group"}}, nil
	}
	t.Setenv("SUBNETS_DRIVE_ID", "drive")
	t.Setenv("SUBNETS_ITEM_ID", "item")
	t.Setenv("SUBNETS_SHEET", "")
	cfg := config.Config{QualysBaseURL: "https://qualys.example", QualysUsername: "u", QualysPassword: "p"}

	code, out := checkOut(t, cfg)
	if code != exitOK || !strings.Contains(out, "1 Asset Group(s)") || !strings.Contains(out, "2 row(s)") ||
		!strings.Contains(out, "2 scan(s) launched in 7 days, 1 scheduled") ||
		!strings.Contains(out, "network row(s) under") || strings.Contains(out, "site(s)") ||
		!strings.Contains(out, "scan schedules, 2 in all, 1 due in the last 7 days, 1 switched off, 0 not judged") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "scans expected from the Qualys scan schedules alone") {
		t.Errorf("with VMSCAN_SCANS unset, --check must say the schedules decide:\n%s", out)
	}
	if strings.Contains(out, "Secret Scan") || strings.Contains(out, "Secret Weekly") {
		t.Errorf("--check prints counts only, never a scan title:\n%s", out)
	}
	for _, name := range []string{"Secret Plant", "Secret Group", "10.1.30"} {
		if strings.Contains(out, name) {
			t.Errorf("--check printed %q:\n%s", name, out)
		}
	}

	t.Setenv("SUBNETS_SHEET", "Nope")
	if code, _ := checkOut(t, cfg); code != exitErr {
		t.Error("a missing sheet passed the check")
	}
	t.Setenv("SUBNETS_SHEET", "")

	t.Setenv("SUBNETS_ITEM_ID", "")
	if code, _ := checkOut(t, cfg); code != exitErr {
		t.Error("an unlocated spreadsheet passed the check")
	}
	t.Setenv("SUBNETS_ITEM_ID", "item")

	fetchGroups = func(context.Context, string, string, string) ([]netmap.Group, error) {
		return nil, errors.New("401")
	}
	if code, _ := checkOut(t, cfg); code != exitErr {
		t.Error("a Qualys failure passed the check")
	}
	if code, _ := checkOut(t, config.Config{}); code != exitErr {
		t.Error("no Qualys settings passed the check")
	}

	graphToken = func(context.Context, *graph.Client) error { return errors.New("AADSTS7000215") }
	driveContent = func(context.Context, *graph.Client, string, string) ([]byte, error) {
		t.Error("the spreadsheet was fetched without a token")
		return nil, errors.New("no")
	}
	if code, out := checkOut(t, cfg); code != exitErr || !strings.Contains(out, "AADSTS7000215") {
		t.Errorf("a Graph failure passed: exit %d\n%s", code, out)
	}
}
