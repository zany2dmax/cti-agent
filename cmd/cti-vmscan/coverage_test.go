package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/config"
	"github.com/zany2dmax/cti-agent/internal/netmap"
	"github.com/zany2dmax/cti-agent/internal/vmscan"
)

const groupsXML = `<ASSET_GROUP_LIST_OUTPUT><RESPONSE><ASSET_GROUP_LIST>
<ASSET_GROUP><ID>1</ID><TITLE>Alpha</TITLE><IP_SET><IP_RANGE>10.1.30.0-10.1.30.255</IP_RANGE></IP_SET></ASSET_GROUP>
</ASSET_GROUP_LIST></RESPONSE></ASSET_GROUP_LIST_OUTPUT>`

func qualysStub(t *testing.T, status int, body string) config.Config {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/2.0/fo/asset/group/") || r.URL.Query().Get("action") != "list" {
			t.Errorf("unexpected request %s", r.URL)
		}
		if r.Header.Get("X-Requested-With") == "" {
			t.Error("the Qualys API needs X-Requested-With")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return config.Config{QualysBaseURL: srv.URL, QualysUsername: "u", QualysPassword: "p"}
}

func weekScanning(groups ...string) vmscan.Week {
	return vmscan.Week{Scans: []vmscan.Scan{{Title: "Weekly", TargetGroups: groups, Start: time.Now()}}}
}

// The whole check against a synthetic spreadsheet and a stub Qualys: Alpha is
// scanned, Beta and Gamma are in no group, Delta has no corp row.
func TestTheCoverageCheckEndToEnd(t *testing.T) {
	cfg := qualysStub(t, 200, groupsXML)
	t.Setenv("NETRULES_FILE", "/nonexistent")
	c := coverage(context.Background(), cfg, nil, weekScanning("Alpha"), "testdata/subnets.xlsx")
	if c.Unavailable != "" {
		t.Fatalf("unavailable: %s", c.Unavailable)
	}
	if c.Checked != 3 || c.Covered != 1 {
		t.Errorf("checked %d covered %d", c.Checked, c.Covered)
	}
	gaps := map[string]bool{}
	for _, f := range c.Gaps() {
		if f.Kind != netmap.NotInAnyGroup {
			t.Errorf("unexpected gap %+v", f)
		}
		gaps[f.Location] = true
	}
	if !gaps["Beta Site - ST - 10.2.0.0/16"] || !gaps["Gamma Site - 10.3.0.0/16"] || len(gaps) != 2 {
		t.Errorf("gaps = %v", gaps)
	}
	if len(c.Questions) != 1 || !strings.HasPrefix(c.Questions[0].Location, "Delta Site") {
		t.Errorf("questions = %+v", c.Questions)
	}
}

func TestAnOperatorRuleSilencesAQuestion(t *testing.T) {
	cfg := qualysStub(t, 200, groupsXML)
	rules := t.TempDir() + "/netrules.txt"
	if err := os.WriteFile(rules, []byte("Delta Site | ignore\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETRULES_FILE", rules)
	c := coverage(context.Background(), cfg, nil, weekScanning("Alpha"), "testdata/subnets.xlsx")
	if len(c.Questions) != 0 {
		t.Errorf("questions = %+v", c.Questions)
	}
}

// Anything that stops the check running is said, and the weekly still goes out.
func TestAnythingThatStopsTheCheckIsReportedNotHidden(t *testing.T) {
	t.Setenv("NETRULES_FILE", "/nonexistent")
	t.Setenv("SUBNETS_DRIVE_ID", "")
	t.Setenv("SUBNETS_ITEM_ID", "")
	cfg := qualysStub(t, 200, groupsXML)
	if c := coverage(context.Background(), cfg, nil, weekScanning("Alpha"), ""); !strings.Contains(c.Unavailable, "SUBNETS_DRIVE_ID") {
		t.Errorf("unlocated sheet: %q", c.Unavailable)
	}
	if c := coverage(context.Background(), cfg, nil, weekScanning("Alpha"), "testdata/missing.xlsx"); !strings.Contains(c.Unavailable, "could not be read") {
		t.Errorf("missing file: %q", c.Unavailable)
	}
	if c := coverage(context.Background(), config.Config{}, nil, weekScanning("Alpha"), "testdata/subnets.xlsx"); !strings.Contains(c.Unavailable, "QUALYS_BASE_URL") {
		t.Errorf("no credentials: %q", c.Unavailable)
	}
	bad := qualysStub(t, 403, "Access denied")
	if c := coverage(context.Background(), bad, nil, weekScanning("Alpha"), "testdata/subnets.xlsx"); !strings.Contains(c.Unavailable, "HTTP 403") {
		t.Errorf("a refusal: %q", c.Unavailable)
	}
}
