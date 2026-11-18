package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/vmscan"
)

func sheetTicket() map[string]any {
	return map[string]any{
		"key": "SEC-77",
		"fields": map[string]any{
			"summary": "Network spreadsheet: 1 location(s) to correct",
			"status": map[string]any{"name": "Waiting for support",
				"statusCategory": map[string]any{"key": "indeterminate"}},
			"labels": []string{"cti-agent", vmscanFixesLabel},
		},
	}
}

func fixesFile(t *testing.T, ff vmscan.FixesFile) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fixes.json")
	if err := os.WriteFile(p, ff.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The weekly report names the spreadsheet ticket and says what happened to
// it. --ref-out is how that reaches cti-vmscan --stamp-ticket.
func TestVMScanRefOutNamesTheTicketAndWhatHappened(t *testing.T) {
	fixes := []vmscan.SheetFix{{Location: "Site A", Kind: "blank", Title: "Blank", Problem: "no network", Action: "add it"}}
	path := fixesFile(t, vmscan.FixesFile{Hash: vmscan.FixesHash(fixes), Fixes: fixes, Cleanup: []vmscan.SheetFix{}})

	for _, tc := range []struct {
		forReal bool
		want    string
	}{{false, "would-comment"}, {true, "commented"}} {
		fj, c := newFakeJira(t, sheetTicket())
		ref := filepath.Join(t.TempDir(), "ref.json")
		if rc := doVMScanFixes(context.Background(), c, testCfg, path, tc.forReal, time.Now(), ref); rc != exitOK {
			t.Fatalf("forReal=%v: rc %d", tc.forReal, rc)
		}
		got, err := vmscan.ReadTicketRef(ref)
		if err != nil {
			t.Fatalf("forReal=%v: no ref written: %v", tc.forReal, err)
		}
		if got.Action != tc.want || got.Key != "SEC-77" || got.Status != "Waiting for support" ||
			!strings.HasSuffix(got.URL, "/browse/SEC-77") {
			t.Errorf("forReal=%v: ref = %+v", tc.forReal, got)
		}
		if line, _ := vmscan.TicketLine(got); !strings.Contains(line, "SEC-77") {
			t.Errorf("forReal=%v: line %q does not name the ticket", tc.forReal, line)
		}
		if n := len(fj.comments["SEC-77"]); (n == 1) != tc.forReal {
			t.Errorf("forReal=%v: %d comment(s) posted", tc.forReal, n)
		}
	}
}

// A week with nothing to correct and no ticket open has nothing to say; a
// list for a sheet with no open ticket is a would-create on a preview.
func TestVMScanRefOutWithNoOpenTicket(t *testing.T) {
	for _, tc := range []struct {
		fixes []vmscan.SheetFix
		want  string
	}{
		{nil, "none"},
		{[]vmscan.SheetFix{{Location: "Site B", Kind: "blank"}}, "would-create"},
	} {
		_, c := newFakeJira(t)
		ff := vmscan.FixesFile{Fixes: tc.fixes, Cleanup: []vmscan.SheetFix{}}
		if ff.Fixes == nil {
			ff.Fixes = []vmscan.SheetFix{}
		}
		ff.Hash = vmscan.FixesHash(ff.Fixes)
		ref := filepath.Join(t.TempDir(), "ref.json")
		if rc := doVMScanFixes(context.Background(), c, testCfg, fixesFile(t, ff), false, time.Now(), ref); rc != exitOK {
			t.Fatalf("%s: rc %d", tc.want, rc)
		}
		got, err := vmscan.ReadTicketRef(ref)
		if err != nil || got.Action != tc.want {
			t.Errorf("want %s: ref = %+v, err %v", tc.want, got, err)
		}
	}
}
