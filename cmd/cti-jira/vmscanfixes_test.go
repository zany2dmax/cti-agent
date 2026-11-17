package main

import (
	"strings"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/jira"
	"github.com/zany2dmax/cti-agent/internal/vmscan"
)

func fixesOf(n int) vmscan.FixesFile {
	f := vmscan.FixesFile{}
	for i := 0; i < n; i++ {
		f.Fixes = append(f.Fixes, vmscan.SheetFix{Location: "Site " + string(rune('A'+i)), Kind: "blank-network",
			Title: "Corp row with no network written in it", Problem: "its corp row has no network written in it",
			Action: "Network team: fill in this location's corp network."})
	}
	f.Hash = vmscan.FixesHash(f.Fixes)
	return f
}

func TestPlanVMScanFixes(t *testing.T) {
	open := &jira.Issue{Key: "CR-9"}
	two := fixesOf(2)
	cases := []struct {
		name string
		open *jira.Issue
		prev vmscanFixesState
		ff   vmscan.FixesFile
		want domainsPlan
	}{
		{"held touches nothing", open, vmscanFixesState{Hash: "x"}, vmscan.FixesFile{Held: true, HeldWhy: "no scan"}, domainsNothing},
		{"nothing to do", nil, vmscanFixesState{}, fixesOf(0), domainsNothing},
		{"first list files a ticket", nil, vmscanFixesState{}, two, domainsCreate},
		{"same list, no comment", open, vmscanFixesState{Hash: two.Hash}, two, domainsNothing},
		{"changed list comments", open, vmscanFixesState{Hash: "old"}, two, domainsComment},
		{"emptied list says done", open, vmscanFixesState{Hash: two.Hash}, fixesOf(0), domainsDone},
		{"said done once", open, vmscanFixesState{Resolved: true}, fixesOf(0), domainsNothing},
	}
	for _, c := range cases {
		if got, _ := planVMScanFixes(c.open, c.prev, c.ff); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVMScanFixesBodyEscapesTheSheetsText(t *testing.T) {
	ff := fixesOf(1)
	ff.Fixes[0].Location = "Odd {color:red}Site|[link]"
	ff.Fixes[0].Row = 1169
	body := vmscanFixesBody(ff, time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	if strings.Contains(body, "{color:red}") || strings.Contains(body, "|[link]") {
		t.Errorf("wiki markup from the sheet reached the ticket:\n%s", body)
	}
	for _, want := range []string{"h3. Corp row with no network written in it", "(sheet row 1169)",
		"Network team: fill in", "help desk to assign to the network team"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if s := vmscanFixesSummary(ff, time.Now()); !strings.Contains(s, "1 location(s) to correct") {
		t.Errorf("summary %q", s)
	}
}

func TestTheSpreadsheetTicketHasItsOwnKindInTheList(t *testing.T) {
	if k := ticketKind([]string{"cti-agent", vmscanFixesLabel}); k != "spreadsheet" {
		t.Errorf("kind = %q", k)
	}
}
