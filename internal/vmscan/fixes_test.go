package vmscan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zany2dmax/cti-agent/internal/netmap"
)

func TestFixesListsTheSheetQuestionsInTheEmailsOrder(t *testing.T) {
	c := &Coverage{Questions: []netmap.Question{
		{Location: "Datacenter", Kind: netmap.QNoCorpRow, Row: 3, Why: "no row counts"},
		{Location: "Naples", Kind: netmap.QInvalid, Row: 469, Why: `its corp network "10.29.30" is not a valid network`},
		{Location: "Deerfield", Kind: netmap.QBlank, Row: 1169, Why: "its corp row has no network written in it"},
	}, Findings: []netmap.Finding{{Kind: netmap.NotInAnyGroup, Location: "Fuse Boca"}}}
	f := c.Fixes(time.Now())
	if f.Held || len(f.Fixes) != 3 || f.Hash == "" {
		t.Fatalf("%+v", f)
	}
	// Blank, then invalid, then no corp row; not-scanned networks are not in it.
	if f.Fixes[0].Location != "Deerfield" || f.Fixes[1].Location != "Naples" || f.Fixes[2].Location != "Datacenter" {
		t.Errorf("order: %+v", f.Fixes)
	}
	var back FixesFile
	if err := json.Unmarshal(f.JSON(), &back); err != nil || back.Hash != f.Hash {
		t.Errorf("round trip: %v", err)
	}
}

// Inserting a row above a location moves its row number; nobody has to act.
func TestTheHashIgnoresRowNumbers(t *testing.T) {
	a := []SheetFix{{Location: "Naples", Kind: "invalid-network", Problem: "x", Row: 469}}
	b := []SheetFix{{Location: "Naples", Kind: "invalid-network", Problem: "x", Row: 470}}
	if FixesHash(a) != FixesHash(b) {
		t.Error("a moved row changed the hash")
	}
	c := []SheetFix{{Location: "Naples", Kind: "invalid-network", Problem: "y", Row: 469}}
	if FixesHash(a) == FixesHash(c) {
		t.Error("a different problem kept the hash")
	}
}

func TestFixesAreHeldWhenTheCheckDidNotRun(t *testing.T) {
	if f := (&Coverage{Unavailable: "no scan"}).Fixes(time.Now()); !f.Held || f.HeldWhy != "no scan" {
		t.Errorf("%+v", f)
	}
	var nilCov *Coverage
	if f := nilCov.Fixes(time.Now()); !f.Held {
		t.Errorf("%+v", f)
	}
}
