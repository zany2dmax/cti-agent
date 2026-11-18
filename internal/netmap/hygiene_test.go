package netmap

import (
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/xlsx"
)

func numbered(rows [][]string) []xlsx.Row {
	out := make([]xlsx.Row, len(rows))
	for i, r := range rows {
		out[i] = xlsx.Row{Num: i + 1, Cells: r}
	}
	return out
}

// The real sheet's clean-up cases (2026-11-18), with invented names.
var hygieneSheet = [][]string{
	{"DECOMISSIONED - Old Branch - 10.2.0.0/16"}, {"corp", "10.2.30.0/24", "vlan1"},
	{"Decommissioned?? - Maybe Branch - 10.35.0.0/16"}, {"corp", "10.35.30.0/24", "vlan1"},
	{"Harbour Store - 10.44.0.0/16 - Formally Old Store Decommissioned 8/1/2025"}, {"corp", "10.44.30.0/24", "vlan30"},
	{"Datacenter - Example -"}, {"Servers", "192.168.200.0/24", "vlan200"},
	{"Tiny - 10.77.30.0/24"}, {"corp", "10.77.30.0/24", "vlan1"},
	{"Cabinet Shop - 10.20.0.0/16"}, {"internet", "ATT: 198.51.100.81", "255.255.255.248"},
	{"Employee LAN", "10.20.30.0/24", "vlan30"},
	{"Norcross Branch - 10.14.0.0/16"}, {"setup", "10.20.30.0/24", "vlan1"}, {"corp", "10.14.30.0/24", "vlan30"},
	{"Overflow - 10.79.0.0/16"}, {"corp", "10.79.30.0/23", "vlan30"}, {"security", "", "vlan210"},
	{"netman", "10.80.220.0/24", "vlan220"},
	{"Miami Store - 10.70.0.0/16"}, {"internet", "198.51.100.57"}, {"corp", "10.70.30.0/24", "vlan1"},
	{"Lauderdale Store - 10.69.0.0/16"}, {"internet", "198.51.100.57"}, {"corp", "10.69.30.0/24", "vlan1"},
}

func hygiene(t *testing.T) map[CleanupKind][]Cleanup {
	t.Helper()
	rows := numbered(hygieneSheet)
	subs := ParseSiteRows(rows)
	_, qs := SelectCorp(subs, Rules{})
	got := map[CleanupKind][]Cleanup{}
	for _, c := range Hygiene(rows, subs, qs) {
		got[c.Kind] = append(got[c.Kind], c)
	}
	return got
}

func TestHygieneFindsTheSheetsHeaderProblems(t *testing.T) {
	got := hygiene(t)
	if len(got[CMisspelledDecom]) != 1 || !strings.HasPrefix(got[CMisspelledDecom][0].Location, "DECOMISSIONED") {
		t.Errorf("misspelling: %+v", got[CMisspelledDecom])
	}
	if len(got[CDecomMention]) != 1 || !strings.HasPrefix(got[CDecomMention][0].Location, "Harbour Store") {
		t.Errorf("decommission mentioned: %+v", got[CDecomMention])
	}
	if len(got[CUnsure]) != 1 || !strings.Contains(got[CUnsure][0].Location, "Maybe Branch") {
		t.Errorf("unsure: %+v", got[CUnsure])
	}
	var noBlock []string
	for _, c := range got[CNoBlock] {
		noBlock = append(noBlock, c.Location+": "+c.Why)
	}
	if len(noBlock) != 2 || !strings.Contains(strings.Join(noBlock, "|"), "names 10.77.30.0/24, not the location's /16") {
		t.Errorf("no block: %q", noBlock)
	}
}

func TestHygieneFindsStrayOverlappingAndBlankRows(t *testing.T) {
	got := hygiene(t)
	var stray []string
	for _, c := range got[COutsideRows] {
		stray = append(stray, c.Location+": "+c.Why)
	}
	all := strings.Join(stray, "|")
	if !strings.Contains(all, "Norcross Branch - 10.14.0.0/16: outside 10.14.0.0/16: 10.20.30.0/24 (setup)") ||
		!strings.Contains(all, "Overflow - 10.79.0.0/16: outside 10.79.0.0/16: 10.80.220.0/24 (netman)") {
		t.Errorf("stray rows: %q", stray)
	}
	if len(got[COverlapRows]) != 1 || !strings.Contains(got[COverlapRows][0].Why, "10.20.30.0/24 (Employee LAN) and 10.20.30.0/24 (setup)") {
		t.Errorf("overlap: %+v", got[COverlapRows])
	}
	if len(got[CBlankRows]) != 1 || got[CBlankRows][0].Why != "no network written for: security" {
		t.Errorf("blank rows: %+v", got[CBlankRows])
	}
	if len(got[CSharedPublicIP]) != 1 || !strings.Contains(got[CSharedPublicIP][0].Why, "198.51.100.57 is also listed under Lauderdale Store") {
		t.Errorf("shared IP: %+v", got[CSharedPublicIP])
	}
}

func TestHygieneLeavesClosedSitesAndOtherPlansAlone(t *testing.T) {
	got := hygiene(t)
	for _, cs := range got {
		for _, c := range cs {
			if c.Kind != CMisspelledDecom && c.Kind != CUnsure && strings.Contains(c.Location, "Old Branch") {
				t.Errorf("a closed site's rows were picked at: %+v", c)
			}
			if c.Kind == COutsideRows && strings.Contains(c.Why, "192.168") {
				t.Errorf("a 192.168 network is another addressing plan, not a stray row: %+v", c)
			}
		}
	}
}

func TestNotesAreReadAndPlacedOnTheirHeader(t *testing.T) {
	notes, problems := ParseNotes("# a comment\nCabinet Shop | the redesign gives it 10.21.0.0/16\n" +
		"Cancos | no location in the sheet\nbroken line\n")
	if len(notes) != 2 || len(problems) != 1 {
		t.Fatalf("notes %+v problems %v", notes, problems)
	}
	placed := PlaceNotes(notes, ParseSiteRows(numbered(hygieneSheet)))
	if placed[0].Location != "Cabinet Shop - 10.20.0.0/16" || placed[0].Row == 0 {
		t.Errorf("a note on a known location takes its header and row: %+v", placed[0])
	}
	if placed[1].Location != "Cancos" || placed[1].Row != 0 {
		t.Errorf("a note on a missing site keeps its name and no row: %+v", placed[1])
	}
}
