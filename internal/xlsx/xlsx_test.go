package xlsx

import (
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/xlsx/xlsxtest"
)

var sample = [][]string{
	{"Location", "Network", "Mask/VLAN", "Gateway"},
	{"Alpha Site - ST - 10.1.0.0/16"},
	{"corp", "10.1.30.0/24", "vlan1"},
	{"10.1.30.1", "firewall"},
	{"", "an address note"},
}

func TestReadsSheetsByNameAndKeepsTextAndInlineCells(t *testing.T) {
	x := xlsxtest.Build(t, map[string][][]string{"Sites": sample, "Home": {{"INLINE", "x"}}}, []string{"Sites", "Home"})
	rows, err := ReadSheet(x, "sites")
	if err != nil || len(rows) != len(sample) {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[2][0] != "corp" || rows[2][1] != "10.1.30.0/24" {
		t.Errorf("row 3 = %v", rows[2])
	}
	home, _ := ReadSheet(x, "Home")
	if home[0][0] != "inline text" {
		t.Errorf("inline = %v", home)
	}
	if _, err := ReadSheet(x, "Nope"); err == nil || !strings.Contains(err.Error(), "Sites, Home") {
		t.Errorf("a missing sheet should name the ones there: %v", err)
	}
	if _, err := ReadSheet([]byte("not a zip"), "Sites"); err == nil {
		t.Error("garbage was accepted as a workbook")
	}
}

func TestSheetNamesAreInWorkbookOrder(t *testing.T) {
	x := xlsxtest.Build(t, map[string][][]string{"Sites": sample, "Home": {{"x"}}}, []string{"Sites", "Home"})
	names, err := SheetNames(x)
	if err != nil || strings.Join(names, ",") != "Sites,Home" {
		t.Fatalf("names %v, err %v", names, err)
	}
	if _, err := SheetNames([]byte("not a zip")); err == nil {
		t.Error("garbage was accepted as a workbook")
	}
}

func TestRowsKeepTheirSheetRowNumbers(t *testing.T) {
	x := xlsxtest.Build(t, map[string][][]string{"Sites": sample}, []string{"Sites"})
	rows, err := ReadSheetRows(x, "Sites")
	if err != nil || len(rows) != len(sample) {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[2].Num != 3 || rows[2].Cells[0] != "corp" {
		t.Errorf("row = %+v", rows[2])
	}
}
