package xlsx

import (
	"archive/zip"
	"bytes"
	"strconv"
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

// rawBook builds a workbook whose one sheet is the given XML, for files built
// to hurt: the helper in xlsxtest only writes well-formed cells.
func rawBook(t *testing.T, sheetXML string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	add("xl/workbook.xml", `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>`)
	add("xl/_rels/workbook.xml.rels", `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>`)
	add("xl/worksheets/sheet1.xml", sheetXML)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const sheetHead = `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`

// A reference that names a column no workbook has is ignored, not allocated:
// before the limit it grew a slice to that column and killed the run.
func TestACellInAColumnNoWorkbookHasIsIgnored(t *testing.T) {
	x := rawBook(t, sheetHead+`<row r="1"><c r="A1" t="inlineStr"><is><t>keep</t></is></c>`+
		`<c r="ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ1" t="inlineStr"><is><t>boom</t></is></c>`+
		`<c r="XFE1" t="inlineStr"><is><t>past the last column</t></is></c>`+
		`<c r="XFD1" t="inlineStr"><is><t>last real column</t></is></c></row></sheetData></worksheet>`)
	rows, err := ReadSheetRows(x, "S")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, err %v", len(rows), err)
	}
	if rows[0].Cells[0] != "keep" || len(rows[0].Cells) != maxCols || rows[0].Cells[maxCols-1] != "last real column" {
		t.Errorf("cells = %d long, first %q", len(rows[0].Cells), rows[0].Cells[0])
	}
	for _, ref := range []string{"A1", "Z9", "XFD1"} {
		if colIndex(ref) >= maxCols {
			t.Errorf("%s is a real cell", ref)
		}
	}
	for _, ref := range []string{"XFE1", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ1"} {
		if colIndex(ref) < maxCols {
			t.Errorf("%s was accepted as a column", ref)
		}
	}
}

// Rows that each name the last column would cost 16,384 cells apiece.
func TestAWorkbookOfPaddedRowsIsRefusedNotAllocated(t *testing.T) {
	var sd strings.Builder
	sd.WriteString(sheetHead)
	for r := 1; r <= 400; r++ {
		sd.WriteString(`<row r="` + strconv.Itoa(r) + `"><c r="XFD` + strconv.Itoa(r) + `"><v>x</v></c></row>`)
	}
	sd.WriteString(`</sheetData></worksheet>`)
	if _, err := ReadSheetRows(rawBook(t, sd.String()), "S"); err == nil || !strings.Contains(err.Error(), "too large to read") {
		t.Fatalf("a sheet that would allocate millions of cells was read: %v", err)
	}
}

// A part that decompresses far past its size is stopped, whatever the zip says.
func TestAPartThatDecompressesPastTheLimitIsRefused(t *testing.T) {
	x := rawBook(t, sheetHead+strings.Repeat(" ", maxPart+1024)+`</sheetData></worksheet>`)
	if len(x) > 1<<20 {
		t.Fatalf("the test file is %d bytes, so it is not a compressed bomb", len(x))
	}
	if _, err := ReadSheetRows(x, "S"); err == nil || !strings.Contains(err.Error(), "too large to read") {
		t.Fatalf("an over-limit part was read: %v", err)
	}
}
