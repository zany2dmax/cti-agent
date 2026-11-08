// Package xlsxtest builds small .xlsx workbooks for tests, so every package that
// reads a workbook tests against the same shape of file.
package xlsxtest

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Build writes a minimal workbook with the given sheets: shared strings for
// text, the way Excel does, plus one inline string to cover both.
func Build(t *testing.T, sheets map[string][][]string, order []string) []byte {
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
	var shared []string
	idx := map[string]int{}
	si := func(s string) int {
		if i, ok := idx[s]; ok {
			return i
		}
		idx[s] = len(shared)
		shared = append(shared, s)
		return idx[s]
	}
	var wb, rels strings.Builder
	wb.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	rels.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for n, name := range order {
		fmt.Fprintf(&wb, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, name, n+1, n+1)
		fmt.Fprintf(&rels, `<Relationship Id="rId%d" Target="worksheets/sheet%d.xml"/>`, n+1, n+1)
		var sd strings.Builder
		sd.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
		for r, row := range sheets[name] {
			fmt.Fprintf(&sd, `<row r="%d">`, r+1)
			for c, v := range row {
				if v == "" {
					continue
				}
				ref := fmt.Sprintf("%c%d", 'A'+c, r+1)
				if v == "INLINE" {
					fmt.Fprintf(&sd, `<c r="%s" t="inlineStr"><is><t>inline text</t></is></c>`, ref)
					continue
				}
				fmt.Fprintf(&sd, `<c r="%s" t="s"><v>%d</v></c>`, ref, si(v))
			}
			sd.WriteString(`</row>`)
		}
		sd.WriteString(`</sheetData></worksheet>`)
		add(fmt.Sprintf("xl/worksheets/sheet%d.xml", n+1), sd.String())
	}
	wb.WriteString(`</sheets></workbook>`)
	rels.WriteString(`</Relationships>`)
	add("xl/workbook.xml", wb.String())
	add("xl/_rels/workbook.xml.rels", rels.String())
	var sst strings.Builder
	sst.WriteString(`<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	for _, s := range shared {
		fmt.Fprintf(&sst, `<si><t>%s</t></si>`, s)
	}
	sst.WriteString(`</sst>`)
	add("xl/sharedStrings.xml", sst.String())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
