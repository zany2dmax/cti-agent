// Package xlsx reads the cells of an .xlsx workbook with the standard library
// only (archive/zip and encoding/xml): text, shared strings and inline strings,
// by sheet name, each row with its row number. It reads values as the file
// stores them. It does not evaluate formulas, format dates or numbers, or open
// anything but the workbook's own XML parts, so a workbook cannot make it read
// another file.
package xlsx

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// maxPart bounds one file read from the workbook. A real sheet of this kind is
// well under a megabyte; the cap is for a zip that lies about its size.
const maxPart = 32 << 20

type xmlSheet struct {
	Name string `xml:"name,attr"`
	RID  string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
}

type xmlWorkbook struct {
	Sheets []xmlSheet `xml:"sheets>sheet"`
}

type xmlRels struct {
	Rels []struct {
		ID     string `xml:"Id,attr"`
		Target string `xml:"Target,attr"`
	} `xml:"Relationship"`
}

type xmlSST struct {
	Items []struct {
		T string   `xml:"t"`
		R []string `xml:"r>t"`
	} `xml:"si"`
}

type xmlCell struct {
	Ref    string `xml:"r,attr"`
	Type   string `xml:"t,attr"`
	Value  string `xml:"v"`
	Inline string `xml:"is>t"`
}

type xmlRow struct {
	R     int       `xml:"r,attr"`
	Cells []xmlCell `xml:"c"`
}

type xmlSheetData struct {
	Rows []xmlRow `xml:"sheetData>row"`
}

func readPart(zr *zip.Reader, name string) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(io.LimitReader(rc, maxPart+1))
		if err != nil {
			return nil, err
		}
		if len(b) > maxPart {
			return nil, fmt.Errorf("%s is larger than %d bytes", name, maxPart)
		}
		return b, nil
	}
	return nil, fmt.Errorf("no %s in the workbook", name)
}

// SheetNames lists the worksheet names in workbook order, so a caller that does
// not know what a form's sheet is called can ask instead of guessing.
func SheetNames(data []byte) ([]string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not an .xlsx workbook: %w", err)
	}
	wbB, err := readPart(zr, "xl/workbook.xml")
	if err != nil {
		return nil, err
	}
	var wb xmlWorkbook
	if err := xml.Unmarshal(wbB, &wb); err != nil {
		return nil, fmt.Errorf("workbook.xml: %w", err)
	}
	names := make([]string, len(wb.Sheets))
	for i, sh := range wb.Sheets {
		names[i] = sh.Name
	}
	return names, nil
}

// ReadSheet returns one worksheet's rows that have any cell, in order, each
// row's cells by column (a short row is padded only as far as its last cell).
// Blank rows are not returned, so an index is not a row number. A workbook that
// is not an .xlsx, or a sheet that is not there, is an error that says so.
func ReadSheet(data []byte, sheetName string) ([][]string, error) {
	rows, err := ReadSheetRows(data, sheetName)
	if err != nil {
		return nil, err
	}
	out := make([][]string, len(rows))
	for i, r := range rows {
		out[i] = r.Cells
	}
	return out, nil
}

// Row is one worksheet row with its row number in the sheet, so a finding can
// say "row 1180" and the person fixing the spreadsheet can go straight to it.
type Row struct {
	Num   int
	Cells []string
}

// ReadSheetRows is ReadSheet with each row's number.
func ReadSheetRows(data []byte, sheetName string) ([]Row, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not an .xlsx workbook: %w", err)
	}
	wbB, err := readPart(zr, "xl/workbook.xml")
	if err != nil {
		return nil, err
	}
	var wb xmlWorkbook
	if err := xml.Unmarshal(wbB, &wb); err != nil {
		return nil, fmt.Errorf("workbook.xml: %w", err)
	}
	var rid string
	var names []string
	for _, s := range wb.Sheets {
		names = append(names, s.Name)
		if strings.EqualFold(strings.TrimSpace(s.Name), strings.TrimSpace(sheetName)) {
			rid = s.RID
		}
	}
	if rid == "" {
		return nil, fmt.Errorf("no worksheet named %q (the workbook has: %s)", sheetName, strings.Join(names, ", "))
	}
	relB, err := readPart(zr, "xl/_rels/workbook.xml.rels")
	if err != nil {
		return nil, err
	}
	var rels xmlRels
	if err := xml.Unmarshal(relB, &rels); err != nil {
		return nil, fmt.Errorf("workbook.xml.rels: %w", err)
	}
	target := ""
	for _, r := range rels.Rels {
		if r.ID == rid {
			target = r.Target
		}
	}
	if target == "" {
		return nil, fmt.Errorf("worksheet %q has no file in the workbook", sheetName)
	}
	if strings.HasPrefix(target, "/") {
		target = strings.TrimPrefix(target, "/")
	} else {
		target = path.Join("xl", target)
	}

	var shared []string
	if b, err := readPart(zr, "xl/sharedStrings.xml"); err == nil {
		var sst xmlSST
		if err := xml.Unmarshal(b, &sst); err != nil {
			return nil, fmt.Errorf("sharedStrings.xml: %w", err)
		}
		for _, it := range sst.Items {
			s := it.T
			if len(it.R) > 0 {
				s = strings.Join(it.R, "")
			}
			shared = append(shared, s)
		}
	}

	sheetB, err := readPart(zr, target)
	if err != nil {
		return nil, err
	}
	var sd xmlSheetData
	if err := xml.Unmarshal(sheetB, &sd); err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	var out []Row
	for n, row := range sd.Rows {
		num := row.R
		if num == 0 {
			num = n + 1
		}
		var cells []string
		for _, c := range row.Cells {
			col := colIndex(c.Ref)
			for len(cells) <= col {
				cells = append(cells, "")
			}
			switch c.Type {
			case "s":
				if i, err := strconv.Atoi(strings.TrimSpace(c.Value)); err == nil && i >= 0 && i < len(shared) {
					cells[col] = shared[i]
				}
			case "inlineStr":
				cells[col] = c.Inline
			default:
				cells[col] = c.Value
			}
		}
		out = append(out, Row{Num: num, Cells: cells})
	}
	return out, nil
}

// colIndex turns a cell reference's column letters into a zero-based index:
// "A12" is 0, "C3" is 2, "AA1" is 26.
func colIndex(ref string) int {
	n := 0
	for _, r := range ref {
		if r < 'A' || r > 'Z' {
			break
		}
		n = n*26 + int(r-'A') + 1
	}
	if n == 0 {
		return 0
	}
	return n - 1
}
