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

// Limits on what one workbook may make this package do. A real form or subnet
// sheet is well under a megabyte and a few hundred cells; these are for a file
// built to hurt: a zip that lies about its size, a cell that names column
// 'ZZZZZZZZZZ', a million rows that each name the last column.
const (
	// maxPart bounds one file read from the workbook.
	maxPart = 16 << 20
	// maxTotal bounds everything decompressed for one call, across parts.
	maxTotal = 24 << 20
	// maxCols and maxRows are Excel's own limits (column XFD, row 1,048,576).
	maxCols = 16384
	maxRows = 1 << 20
	// maxCellSlots bounds the cells allocated for one sheet, padding included.
	// A row padded to its last cell costs a slot for every column before it, so
	// a sheet of one-cell rows in column XFD would otherwise cost 16,384 each.
	maxCellSlots = 4 << 20
)

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

// parts reads the workbook's XML parts under one shared budget.
type parts struct {
	zr   *zip.Reader
	left int64
}

func newParts(zr *zip.Reader) *parts { return &parts{zr: zr, left: maxTotal} }

func (p *parts) read(name string) ([]byte, error) {
	for _, f := range p.zr.File {
		if f.Name != name {
			continue
		}
		limit := int64(maxPart)
		if p.left < limit {
			limit = p.left
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer func() { _ = rc.Close() }()
		b, err := io.ReadAll(io.LimitReader(rc, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("%s is too large to read (the limits are %d bytes a part and %d for the workbook)", name, maxPart, maxTotal)
		}
		p.left -= int64(len(b))
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
	pr := newParts(zr)
	wbB, err := pr.read("xl/workbook.xml")
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
	pr := newParts(zr)
	wbB, err := pr.read("xl/workbook.xml")
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
	relB, err := pr.read("xl/_rels/workbook.xml.rels")
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
	b, serr := pr.read("xl/sharedStrings.xml")
	if serr != nil && !strings.Contains(serr.Error(), "no xl/sharedStrings.xml") {
		// Present but unreadable (over the size limit, say): an error, not "no
		// shared strings", which would read every text cell as blank.
		return nil, serr
	}
	if serr == nil {
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

	sheetB, err := pr.read(target)
	if err != nil {
		return nil, err
	}
	var sd xmlSheetData
	if err := xml.Unmarshal(sheetB, &sd); err != nil {
		return nil, fmt.Errorf("%s: %w", target, err)
	}
	if len(sd.Rows) > maxRows {
		return nil, fmt.Errorf("%s has more than %d rows", target, maxRows)
	}
	var out []Row
	slots := 0
	for n, row := range sd.Rows {
		num := row.R
		if num == 0 {
			num = n + 1
		}
		var cells []string
		for _, c := range row.Cells {
			col := colIndex(c.Ref)
			if col >= maxCols {
				continue // not a cell Excel could have written: ignored, not allocated
			}
			if grow := col + 1 - len(cells); grow > 0 {
				if slots += grow; slots > maxCellSlots {
					return nil, fmt.Errorf("%s is too large to read (more than %d cells)", target, maxCellSlots)
				}
				cells = append(cells, make([]string, grow)...)
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
		if n > maxCols {
			return maxCols // far past any real column; the caller ignores it, and n cannot overflow
		}
	}
	if n == 0 {
		return 0
	}
	return n - 1
}
