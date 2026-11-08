// Package supplier reads the new-supplier request form that arrives in the
// supplier-request mailbox, so the supplier-request lane can judge each request
// from what the requester wrote.
//
// The form is an .xlsx the requester fills in. It is read as people lay it out,
// not as a table: a label cell, then the answer in a cell to its right. The
// answer's column is not fixed, and the form exists in more than one version,
// so a field is found by its label text, never by its position.
//
// This package only reads the form. It never opens the tax (W-9) or bank
// attachments, and it does nothing with a form but return its fields: the
// caller decides what to do with them.
package supplier

import (
	"fmt"
	"strings"

	"github.com/zany2dmax/cti-agent/internal/xlsx"
)

// Form is what a requester wrote on the form. A field the requester left blank
// is the empty string: forms arrive half filled in, and that is data too.
type Form struct {
	// Request is the first choice on the form: new, or reactivate or update an
	// existing supplier. Kind turns it into one of three words.
	Request string
	// Branch is the branch or market that will use the supplier.
	Branch string
	ERP    string
	// Class is "Expense" or "Inventory" as chosen on the form.
	Class string
	Name  string
	// Address is the remittance address, its lines joined with ", ".
	Address       string
	ARContact     string
	PaymentTerms  string
	DiscountTerms string
	// MonthlySpend and CreditLimit are kept as written ("1500", "$2,000").
	MonthlySpend string
	CreditLimit  string
	PORequired   string
	CardNoFee    string
	ACH          string
	RemitEmail   string
	RequestedBy  string
	ApprovedBy   string
	// Notes is the free-text comment, the most useful field for judging what
	// the supplier does.
	Notes string

	// Missing lists the labels the form marks required (with a *) that the
	// requester left empty, as written on the form.
	Missing []string
}

// Kind is "new", "reactivate" or "update", or "" when the choice is blank or
// is something else.
func (f Form) Kind() string {
	v := strings.ToLower(strings.TrimSpace(f.Request))
	switch {
	case strings.HasPrefix(v, "new"):
		return "new"
	case strings.HasPrefix(v, "reactivate"):
		return "reactivate"
	case strings.HasPrefix(v, "update"):
		return "update"
	}
	return ""
}

// field ties a label (found in the normalized label text) to where its answer
// goes. Order matters only where one label could contain another's key.
type field struct {
	key string
	set func(*Form, string)
}

var fields = []field{
	{"new supplier or reactivate", func(f *Form, v string) { f.Request = v }},
	{"branch", func(f *Form, v string) { f.Branch = v }},
	{"erp", func(f *Form, v string) { f.ERP = v }},
	{"expense or inventory", func(f *Form, v string) { f.Class = v }},
	{"supplier name", func(f *Form, v string) { f.Name = v }},
	{"remittance address", func(f *Form, v string) { f.Address = v }},
	{"accounts receivable contact", func(f *Form, v string) { f.ARContact = v }},
	{"payment terms", func(f *Form, v string) { f.PaymentTerms = v }},
	{"discount terms", func(f *Form, v string) { f.DiscountTerms = v }},
	{"anticipated monthly spend", func(f *Form, v string) { f.MonthlySpend = v }},
	{"credit limit", func(f *Form, v string) { f.CreditLimit = v }},
	{"po required", func(f *Form, v string) { f.PORequired = v }},
	{"credit card payments", func(f *Form, v string) { f.CardNoFee = v }},
	{"ach payments", func(f *Form, v string) { f.ACH = v }},
	{"electronic remittance", func(f *Form, v string) { f.RemitEmail = v }},
	{"requested by", func(f *Form, v string) { f.RequestedBy = v }},
	{"approved by", func(f *Form, v string) { f.ApprovedBy = v }},
	{"additional notes", func(f *Form, v string) { f.Notes = v }},
}

// normalize lowercases a label and drops the required marker and extra spaces.
func normalize(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "*", ""))
	return strings.Join(strings.Fields(s), " ")
}

func lookup(label string) *field {
	n := normalize(label)
	for i := range fields {
		if strings.Contains(n, fields[i].key) {
			return &fields[i]
		}
	}
	return nil
}

// sheetFor picks the worksheet that holds the form: the one named like the
// form, else the first that is not the instructions or the dropdown lists.
func sheetFor(data []byte) (string, error) {
	names, err := xlsx.SheetNames(data)
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if strings.EqualFold(strings.TrimSpace(n), "supplier request form") {
			return n, nil
		}
	}
	for _, n := range names {
		l := strings.ToLower(n)
		if strings.Contains(l, "supplier") && !strings.Contains(l, "instruction") && !strings.Contains(l, "list") {
			return n, nil
		}
	}
	return "", fmt.Errorf("no supplier request form sheet in the workbook (it has: %s)", strings.Join(names, ", "))
}

// Parse reads the supplier request form from an .xlsx workbook. A workbook
// with no form sheet, or a sheet with no recognizable field, is an error that
// says so, so the caller can report the form as unreadable instead of treating
// it as an empty one.
func Parse(data []byte) (Form, error) {
	name, err := sheetFor(data)
	if err != nil {
		return Form{}, err
	}
	rows, err := xlsx.ReadSheetRows(data, name)
	if err != nil {
		return Form{}, err
	}

	vals := map[string]string{} // answers by field key, built up across rows
	type req struct{ key, label string }
	var required []req
	var cur *field // the field the previous row set, for continuation rows
	var curCol int
	for _, r := range rows {
		col := -1
		for i, c := range r.Cells {
			if strings.TrimSpace(c) != "" {
				col = i
				break
			}
		}
		if col < 0 {
			continue
		}
		label := strings.TrimSpace(r.Cells[col])

		// A row whose first cell sits to the right of the previous label, with
		// no label of its own, carries on that answer (an address's second
		// line). A hint under a label starts at the label's own column, so it
		// is not mistaken for one.
		if cur != nil && col > curCol {
			if v := join(r.Cells[col:]); v != "" {
				vals[cur.key] = joinParts(vals[cur.key], v)
			}
			continue
		}

		fl := lookup(label)
		if fl == nil {
			continue
		}
		cur, curCol = fl, col
		vals[fl.key] = join(r.Cells[col+1:])
		if strings.Contains(label, "*") {
			required = append(required, req{fl.key, strings.TrimSpace(strings.ReplaceAll(label, "*", ""))})
		}
	}
	if cur == nil {
		return Form{}, fmt.Errorf("sheet %q has none of the supplier form's fields", name)
	}
	var f Form
	for i := range fields {
		if v, ok := vals[fields[i].key]; ok {
			fields[i].set(&f, v)
		}
	}
	// A required field is missing only if nothing was written in it, on its own
	// row or on a continuation row under it.
	for _, r := range required {
		if vals[r.key] == "" {
			f.Missing = append(f.Missing, r.label)
		}
	}
	return f, nil
}

// join joins the non-empty cells with a space.
func join(cells []string) string {
	var parts []string
	for _, c := range cells {
		if c = strings.TrimSpace(c); c != "" {
			parts = append(parts, c)
		}
	}
	return strings.Join(parts, " ")
}

func joinParts(a, b string) string {
	if a == "" {
		return b
	}
	return a + ", " + b
}
