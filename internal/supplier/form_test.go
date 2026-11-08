package supplier

import (
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/xlsx/xlsxtest"
)

// Invented suppliers throughout: the real forms are not in the repo. The layout
// is the real one: a title, a required-fields note, then label cells in the
// second column with the answer in a cell to the right, hint rows under some
// labels, and an address that carries on to a second row.
var completeForm = [][]string{
	{"Supplier Request Form"},
	{"", "* Required Fields"},
	{"", "New Supplier or Reactivate/Update Existing Supplier*", "", "", "New Supplier"},
	{"", "Branch(es)/Markets Using Supplier*", "", "", "Plumbing"},
	{"", "ERP*"},
	{"", "Expense or Inventory Supplier*", "", "", "Expense"},
	{"", "Supplier Name*", "", "", "Example Geo Services, Inc."},
	{"", "(must agree with name on W-9)"},
	{"", "Remittance Address*", "", "", "1 Example Way, Springfield, XX  00000"},
	{"", "Supplier's Accounts Receivable Contact", "", "(800) 555-0100", "", "ar@example.test"},
	{"", "Payment Terms", "", "", "N30"},
	{"", "Anticipated Monthly Spend*", "", "", "1500"},
	{"", "Credit Limit Requested*", "", "", "0"},
	{"", "PO Required (Y/N)*", "", "", "No"},
	{"", "Does the supplier accept ACH payments?"},
	{"", "  *If yes, ACH instructions on company letterhead or a bank letter must be attached"},
	{"", "Email address for electronic remittance", "", "", "remit@example.test"},
	{"", "Requested by*", "", "", "A. Requester"},
	{"", "Approved by*", "", "", "A. Approver"},
	{"", "Additional notes/comments", "", "", "Site coring services"},
}

func workbook(t *testing.T, form [][]string) []byte {
	t.Helper()
	return xlsxtest.Build(t, map[string][][]string{
		"Instructions":          {{"Supplier Request Form Instructions"}, {"", "Approved by", "Someone"}},
		"Supplier Request Form": form,
		"Lists":                 {{"New Supplier", "", "", "Appliances"}},
	}, []string{"Instructions", "Supplier Request Form", "Lists"})
}

func TestReadsTheFieldsByLabelNotPosition(t *testing.T) {
	f, err := Parse(workbook(t, completeForm))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"Request": {f.Request, "New Supplier"}, "Branch": {f.Branch, "Plumbing"},
		"Class": {f.Class, "Expense"}, "Name": {f.Name, "Example Geo Services, Inc."},
		"Address":      {f.Address, "1 Example Way, Springfield, XX  00000"},
		"ARContact":    {f.ARContact, "(800) 555-0100 ar@example.test"},
		"PaymentTerms": {f.PaymentTerms, "N30"}, "MonthlySpend": {f.MonthlySpend, "1500"},
		"CreditLimit": {f.CreditLimit, "0"}, "PORequired": {f.PORequired, "No"},
		"RemitEmail": {f.RemitEmail, "remit@example.test"}, "RequestedBy": {f.RequestedBy, "A. Requester"},
		"ApprovedBy": {f.ApprovedBy, "A. Approver"}, "Notes": {f.Notes, "Site coring services"},
	}
	for k, v := range want {
		if v[0] != v[1] {
			t.Errorf("%s = %q, want %q", k, v[0], v[1])
		}
	}
	if f.Kind() != "new" {
		t.Errorf("kind = %q", f.Kind())
	}
}

func TestBlankFieldsStayBlankAndRequiredOnesAreListed(t *testing.T) {
	f, err := Parse(workbook(t, completeForm))
	if err != nil {
		t.Fatal(err)
	}
	// The ERP is required and was left empty; the ACH question and discount
	// terms are not required and are also empty.
	if f.ERP != "" || f.ACH != "" || f.DiscountTerms != "" {
		t.Errorf("blank fields were filled: %+v", f)
	}
	if len(f.Missing) != 1 || f.Missing[0] != "ERP" {
		t.Errorf("missing = %v, want [ERP]", f.Missing)
	}
}

func TestAHintRowIsNotTakenForAFieldOrAContinuation(t *testing.T) {
	f, err := Parse(workbook(t, completeForm))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Name, "must agree") || strings.Contains(f.ACH, "letterhead") {
		t.Errorf("a hint leaked into an answer: name %q, ach %q", f.Name, f.ACH)
	}
}

func TestAnAddressOnTwoRowsIsJoined(t *testing.T) {
	form := [][]string{
		{"", "Supplier Name*", "", "", "Example Builders Association"},
		{"", "Remittance Address*", "", "", "2 Sample Park Suite 9"},
		{"", "", "", "", "Testville, XX 11111"},
		{"", "Payment Terms", "", "", "Due on Receipt"},
	}
	f, err := Parse(workbook(t, form))
	if err != nil {
		t.Fatal(err)
	}
	if f.Address != "2 Sample Park Suite 9, Testville, XX 11111" {
		t.Errorf("address = %q", f.Address)
	}
	if f.PaymentTerms != "Due on Receipt" {
		t.Errorf("the row after the address was swallowed: %q", f.PaymentTerms)
	}
}

func TestAContinuedRequiredFieldIsNotMissing(t *testing.T) {
	form := [][]string{
		{"", "Remittance Address*"},
		{"", "", "", "", "3 Demo Road"},
	}
	f, err := Parse(workbook(t, form))
	if err != nil {
		t.Fatal(err)
	}
	if f.Address != "3 Demo Road" || len(f.Missing) != 0 {
		t.Errorf("address %q, missing %v", f.Address, f.Missing)
	}
}

func TestKindForTheThreeChoicesAndABlank(t *testing.T) {
	for in, want := range map[string]string{
		"New Supplier": "new", "Reactivate Existing Supplier": "reactivate",
		"Update Existing Supplier": "update", "": "", "Other": "",
	} {
		if got := (Form{Request: in}).Kind(); got != want {
			t.Errorf("Kind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnotherSheetOrder(t *testing.T) {
	// The form sheet is found by name even when it is not the second sheet.
	x := xlsxtest.Build(t, map[string][][]string{
		"Supplier Request Form": {{"", "Supplier Name*", "", "", "Example Co"}},
		"Instructions":          {{"x"}},
	}, []string{"Supplier Request Form", "Instructions"})
	f, err := Parse(x)
	if err != nil || f.Name != "Example Co" {
		t.Fatalf("name %q, err %v", f.Name, err)
	}
}

func TestAWorkbookThatIsNotTheFormIsAnError(t *testing.T) {
	other := xlsxtest.Build(t, map[string][][]string{"Budget": {{"Item", "Cost"}}}, []string{"Budget"})
	if _, err := Parse(other); err == nil || !strings.Contains(err.Error(), "Budget") {
		t.Errorf("no form sheet should name the sheets there: %v", err)
	}
	empty := xlsxtest.Build(t, map[string][][]string{"Supplier Request Form": {{"nothing", "recognizable"}}}, []string{"Supplier Request Form"})
	if _, err := Parse(empty); err == nil {
		t.Error("a sheet with none of the fields was accepted as a form")
	}
	if _, err := Parse([]byte("not a zip")); err == nil {
		t.Error("garbage was accepted as a workbook")
	}
}
