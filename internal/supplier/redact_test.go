package supplier

import (
	"strings"
	"testing"
)

func TestRedactSensitiveRemovesWhatTheModelMustNotReceive(t *testing.T) {
	for _, c := range []struct{ name, in, gone, marker string }{
		{"EIN", "Our EIN is 12-3456789 for the W-9.", "12-3456789", "[redacted: tax id]"},
		{"SSN", "sole proprietor SSN 123-45-6789", "123-45-6789", "[redacted: tax id]"},
		{"IBAN", "pay to GB82 WEST 1234 5698 7654 32 please", "5698 7654", "[redacted: iban]"},
		{"IBAN compact", "IBAN DE89370400440532013000", "0532013000", "[redacted: iban]"},
		{"card, Luhn valid", "card 4111 1111 1111 1111 exp 12/29", "4111 1111", "[redacted: card number]"},
		{"card with dashes", "4111-1111-1111-1111", "1111-1111", "[redacted: card number]"},
		{"account on an account line", "Bank account number: 000123456789, routing 021000021", "000123456789", "[redacted: account number]"},
		{"routing", "ACH routing 021000021", "021000021", "[redacted: account number]"},
		{"spaced account digits", "acct 1234 5678 90", "1234 5678 90", "[redacted: account number]"},
	} {
		got := RedactSensitive(c.in)
		if strings.Contains(got, c.gone) {
			t.Errorf("%s: %q still in %q", c.name, c.gone, got)
		}
		if !strings.Contains(got, c.marker) {
			t.Errorf("%s: no %s marker in %q", c.name, c.marker, got)
		}
	}
}

func TestRedactSensitiveLeavesOrdinaryRequestsAlone(t *testing.T) {
	for _, in := range []string{
		"New supplier of concrete and aggregate for the Dallas market.",
		"Annual contract about 120,000 dollars, net 30, ships on pallets.",
		"Call Pat at 555-123-4567 about the order on the 14th.", // no bank word on the line
		"Order 4111 1111 1111 1112 is not a card (fails Luhn).", // 16 digits, no Luhn, no bank word
		"Software and cloud hosting; needs access to our network.",
		"Invoice 2026-11-19, PO 88123, page 3 of 12.",
	} {
		if got := RedactSensitive(in); got != in {
			t.Errorf("changed an ordinary line:\n in: %q\nout: %q", in, got)
		}
	}
}

func TestRedactSensitiveIsIdempotentAndHandlesOddInput(t *testing.T) {
	in := "EIN 12-3456789\naccount 000123456789\nfin é 日本語 \x00 end"
	once := RedactSensitive(in)
	if twice := RedactSensitive(once); twice != once {
		t.Errorf("not idempotent:\n%q\n%q", once, twice)
	}
	if RedactSensitive("") != "" {
		t.Error("empty input changed")
	}
	if got := RedactSensitive(strings.Repeat("1 ", 50000)); len(got) == 0 {
		t.Error("a long digit run lost everything")
	}
}

// The model sees less than the form holds, and the sender as a domain.
func TestSourceShowsTheModelOnlyWhatTheQuestionNeeds(t *testing.T) {
	in := Input{
		Sender:  "Pat Requester <pat.requester@corp.example>",
		Subject: "New supplier, tax id 12-3456789",
		Body:    "Please set up Acme Concrete. Bank account 000123456789.",
		State:   StateRead,
		Form: &Form{
			Request: "New supplier", Class: "Expense", Name: "Acme Concrete",
			Notes:   "Supplies aggregate. EIN 98-7654321.",
			Address: "1 Remit Road, Springfield", ARContact: "Ann Contact ann@acme.example",
			PaymentTerms: "Net 30", CreditLimit: "$50,000", MonthlySpend: "$12,000",
			RequestedBy: "Pat Requester", ApprovedBy: "Boss Person", Branch: "Dallas", ERP: "SAP",
		},
	}
	src := in.Source()
	for _, want := range []string{"SENDER DOMAIN: corp.example", "Supplier name: Acme Concrete", "Supplies aggregate.", "Request: New supplier", "Expense or inventory: Expense"} {
		if !strings.Contains(src, want) {
			t.Errorf("source lacks %q:\n%s", want, src)
		}
	}
	for _, gone := range []string{
		"pat.requester", "Pat Requester", "Remit Road", "ann@acme.example", "Ann Contact", "Net 30", "$50,000", "$12,000",
		"Boss Person", "Dallas", "SAP", "12-3456789", "98-7654321", "000123456789",
	} {
		if strings.Contains(src, gone) {
			t.Errorf("source still carries %q:\n%s", gone, src)
		}
	}
	for _, marker := range []string{"[redacted: tax id]", "[redacted: account number]"} {
		if !strings.Contains(src, marker) {
			t.Errorf("source lacks %s:\n%s", marker, src)
		}
	}
}

func TestSenderDomainNeverLeaksTheAddress(t *testing.T) {
	for in, want := range map[string]string{
		"pat@Corp.Example":       "corp.example",
		"Pat <pat@corp.example>": "corp.example",
		"no address":             "(unknown)",
		"":                       "(unknown)",
		"trailing@":              "(unknown)",
	} {
		if got := senderDomain(in); got != want {
			t.Errorf("senderDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// An evidence quote the model gives is checked against the same text it read,
// so redaction cannot make a genuine quote look fabricated.
func TestEvidenceIsCheckedAgainstTheRedactedSource(t *testing.T) {
	in := Input{Sender: "p@corp.example", Subject: "x", State: StateNone,
		Body: "We need cloud hosting. Account 000123456789 for billing."}
	src := in.Source()
	if !strings.Contains(squash(src), squash("We need cloud hosting.")) {
		t.Fatalf("the quote is not in the source:\n%s", src)
	}
	if strings.Contains(src, "000123456789") {
		t.Fatalf("the account number reached the source:\n%s", src)
	}
}
