package supplier

import (
	"strings"
	"testing"

	"github.com/zany2dmax/cti-agent/internal/redact"
)

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

func TestRedactionLeavesWhatTheJudgementNeeds(t *testing.T) {
	for _, in := range []string{
		"Acme Cloud Hosting LLC provides SaaS and managed network services",
		"Needs access to our ERP and the customer database over a VPN",
		"Annual spend $120,000, 3 year term, SLA 99.95%",
		"See https://example.com/security/trust-center for their SOC 2 report",
	} {
		if got := redact.Sensitive(in); got != in {
			t.Errorf("redaction changed text the judgement needs:\n in: %q\nout: %q", in, got)
		}
	}
}
