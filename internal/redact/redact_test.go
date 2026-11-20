package redact

import (
	"strings"
	"testing"
)

func TestSensitiveRemovesWhatTheModelMustNotReceive(t *testing.T) {
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
		// found by review: realistic layouts the first version missed
		{"9-digit EIN, no hyphen", "EIN 123456789 attached", "123456789", "[redacted: tax id]"},
		{"Tax ID label", "Tax ID: 123456789", "123456789", "[redacted: tax id]"},
		{"SSN with spaces", "SSN 123 45 6789", "123 45 6789", "[redacted: tax id]"},
		{"SSN with dots", "ssn 123.45.6789", "123.45.6789", "[redacted: tax id]"},
		{"label above value", "Routing\n021000021\nthanks", "021000021", "[redacted: account number]"},
		{"account label above value", "acct no:\n12345678", "12345678", "[redacted: account number]"},
		{"bare routing number, no bank word", "please use 021000021 for the transfer", "021000021", "[redacted: account number]"},
		{"accountnumber run on", "accountnumber 12345678", "12345678", "[redacted: account number]"},
		{"card with dots", "4111.1111.1111.1111", "1111.1111", "[redacted: card number]"},
		{"lowercase iban", "iban de89 3704 0044 0532 0130 00", "0532 0130", "[redacted: iban]"},
		{"fullwidth digits", "EIN １２-３４５６７８９", "３４５６７８９", "[redacted: tax id]"},
		{"zero-width inside the number", "EIN 12-345\u200b6789", "6789", "[redacted: tax id]"},
	} {
		got := Sensitive(c.in)
		if strings.Contains(got, c.gone) {
			t.Errorf("%s: %q still in %q", c.name, c.gone, got)
		}
		if !strings.Contains(got, c.marker) {
			t.Errorf("%s: no %s marker in %q", c.name, c.marker, got)
		}
	}
}

func TestSensitiveLeavesOrdinaryRequestsAlone(t *testing.T) {
	for _, in := range []string{
		"New supplier of concrete and aggregate for the Dallas market.",
		"Annual contract about 120,000 dollars, net 30, ships on pallets.",
		"Call Pat at 555-123-4567 about the order on the 14th.", // no bank word on the line
		"Order 4111 1111 1111 1112 is not a card (fails Luhn).", // 16 digits, no Luhn, no bank word
		"Software and cloud hosting; needs access to our network.",
		"Invoice 2026-11-19, PO 88123, page 3 of 12.",
		"We have 123456789 users",                                  // nine digits, fails the routing checksum, no tax word
		"Our EIN application is pending; we will send it later.",   // a tax word with no number
		"The account manager is Pat; call about the Dallas depot.", // a bank-ish word with no digits
	} {
		if got := Sensitive(in); got != in {
			t.Errorf("changed an ordinary line:\n in: %q\nout: %q", in, got)
		}
	}
}

func TestSensitiveIsIdempotentAndHandlesOddInput(t *testing.T) {
	in := "EIN 12-3456789\naccount 000123456789\nfin é 日本語 \x00 end"
	once := Sensitive(in)
	if twice := Sensitive(once); twice != once {
		t.Errorf("not idempotent:\n%q\n%q", once, twice)
	}
	if Sensitive("") != "" {
		t.Error("empty input changed")
	}
	if got := Sensitive(strings.Repeat("1 ", 50000)); len(got) == 0 {
		t.Error("a long digit run lost everything")
	}
}
