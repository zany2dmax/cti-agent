package supplier

import (
	"regexp"
	"strings"
)

// RedactSensitive replaces what a request must not carry to a model: tax ids,
// bank account and routing numbers, IBANs and card numbers, each with a marker
// that says what was there.
//
// WHY. A supplier request is business and financial paperwork. The model is
// asked one question: does this supplier touch company data, systems or
// technology. Nothing it needs to answer that is a tax id or a bank number, and
// requesters paste them into the free-text note and the message body even though
// the form has attachments for them (which the lane never opens). The model is a
// third-party service; what it never receives it cannot retain.
//
// It is deliberately blunt and errs toward removing too much: a phone number on
// a line that also says "account" loses its digits, which costs nothing. It is a
// net under the field list in formLines, not a replacement for it: the real
// protection is sending fewer fields. A number written as words, or split over
// lines, is not caught; that is why the field list is short.
//
// The model reads the redacted text and the evidence quotes are checked against
// that same text (Input.Source), so a redaction never makes a real quote look
// fabricated.
func RedactSensitive(s string) string {
	// Tax ids: EIN 12-3456789, SSN 123-45-6789.
	s = einRE.ReplaceAllString(s, "[redacted: tax id]")
	s = ssnRE.ReplaceAllString(s, "[redacted: tax id]")
	// IBANs.
	s = ibanRE.ReplaceAllStringFunc(s, func(m string) string {
		if len(strings.NewReplacer(" ", "").Replace(m)) >= 15 {
			return "[redacted: iban]"
		}
		return m
	})
	// Card numbers: 13 to 19 digits that pass the Luhn check.
	s = cardRE.ReplaceAllStringFunc(s, func(m string) string {
		d := digitsOnly(m)
		if len(d) >= 13 && len(d) <= 19 && luhn(d) {
			return "[redacted: card number]"
		}
		return m
	})
	// Bank numbers: on a line that talks about accounts or routing, any run of
	// 6 or more digits.
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if bankWordRE.MatchString(l) {
			lines[i] = digitRunRE.ReplaceAllStringFunc(l, func(m string) string {
				if len(digitsOnly(m)) >= 6 {
					return "[redacted: account number]"
				}
				return m
			})
		}
	}
	return strings.Join(lines, "\n")
}

var (
	einRE  = regexp.MustCompile(`\b\d{2}-\d{7}\b`)
	ssnRE  = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ibanRE = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	cardRE = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	// Whole-word match on the words that mark a bank detail.
	bankWordRE = regexp.MustCompile(`(?i)\b(acct|account|accounts|a/c|routing|aba|swift|bic|iban|ach|wire|sort code|bank)\b`)
	// A run of digits that may have single spaces or hyphens inside it.
	digitRunRE = regexp.MustCompile(`\d(?:[ -]?\d)+`)
)

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhn reports whether a digit string passes the Luhn check card numbers use.
func luhn(d string) bool {
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
