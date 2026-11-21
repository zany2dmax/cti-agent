// Package redact removes what a model must not receive from text bound for it.
// Both model lanes use it: the supplier lane and advisory triage.
package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// Sensitive replaces what a request must not carry to a model: tax ids,
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
// It is deliberately blunt and errs toward removing too much: a phone number or
// a date on a line that also says "account" loses its digits, and a random
// nine-digit number that happens to pass the routing checksum is removed, which
// costs nothing. It is a net under the field list in formLines, not a
// replacement for it: the real protection is sending fewer fields. It does NOT
// catch a number written as words, one broken up by anything other than a space,
// dot or hyphen, one encoded (base64), an account number on a line with no bank
// word beside it, or a label and its value more than one line apart; that is why
// the field list is short.
//
// The model reads the redacted text and the evidence quotes are checked against
// that same text (Input.Source), so a redaction never makes a real quote look
// fabricated.
func Sensitive(s string) string {
	s = canonical(s)
	// Tax ids written the common way: EIN 12-3456789, SSN 123-45-6789, and an
	// SSN with spaces or dots.
	s = einRE.ReplaceAllString(s, "[redacted: tax id]")
	s = ssnRE.ReplaceAllString(s, "[redacted: tax id]")
	// IBANs, in either case.
	s = ibanRE.ReplaceAllStringFunc(s, func(m string) string {
		if len(strings.NewReplacer(" ", "").Replace(m)) >= 15 {
			return "[redacted: iban]"
		}
		return m
	})
	// Card numbers: 13 to 19 digits, separated by spaces, dots or hyphens, that
	// pass the Luhn check.
	s = cardRE.ReplaceAllStringFunc(s, func(m string) string {
		d := digitsOnly(m)
		if len(d) >= 13 && len(d) <= 19 && luhn(d) {
			return "[redacted: card number]"
		}
		return m
	})
	// A bare nine-digit number that passes the ABA routing checksum, wherever it
	// is: one in ten random nine-digit numbers does, and losing it costs nothing.
	s = nineRE.ReplaceAllStringFunc(s, func(m string) string {
		if abaOK(m) {
			return "[redacted: account number]"
		}
		return m
	})
	// Context lines. On a line that talks about accounts, routing or tax ids, any
	// run of 6 or more digits (9 for a tax id) is removed; and a value that sits
	// alone on the NEXT line, which is how a pasted table or an HTML form lays out
	// "Routing" over "021000021", is removed too.
	lines := strings.Split(s, "\n")
	carry := ""
	for i, l := range lines {
		ctx := ""
		switch {
		case bankWordRE.MatchString(l):
			ctx = "account number"
		case taxWordRE.MatchString(l):
			ctx = "tax id"
		}
		if ctx == "" && carry != "" && valueLineRE.MatchString(l) {
			ctx = carry
		}
		if ctx != "" {
			min := 6
			if ctx == "tax id" {
				min = 9
			}
			lines[i] = digitRunRE.ReplaceAllStringFunc(l, func(m string) string {
				if len(digitsOnly(m)) >= min {
					return "[redacted: " + ctx + "]"
				}
				return m
			})
		}
		// A line that names a bank or tax field and has no digits of its own
		// hands its context to the next line.
		carry = ""
		if ctx != "" && !strings.ContainsAny(l, "0123456789") {
			carry = ctx
		}
	}
	return strings.Join(lines, "\n")
}

// Strict removes only what checks itself, so it cannot mangle ordinary technical
// text: a formatted tax id (12-3456789, 123-45-6789), an IBAN whose check digits
// are valid, and a card number (13 to 19 digits, spaces or hyphens only) that
// passes the Luhn check. It has no bank-word line rule, no bare nine-digit
// checksum rule and no dots in card numbers, because threat intelligence is
// full of CVE ids, hashes, IP lists and version numbers on lines that happen to
// say "account", "bank", "wire" or "tax", and the blunt rules in Sensitive
// rewrote those into "[redacted: account number]". Sensitive is for finance
// paperwork (the supplier lane); Strict is the net under advisory triage.
func Strict(s string) string {
	s = canonical(s)
	s = einRE.ReplaceAllString(s, "[redacted: tax id]")
	s = ssnDashRE.ReplaceAllString(s, "[redacted: tax id]")
	s = ibanRE.ReplaceAllStringFunc(s, func(m string) string {
		if ibanValid(strings.ReplaceAll(m, " ", "")) {
			return "[redacted: iban]"
		}
		return m
	})
	return cardRE.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, ".") {
			return m // an IP list or a version string, not a card
		}
		d := digitsOnly(m)
		if len(d) >= 13 && len(d) <= 19 && luhn(d) {
			return "[redacted: card number]"
		}
		return m
	})
}

// ibanValid is the ISO 13616 mod-97 check: move the first four characters to
// the end, turn letters into numbers (A=10), and the remainder mod 97 is 1.
func ibanValid(iban string) bool {
	iban = strings.ToUpper(iban)
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}
	rest := iban[4:] + iban[:4]
	rem := 0
	for _, r := range rest {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			rem = (rem*100 + int(r-'A') + 10) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// canonical removes what could hide a number from the patterns without changing
// what a reader sees: zero-width and other invisible format characters
// (category Cf), and fullwidth digits, which become ASCII. The model gets the
// canonical text, so a hidden number is not hidden from the redaction either.
func canonical(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.Is(unicode.Cf, r):
			return -1
		case r >= 0xFF10 && r <= 0xFF19: // fullwidth digits
			return '0' + (r - 0xFF10)
		}
		return r
	}, s)
}

// abaOK reports whether nine digits pass the ABA routing-number checksum.
func abaOK(d string) bool {
	if len(d) != 9 {
		return false
	}
	n := func(i int) int { return int(d[i] - '0') }
	return (3*(n(0)+n(3)+n(6))+7*(n(1)+n(4)+n(7))+(n(2)+n(5)+n(8)))%10 == 0
}

var (
	einRE = regexp.MustCompile(`\b\d{2}-\d{7}\b`)
	ssnRE = regexp.MustCompile(`\b\d{3}[- .]\d{2}[- .]\d{4}\b`)
	// ssnDashRE is the SSN written with hyphens only: with dots or spaces it is
	// indistinguishable from an IP fragment or a version.
	ssnDashRE = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ibanRE    = regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	cardRE    = regexp.MustCompile(`\b\d(?:[ .-]?\d){12,18}\b`)
	nineRE    = regexp.MustCompile(`\b\d{9}\b`)
	// A bank or tax word marks the line. "account" may run on into "accountnumber".
	bankWordRE = regexp.MustCompile(`(?i)\b(acct\w*|account\w*|a/c|routing|aba|swift|bic|iban|ach|wire|sort code|bank)\b`)
	taxWordRE  = regexp.MustCompile(`(?i)\b(ein|fein|tin|tax|taxpayer|ssn|vat)\b`)
	// A line that is only a value: digits and the separators between them.
	valueLineRE = regexp.MustCompile(`^\s*[\d][\d .-]{4,}\s*$`)
	// A run of digits that may have single spaces, dots or hyphens inside it.
	digitRunRE = regexp.MustCompile(`\d(?:[ .-]?\d)+`)
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
